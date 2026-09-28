"""Verification framework — safe, local-only checks that decide a finding's lifecycle.

A Verifier takes a normalized (suspected/correlated) Finding, gathers *evidence* about
whether the underlying property actually holds against the local target or the local
source tree, and records the outcome through :mod:`engine.lifecycle`. Only a verifier may
move a finding out of suspected/correlated.

Verification *result* and lifecycle *status* are two separate concepts. A verifier reports
a result (confirmed / refuted / inconclusive / not_applicable) and :func:`lifecycle.
apply_verification` maps it to the status (confirmed->verified, refuted/not_applicable->
false_positive, inconclusive->needs_manual_review). A probe can NEVER bypass that mapping:
e.g. a "refuted" result can only ever yield false_positive, never "verified".

Verifiers are strictly non-destructive and local-only: they read local files or interpret
the output of the controlled, loopback-scoped active probes (headers / CORS / rate-limit /
auth-MCP / SSRF-canary). They never brute-force, never fuzz, and never reach third-party
or cloud-metadata hosts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from checks.active_base import ProbeVerdict
from checks.auth_mcp import classify_auth
from checks.cors import classify_cors
from checks.rate_limit import classify_rate_limit
from checks.security_headers import EXPECTED_PROPERTY, SECURITY_HEADERS, is_loopback
from checks.ssrf import classify_ssrf
from engine import lifecycle
from engine.deps import DEFAULT_SOURCE_DIRS, analyze_dependency, load_manifests
from model.finding import Severity, Status


@dataclass
class VerificationContext:
    """Everything a verifier may need — all local, all read-only."""

    repo_path: Optional[str] = None
    target_url: Optional[str] = None
    pkg_json: Optional[dict] = None
    lock: Optional[dict] = None
    source_dirs: tuple = DEFAULT_SOURCE_DIRS

    @classmethod
    def build(cls, repo_path=None, target_url=None):
        pkg_json, lock = load_manifests(repo_path) if repo_path else (None, None)
        return cls(repo_path=repo_path, target_url=target_url, pkg_json=pkg_json, lock=lock)


class Verifier:
    """Base interface. `applies_to` gates a finding; `verify` records a transition."""

    name = "verifier"

    def applies_to(self, finding) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def verify(self, finding, context=None) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


def _apply_verdict(finding, verdict: ProbeVerdict, *, actor, probe, method="active_probe") -> bool:
    """Stamp a probe verdict onto a finding and route it through lifecycle enforcement.

    Sets the (possibly re-rated) severity, records the verification evidence, and calls
    :func:`lifecycle.apply_verification` so the result -> status mapping is enforced in one
    place. Returns True iff the lifecycle transition was applied.
    """
    finding.severity = verdict.severity
    updates = dict(verdict.evidence or {})
    updates["verification_status"] = verdict.result
    updates["evidence"] = verdict.rationale
    if verdict.remediation:
        updates["remediation"] = verdict.remediation
        finding.fix = {"recommendation": verdict.remediation}
    return lifecycle.apply_verification(
        finding, result=verdict.result, actor=actor, method=method, probe=probe,
        rationale=verdict.rationale, evidence_updates=updates)


class SecurityHeaderVerifier(Verifier):
    """Turn a raw security-header observation into a probed verification result.

    The header probe already ran (an active HTTP GET); this verifier interprets that live
    observation:
      * header present                  -> missing-header concern REFUTED  (-> false_positive)
      * header absent + applicable      -> missing header CONFIRMED         (-> verified)
      * HSTS absent over loopback http  -> NOT_APPLICABLE                   (-> false_positive)
    Only a genuinely-absent, applicable header is a verified gap; a present header or an
    inapplicable one is a false positive, never "verified".
    """

    name = "security-header"

    def applies_to(self, finding) -> bool:
        return finding.tool == "security-headers" and isinstance(finding.evidence, dict)

    def verify(self, finding, context=None) -> bool:
        ev = finding.evidence
        header = ev.get("header")
        present = bool(ev.get("present"))
        scheme = ev.get("scheme", "")
        host = ev.get("host", "")
        url = ev.get("url_tested") or finding.endpoint
        expected = EXPECTED_PROPERTY.get(header, header)
        missing_severity = SECURITY_HEADERS.get(header, "low")
        ev.setdefault("expected_property", expected)

        if present:
            verdict = ProbeVerdict(
                lifecycle.REFUTED,
                f"{header} is present on {url} (HTTP {ev.get('status_code')}); the missing-header "
                "concern is refuted by the live response.",
                Severity.INFO,
                remediation="Present. Review the policy value for strictness in a later phase.")
        elif header == "Strict-Transport-Security" and scheme == "http" and is_loopback(host):
            verdict = ProbeVerdict(
                lifecycle.NOT_APPLICABLE,
                f"{header} is absent, but the target is plain HTTP on a loopback host ({host}); "
                "HSTS cannot apply, so its absence is not a weakness here.",
                Severity.INFO,
                remediation="Enforce HSTS in production over HTTPS; not applicable on local HTTP.")
        else:
            verdict = ProbeVerdict(
                lifecycle.CONFIRMED,
                f"{header} is absent from the response on {url} (HTTP {ev.get('status_code')}); "
                "missing-header gap confirmed by probe.",
                missing_severity,
                remediation=f"Set the {header} response header. Expected: {expected}")
        return _apply_verdict(finding, verdict, actor=self.name, probe="security-headers")


class DependencyReachabilityVerifier(Verifier):
    """Decide whether a dependency advisory plausibly affects the running target.

    Uses local manifests only and never asserts a vulnerability just because a scanner named
    the package:
      * package absent from lockfile          -> REFUTED         (advisory doesn't match tree)
      * development-only dependency           -> NOT_APPLICABLE   (out of scope for a prod target)
      * production + imported by app source   -> INCONCLUSIVE     (reachable, not yet exploited)
      * production + transitive + not imported-> INCONCLUSIVE     (needs manual review)
    Nothing here reaches "verified"; demonstrating exploitation needs an active probe.
    """

    name = "dependency-reachability"
    _TOOLS = {"npm-audit", "osv-scanner"}

    def applies_to(self, finding) -> bool:
        return (finding.tool in self._TOOLS and isinstance(finding.evidence, dict)
                and bool(finding.evidence.get("package")))

    def verify(self, finding, context=None) -> bool:
        ev = finding.evidence
        name = ev.get("package")
        facts = analyze_dependency(
            getattr(context, "repo_path", None), name,
            source_dirs=getattr(context, "source_dirs", None) or DEFAULT_SOURCE_DIRS,
            pkg_json=getattr(context, "pkg_json", None),
            lock=getattr(context, "lock", None),
        )
        ev.update(facts.as_evidence())
        fixed = ev.get("fixed_version")
        remediation = (
            f"Upgrade '{name}' beyond the vulnerable range (npm/OSV suggests {fixed}); "
            "verify compatibility." if fixed
            else f"Track the upstream fix for '{name}'; no fixed version was reported by the tool.")

        if facts.manifest_error:
            result, severity, reason = (lifecycle.INCONCLUSIVE, finding.severity,
                                        f"Could not analyse reachability: {facts.manifest_error} "
                                        "Manual review required.")
        elif not facts.present_in_lock:
            result, severity, reason = (lifecycle.REFUTED, Severity.INFO, facts.reachability_reason)
        elif facts.dependency_type == "development":
            result, severity, reason = (
                lifecycle.NOT_APPLICABLE, Severity.INFO,
                facts.reachability_reason + " Scoped out of this production-target assessment; a "
                "development/CI risk may remain and is disclosed here.")
        elif facts.reachable == "imported":
            result, severity, reason = (
                lifecycle.INCONCLUSIVE, finding.severity,
                facts.reachability_reason + " Reachability is shown, but exploitation is not "
                "demonstrated without an active probe; manual review required.")
        else:
            result, severity, reason = (lifecycle.INCONCLUSIVE, finding.severity,
                                        facts.reachability_reason)

        verdict = ProbeVerdict(result, reason, severity, remediation=remediation)
        return _apply_verdict(finding, verdict, actor=self.name,
                              probe="dependency-reachability", method="dependency-reachability")


class _ProbeVerifier(Verifier):
    """Base for the Phase-4 active verifiers: classify the probe evidence, apply the verdict.

    Each subclass names the tool whose normalized finding it interprets and the pure
    ``classify`` function (over ``finding.evidence``) that produces the :class:`ProbeVerdict`.
    """

    name = "probe"
    tool = None
    probe = None

    @staticmethod
    def classify(evidence) -> ProbeVerdict:  # pragma: no cover - interface
        raise NotImplementedError

    def applies_to(self, finding) -> bool:
        return finding.tool == self.tool and isinstance(finding.evidence, dict)

    def verify(self, finding, context=None) -> bool:
        verdict = self.classify(finding.evidence)
        return _apply_verdict(finding, verdict, actor=self.name, probe=self.probe)


class CorsVerifier(_ProbeVerifier):
    name = "cors"
    tool = "cors"
    probe = "cors"
    classify = staticmethod(classify_cors)


class RateLimitVerifier(_ProbeVerifier):
    name = "rate-limit"
    tool = "rate-limit"
    probe = "rate-limit"
    classify = staticmethod(classify_rate_limit)


class AuthVerifier(_ProbeVerifier):
    name = "auth-mcp"
    tool = "auth-mcp"
    probe = "auth-mcp"
    classify = staticmethod(classify_auth)


class SsrfVerifier(_ProbeVerifier):
    name = "ssrf-canary"
    tool = "ssrf"
    probe = "ssrf-canary"
    classify = staticmethod(classify_ssrf)


ACTIVE_VERIFIERS = (SecurityHeaderVerifier, DependencyReachabilityVerifier,
                    CorsVerifier, RateLimitVerifier, AuthVerifier, SsrfVerifier)


def default_verifiers():
    """The verifiers that run in a full WATCHTOWER assessment (Phases 3 + 4)."""
    return [cls() for cls in ACTIVE_VERIFIERS]


def run_verifiers(findings, context=None, verifiers=None) -> dict:
    """Apply each applicable verifier to each finding; return a per-verifier applied-count.

    A verifier changes status only through :mod:`engine.lifecycle`, so terminal states are
    respected. A verifier that raises is isolated: the error is recorded on the finding and
    the pipeline continues rather than crashing the whole run.
    """
    verifiers = verifiers if verifiers is not None else default_verifiers()
    counts = {v.name: 0 for v in verifiers}
    for finding in findings:
        for v in verifiers:
            try:
                if v.applies_to(finding) and v.verify(finding, context):
                    counts[v.name] += 1
            except Exception as exc:  # a verifier must never crash the pipeline
                if isinstance(finding.evidence, dict):
                    finding.evidence.setdefault("verifier_errors", []).append(f"{v.name}: {exc}")
    return counts
