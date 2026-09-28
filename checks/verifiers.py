"""Verification framework — safe, local-only checks that decide a finding's lifecycle.

A Verifier takes a normalized (suspected/correlated) Finding, gathers *evidence* about
whether the underlying property actually holds against the local target or the local
source tree, and records a status transition through :mod:`engine.lifecycle`. Only a
verifier may move a finding to VERIFIED or FALSE_POSITIVE.

Verifiers here are strictly non-destructive: they read local files and interpret the
already-collected probe output. They never attack the target, never fuzz, never reach
third-party or cloud-metadata hosts. The CORS / rate-limit / auth / SSRF verifiers are
declared as interfaces (Phase 4) and intentionally decline rather than guess; when SSRF
is implemented it must use a LOCAL canary only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from checks.security_headers import EXPECTED_PROPERTY, SECURITY_HEADERS, is_loopback
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


class SecurityHeaderVerifier(Verifier):
    """Turn a raw security-header observation into a probed verdict.

    The header probe already ran (an active HTTP GET); this verifier interprets that live
    observation and demonstrates the property:
      * header present                    -> missing-header concern REFUTED (informational)
      * header absent + applicable        -> missing header CONFIRMED (a real, probed gap)
      * HSTS absent over loopback http     -> NOT APPLICABLE (absence expected, not a weakness)
    All three are 'verified' — the live response is direct evidence either way.
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

        if present:
            severity, result = Severity.INFO, "refuted"
            statement = (f"{header} is present on {url} (HTTP {ev.get('status_code')}); the "
                         "missing-header concern is refuted by the live response.")
            remediation = "Present. Review the policy value for strictness in a later phase."
        elif header == "Strict-Transport-Security" and scheme == "http" and is_loopback(host):
            severity, result = Severity.INFO, "not_applicable"
            statement = (f"{header} is absent, but the target is plain HTTP on a loopback host "
                         f"({host}); HSTS cannot apply, so its absence is not a weakness here.")
            remediation = "Enforce HSTS in production over HTTPS; not applicable on local HTTP."
        else:
            severity, result = missing_severity, "confirmed"
            statement = (f"{header} is absent from the response on {url} "
                         f"(HTTP {ev.get('status_code')}); missing-header gap confirmed by probe.")
            remediation = f"Set the {header} response header. Expected: {expected}"

        finding.severity = severity
        ev["verification_status"] = result
        ev["evidence"] = statement
        ev["remediation"] = remediation
        ev.setdefault("expected_property", expected)
        return lifecycle.transition(
            finding, Status.VERIFIED, actor=self.name, result=result,
            method="active_probe", probe="security-headers", rationale=statement)


class DependencyReachabilityVerifier(Verifier):
    """Decide whether a dependency advisory plausibly affects the running target.

    Uses the local manifests only and never asserts a vulnerability just because a scanner
    named the package:
      * package absent from lockfile            -> FALSE_POSITIVE (advisory doesn't match tree)
      * development-only dependency             -> FALSE_POSITIVE for the production target
                                                    (a dev/CI residual risk is disclosed)
      * production + imported by app source      -> stays SUSPECTED/CORRELATED (needs Phase-4 probe)
      * production + transitive + not imported   -> NEEDS_MANUAL_REVIEW
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
        ev["remediation"] = (
            f"Upgrade '{name}' beyond the vulnerable range (npm/OSV suggests {fixed}); "
            "verify compatibility." if fixed
            else f"Track the upstream fix for '{name}'; no fixed version was reported by the tool.")

        if facts.manifest_error:
            return lifecycle.transition(
                finding, Status.NEEDS_MANUAL_REVIEW, actor=self.name,
                method="dependency-reachability", result="inconclusive",
                rationale=(f"Could not analyse reachability: {facts.manifest_error} "
                           "Manual review required."))
        if not facts.present_in_lock:
            return lifecycle.transition(
                finding, Status.FALSE_POSITIVE, actor=self.name,
                method="dependency-reachability", result="refuted",
                rationale=facts.reachability_reason)
        if facts.dependency_type == "development":
            return lifecycle.transition(
                finding, Status.FALSE_POSITIVE, actor=self.name,
                method="dependency-reachability", result="refuted",
                rationale=(facts.reachability_reason + " Scoped out of this production-target "
                           "assessment; a development/CI risk may remain and is disclosed here."))
        if facts.reachable == "imported":
            return lifecycle.transition(
                finding, finding.status, actor=self.name,
                method="dependency-reachability", result="inconclusive",
                rationale=(facts.reachability_reason + " Remains suspected: reachability is "
                           "shown, but exploitation is not demonstrated without a Phase-4 probe."))
        return lifecycle.transition(
            finding, Status.NEEDS_MANUAL_REVIEW, actor=self.name,
            method="dependency-reachability", result="inconclusive",
            rationale=facts.reachability_reason)


class _StubVerifier(Verifier):
    """A declared-but-deferred verifier interface (Phase 4).

    It never fabricates a verdict: `applies_to` returns False so the pipeline leaves the
    finding's status untouched until the real probe is implemented. Subclasses document
    the intended, safe, local-only probe.
    """

    name = "stub"
    probe_intent = "not implemented"

    def applies_to(self, finding) -> bool:
        return False

    def verify(self, finding, context=None) -> bool:
        return False


class CorsVerifier(_StubVerifier):
    name = "cors"
    probe_intent = ("Send controlled cross-origin requests to the LOCAL target and observe "
                    "Access-Control-Allow-Origin/-Credentials to confirm a permissive policy.")


class RateLimitVerifier(_StubVerifier):
    name = "rate-limit"
    probe_intent = ("Issue a bounded, non-abusive burst to a LOCAL endpoint and check for 429 / "
                    "rate-limit headers — never a denial-of-service volume.")


class AuthVerifier(_StubVerifier):
    name = "authentication"
    probe_intent = ("Request a protected route / MCP method without credentials on the LOCAL "
                    "target and confirm it is refused (401/403), never brute-forcing secrets.")


class SsrfVerifier(_StubVerifier):
    name = "ssrf-canary"
    probe_intent = ("Ask the LOCAL target to fetch a canary URL on a loopback server we control "
                    "and observe the callback — never cloud-metadata or third-party hosts.")


ACTIVE_VERIFIERS = (SecurityHeaderVerifier, DependencyReachabilityVerifier)
STUB_VERIFIERS = (CorsVerifier, RateLimitVerifier, AuthVerifier, SsrfVerifier)


def default_verifiers():
    """The verifiers that actually run today (Phase 3)."""
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
