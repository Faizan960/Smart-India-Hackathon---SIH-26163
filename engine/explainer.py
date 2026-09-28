"""Per-finding explanation engine and evidence-confidence rating (Phase 5, items 5-6).

The explainer turns a normalised Finding into a plain, auditable narrative: what
was detected, why it matters, the evidence, what verification ran, the result,
the current lifecycle status, what was *not* tested, the limitation, and the
guidance. Every sentence is derived from fields already on the finding — the
engine never invents a claim the evidence does not support.

Evidence confidence (high/medium/low) is defined from how COMPLETE the evidence
is, and is deliberately kept distinct from Severity, the WATCHTOWER Risk Score
and the Lifecycle Status. A high-severity finding can carry low confidence (a
single scanner hit, never verified); a low-severity finding can carry high
confidence (a probe observed the property directly).
"""
from __future__ import annotations

from engine.lifecycle import CONFIRMED, INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Status

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"
CONFIDENCE_LEVELS = (CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW)

# The Finding default records method as the literal string "none" (not None); both
# mean "no verification method ran".
_NO_METHOD = (None, "", "none")


def _real_method(verification: dict):
    method = (verification or {}).get("method")
    return method if method not in _NO_METHOD else None

_STATUS_PHRASE = {
    Status.SUSPECTED: "single-source suspicion, not yet verified",
    Status.CORRELATED: "corroborated by independent tools (raises confidence, not verification)",
    Status.VERIFIED: "a probe demonstrated the property against the live target",
    Status.FALSE_POSITIVE: "evidence disproved the issue or ruled it not applicable",
    Status.NEEDS_MANUAL_REVIEW: "evidence was inconclusive; a human should investigate",
}


def evidence_confidence(finding) -> str:
    """Rate confidence from evidence completeness (NOT severity/score/status)."""
    verification = finding.verification or {}
    result = verification.get("result")
    method = _real_method(verification)
    evidence = finding.evidence or {}
    # A definitive observation either way (confirmed / refuted / not-applicable) that
    # came from an actual verification method is the most complete evidence we have.
    if result in (CONFIRMED, REFUTED, NOT_APPLICABLE) and method:
        return CONFIDENCE_HIGH
    # A verification ran but could not settle it, or reachability analysis was done,
    # or independent tools corroborate: partial but real evidence.
    if result == INCONCLUSIVE and method:
        return CONFIDENCE_MEDIUM
    if finding.status == Status.CORRELATED:
        return CONFIDENCE_MEDIUM
    if evidence.get("dependency_type") or evidence.get("reachability_reason"):
        return CONFIDENCE_MEDIUM
    # Single-source, unverified static suspicion.
    return CONFIDENCE_LOW


def confidence_counts(findings) -> dict:
    counts = {level: 0 for level in CONFIDENCE_LEVELS}
    for finding in findings:
        counts[evidence_confidence(finding)] += 1
    return counts


# Why a class of issue matters — generic, hardening-framed statements that never
# assert exploitation. Keyed by tool; falls back to a severity-aware default.
_WHY_BY_TOOL = {
    "security-headers": ("Security response headers are a defence-in-depth control. A "
                         "missing header is a hardening gap, not a demonstrated exploit."),
    "cors": ("A permissive cross-origin policy can let a hostile site read authenticated "
             "responses. This matters only if the policy actually reflects hostile origins."),
    "rate-limit": ("Absent rate limiting can enable abuse or brute force. WATCHTOWER only "
                   "sends a bounded burst and never attempts a denial-of-service."),
    "auth-mcp": ("An unauthenticated MCP/administrative surface could expose tools or data. "
                 "Exposure is only a weakness if the surface is actually reachable and open."),
    "ssrf": ("A server-side request forgery would let a caller pivot to internal targets. "
             "WATCHTOWER tests this with a loopback-only canary and confirms nothing without it."),
    "npm-audit": ("A vulnerable dependency is only a risk if the vulnerable code path is "
                  "reachable from the application. Reachability is analysed, not assumed."),
}
_WHY_DEFAULT = ("This finding flags a potential weakness. Its impact depends on verification; "
                "an unverified finding is a lead, not a confirmed vulnerability.")


def _evidence_view(finding) -> dict:
    """A compact, secret-free view of the supporting evidence."""
    ev = finding.evidence or {}
    keep = ("identifiers", "observed", "observed_value", "expected", "dedup_group",
            "correlation_group", "correlated_with", "dependency", "dependency_type",
            "direct_or_transitive", "reachable", "reachability_reason", "runtime",
            "status_code", "canary_received", "acao", "remediation")
    view = {k: ev[k] for k in keep if k in ev}
    if finding.cwe:
        view["cwe"] = finding.cwe
    if finding.references:
        view["references"] = list(finding.references)
    return view


def _what_not_tested(finding) -> str:
    result = (finding.verification or {}).get("result")
    rationale = ((finding.verification or {}).get("rationale") or "").lower()
    dev_runtime = "production" in rationale or "serverless" in rationale or "development" in rationale
    if finding.status == Status.SUSPECTED:
        return ("No active probe exercised this finding; it was not verified against the "
                "running target.")
    if result == INCONCLUSIVE or finding.status == Status.NEEDS_MANUAL_REVIEW:
        if dev_runtime:
            return ("The production/serverless runtime of this endpoint was not exercised; "
                    "only the local development runtime responded, so the verdict is inconclusive.")
        return ("The probe ran but could not reach a definitive verdict; the property was "
                "neither demonstrated nor ruled out.")
    if result == CONFIRMED:
        return ("The security property was demonstrated; the downstream exploit impact and "
                "affected data were not further enumerated.")
    if result in (REFUTED, NOT_APPLICABLE):
        return "The issue was ruled out under the tested configuration; no further paths were probed."
    return "See the limitations section for the boundaries of this assessment."


def _guidance(finding) -> str:
    ev = finding.evidence or {}
    if finding.fix:
        return finding.fix
    if ev.get("remediation"):
        return ev["remediation"]
    if finding.status == Status.NEEDS_MANUAL_REVIEW:
        return ("Investigate manually against the production runtime: confirm whether the "
                "endpoint is reachable and whether the flagged property holds there.")
    if finding.status == Status.FALSE_POSITIVE:
        return "No action required based on current evidence; retain for regression tracking."
    return "Review the evidence and verify against the production configuration before acting."


def explain(finding) -> dict:
    """Produce the structured explanation for one finding (item 5)."""
    verification = finding.verification or {}
    method = _real_method(verification)
    result = verification.get("result")
    score_value = (finding.score or {}).get("value")
    if method:
        performed = f"{method}" + (f" (probe: {verification.get('probe')})"
                                   if verification.get("probe") else "")
        performed += f" — {verification.get('rationale')}" if verification.get("rationale") else ""
    else:
        performed = ("None — this is a single-source scanner result and has not been verified "
                     "by any probe.")
    return {
        "id": finding.id,
        "title": finding.title,
        "tool": finding.tool,
        "severity": finding.severity,
        "lifecycle_status": finding.status,
        "risk_score": score_value,
        "evidence_confidence": evidence_confidence(finding),
        "what_was_detected": f"{finding.tool} reported: {finding.description or finding.title}",
        "why_it_matters": _WHY_BY_TOOL.get(finding.tool, _WHY_DEFAULT),
        "evidence": _evidence_view(finding),
        "verification_performed": performed,
        "result": result or "not verified",
        "status_meaning": _STATUS_PHRASE.get(finding.status, finding.status),
        "what_was_not_tested": _what_not_tested(finding),
        "limitation": ("Assessment ran against a LOCAL target only; results reflect the tested "
                       "runtime and configuration, not necessarily production."),
        "guidance": _guidance(finding),
    }


def explain_all(findings) -> dict:
    """Map finding-id -> explanation for every finding."""
    return {f.id: explain(f) for f in findings}

