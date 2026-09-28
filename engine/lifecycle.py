"""Finding lifecycle — the single place that is allowed to change a Finding's status.

Enforces the WATCHTOWER status-transition rules so that no stage can silently promote
a scanner hit to "verified". Every transition is validated against an allow-list and
appended to an on-finding audit trail (``evidence['lifecycle']``).

Rules (Phase-3 spec):
  * scanner-only result                 -> suspected
  * independent supporting evidence     -> correlated
  * a probe demonstrates the property   -> verified
  * evidence disproves the issue        -> false_positive
  * insufficient evidence               -> needs_manual_review

``verified`` and ``false_positive`` are terminal: once a probe has demonstrated or
disproved a property, a later or weaker stage cannot overwrite it. A status may always
"transition" to itself (used to annotate a finding with evidence without escalating it).
"""
from __future__ import annotations

from datetime import datetime, timezone

from model.finding import Status

# from-status -> the set of statuses it may become.
_ALLOWED = {
    Status.SUSPECTED: {Status.SUSPECTED, Status.CORRELATED, Status.VERIFIED,
                       Status.FALSE_POSITIVE, Status.NEEDS_MANUAL_REVIEW},
    Status.CORRELATED: {Status.CORRELATED, Status.VERIFIED,
                        Status.FALSE_POSITIVE, Status.NEEDS_MANUAL_REVIEW},
    Status.NEEDS_MANUAL_REVIEW: {Status.NEEDS_MANUAL_REVIEW, Status.CORRELATED,
                                 Status.VERIFIED, Status.FALSE_POSITIVE},
    Status.VERIFIED: {Status.VERIFIED},              # terminal
    Status.FALSE_POSITIVE: {Status.FALSE_POSITIVE},  # terminal
}

# A verification *result* is a distinct concept from a finding's lifecycle *status*.
# A probe reports what it demonstrated; the lifecycle maps that onto a status. This is
# the single source of truth for that mapping, so no probe can e.g. call a "refuted"
# result "verified".
CONFIRMED = "confirmed"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"
NOT_APPLICABLE = "not_applicable"
VERIFICATION_RESULTS = (CONFIRMED, REFUTED, INCONCLUSIVE, NOT_APPLICABLE)

# verification result -> the lifecycle status it produces.
RESULT_TO_STATUS = {
    CONFIRMED: Status.VERIFIED,              # the property was demonstrated
    INCONCLUSIVE: Status.NEEDS_MANUAL_REVIEW,  # evidence insufficient either way
    REFUTED: Status.FALSE_POSITIVE,          # evidence disproved the issue
    NOT_APPLICABLE: Status.FALSE_POSITIVE,   # the issue cannot apply to this target
}


def status_for_result(result: str) -> str:
    """Map a verification result to the lifecycle status it implies."""
    if result not in RESULT_TO_STATUS:
        raise ValueError(
            f"Unknown verification result {result!r}; expected one of {VERIFICATION_RESULTS}")
    return RESULT_TO_STATUS[result]



def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def can_transition(current: str, new_status: str) -> bool:
    """True if ``current`` is permitted to become ``new_status``."""
    return new_status in _ALLOWED.get(current, set())


def transition(finding, new_status, *, actor, rationale, result=None,
               method=None, probe=None, evidence_updates=None) -> bool:
    """Attempt a status change. Returns True if applied, False if disallowed.

    A disallowed transition (e.g. trying to reopen a terminal ``verified`` finding)
    is a no-op for status and verification, but is still recorded as a rejected entry
    in the lifecycle log so the report shows what was attempted and why it was refused.
    """
    if not isinstance(finding.evidence, dict):
        finding.evidence = {}
    current = finding.status
    allowed = can_transition(current, new_status)

    if allowed:
        finding.status = new_status
        if evidence_updates:
            finding.evidence.update(evidence_updates)
        if method is not None or result is not None or rationale is not None:
            v = finding.verification if isinstance(finding.verification, dict) else {}
            if method is not None:
                v["method"] = method
            v["result"] = result
            v["probe"] = probe
            v["rationale"] = rationale
            v["timestamp"] = _now()
            finding.verification = v

    finding.evidence.setdefault("lifecycle", []).append({
        "from": current,
        "to": new_status if allowed else current,
        "requested": new_status,
        "actor": actor,
        "applied": bool(allowed),
        "rationale": rationale,
        "timestamp": _now(),
    })
    return allowed


def apply_verification(finding, *, result, actor, method, probe=None, rationale,
                       evidence_updates=None) -> bool:
    """Record a probe's verdict and move the finding to the mapped lifecycle status.

    Verifiers call this rather than :func:`transition` directly, so the result->status
    mapping is enforced in one place: a ``refuted`` / ``not_applicable`` result can only
    ever produce ``false_positive``, and ``confirmed`` is the *only* path to ``verified``.
    The verification result itself is always recorded on ``finding.verification['result']``,
    even when the target status is terminal and the transition is refused.
    """
    new_status = status_for_result(result)
    return transition(finding, new_status, actor=actor, rationale=rationale,
                      result=result, method=method, probe=probe,
                      evidence_updates=evidence_updates)
