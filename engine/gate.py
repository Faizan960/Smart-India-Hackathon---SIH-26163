"""Deterministic security gate (Phase 6, Step 4).

A policy layer over an already-produced assessment. The gate consumes ONLY structured
data — ``report["findings"]``, ``report["assessment_limitations"]``, and (when a baseline
is supplied) the structured diff from ``engine.diff`` — and never parses HTML, SARIF,
terminal output, or any human-readable report text. It does not change the lifecycle
model or the WATCHTOWER Risk Score; it reads the lifecycle status and severity those
earlier stages already assigned and applies a fixed pass/warn/fail policy on top.

Policy ``watchtower-gate-v1`` (priority FAIL > WARN > PASS):
  FAIL if any verified Critical, any verified High, or any NEWLY verified finding vs the
       baseline (the last is only evaluated when a baseline/diff is available).
  WARN if any needs_manual_review finding exists, or assessment limitations materially
       reduce coverage (a scanner/probe that was meant to run did not, a tool failed, or
       a surface was reachable only under the dev runtime).
  PASS when neither FAIL nor WARN applies.

Newly verified findings are identified by STABLE FINGERPRINT through the structured diff
(a new finding whose current status is verified, or a shared finding whose status moved
to verified from a non-verified state) — never by array position, and never guessed when
no baseline is available. A WARN is not a process failure: only FAIL exits non-zero.
"""
from __future__ import annotations

from model.finding import Severity, Status

GATE_POLICY = "watchtower-gate-v1"

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"

# Limitation sections that represent a MATERIAL coverage gap: an assessment step that was
# meant to run did not, a tool failed, or a surface was only reachable under the dev
# runtime. Purely informational limitations (static attack-surface candidates no probe
# exercised, the standing local-only note) are deliberately excluded, and no numeric
# coverage threshold is invented.
_MATERIAL_LIMITATION_KEYS = (
    "scanners_skipped",
    "scanners_failed",
    "probes_skipped",
    "unavailable_runtime_surfaces",
)


def _is_verified(finding: dict) -> bool:
    return finding.get("status") == Status.VERIFIED


def _count_verified(findings: list, severity: str) -> int:
    return sum(1 for f in findings if _is_verified(f) and f.get("severity") == severity)


def _needs_manual_review(findings: list) -> int:
    return sum(1 for f in findings if f.get("status") == Status.NEEDS_MANUAL_REVIEW)


def _new_verified_fingerprints(diff: dict) -> set:
    """Fingerprints of findings verified now but NOT verified in the baseline.

    Structured diff only: a NEW finding already at status ``verified`` (baseline had it
    absent), or a shared finding whose status moved TO ``verified`` from another state
    (suspected/correlated/needs_manual_review -> verified). Both sources are keyed by the
    stable content fingerprint, so array position is irrelevant and the two de-duplicate.
    A finding verified on both sides never appears (status_changes only records a change),
    and a baseline-verified finding that later resolved is a resolution, not a new verify.
    """
    fingerprints = set()
    for brief in diff.get("new_findings") or []:
        if brief.get("status") == Status.VERIFIED:
            fingerprints.add(brief.get("fingerprint"))
    for change in diff.get("status_changes") or []:
        if change.get("to") == Status.VERIFIED and change.get("from") != Status.VERIFIED:
            fingerprints.add(change.get("fingerprint"))
    return fingerprints


def _material_limitations(limitations: dict) -> list:
    """(key, count) pairs for limitation sections that materially reduce coverage.

    Deterministic order (the fixed ``_MATERIAL_LIMITATION_KEYS`` sequence). Empty or
    missing sections contribute nothing, so informational-only reports raise no WARN here.
    """
    signals = []
    for key in _MATERIAL_LIMITATION_KEYS:
        items = limitations.get(key) or []
        if items:
            signals.append((key, len(items)))
    return signals


def _reason(level: str, code: str, count: int, message: str, *,
            severity: str | None = None, detail: str | None = None) -> dict:
    """A machine-readable gate reason. ``severity``/``detail`` are included only when set."""
    reason = {"level": level, "code": code, "count": count, "message": message}
    if severity is not None:
        reason["severity"] = severity
    if detail is not None:
        reason["detail"] = detail
    return reason


def evaluate_gate(report: dict, diff: dict | None = None) -> dict:
    """Evaluate the security gate over a structured report and optional structured diff.

    Pure and deterministic: identical inputs always produce an identical result. ``diff``
    should be ``engine.diff.diff_reports(baseline, report)``; when it is ``None`` the gate
    still evaluates the current assessment but makes NO claim about newly verified findings
    (``new_verified`` stays 0 and ``baseline_aware`` is False) rather than inventing history.
    """
    findings = report.get("findings") or []
    limitations = report.get("assessment_limitations") or {}
    baseline_aware = diff is not None

    verified_critical = _count_verified(findings, Severity.CRITICAL)
    verified_high = _count_verified(findings, Severity.HIGH)
    verified_medium = _count_verified(findings, Severity.MEDIUM)
    manual_review = _needs_manual_review(findings)
    new_verified = _new_verified_fingerprints(diff) if baseline_aware else set()

    fail_reasons, warn_reasons = [], []
    if verified_critical:
        fail_reasons.append(_reason(FAIL, "VERIFIED_CRITICAL", verified_critical,
                                    f"{verified_critical} verified Critical finding(s)",
                                    severity=Severity.CRITICAL))
    if verified_high:
        fail_reasons.append(_reason(FAIL, "VERIFIED_HIGH", verified_high,
                                    f"{verified_high} verified High finding(s)",
                                    severity=Severity.HIGH))
    if new_verified:
        fail_reasons.append(_reason(FAIL, "NEW_VERIFIED", len(new_verified),
                                    f"{len(new_verified)} newly verified finding(s) vs baseline"))

    if manual_review:
        warn_reasons.append(_reason(WARN, "NEEDS_MANUAL_REVIEW", manual_review,
                                    f"{manual_review} finding(s) need manual review"))
    for key, count in _material_limitations(limitations):
        warn_reasons.append(_reason(WARN, "ASSESSMENT_LIMITATION", count,
                                    f"coverage limitation: {key} ({count})", detail=key))

    if fail_reasons:
        result = FAIL
    elif warn_reasons:
        result = WARN
    else:
        result = PASS

    # FAIL reasons sort before WARN ("FAIL" < "WARN"), then by code, then by detail.
    reasons = sorted(fail_reasons + warn_reasons,
                     key=lambda r: (r["level"], r["code"], r.get("detail") or ""))
    return {
        "result": result,
        "policy": GATE_POLICY,
        "baseline_aware": baseline_aware,
        "reasons": reasons,
        "counts": {
            "verified_critical": verified_critical,
            "verified_high": verified_high,
            "verified_medium": verified_medium,
            "needs_manual_review": manual_review,
            "new_verified": len(new_verified),
        },
    }


def exit_code_for(result: str) -> int:
    """Process exit code for a gate RESULT: only FAIL is a failure. WARN and PASS -> 0.

    (Configuration/IO/execution errors return 2, but that is decided by the CLI layer, not
    by the gate result itself.)
    """
    return 1 if result == FAIL else 0


def render_gate(gate: dict) -> list:
    """Compact, secret-free human-readable lines describing a gate result."""
    counts = gate["counts"]
    lines = [
        f"gate result: {gate['result']}  "
        f"(policy {gate['policy']}, baseline_aware={gate['baseline_aware']})",
        f"  verified: critical={counts['verified_critical']} high={counts['verified_high']} "
        f"medium={counts['verified_medium']}   needs_manual_review={counts['needs_manual_review']}"
        f"   new_verified={counts['new_verified']}",
    ]
    for reason in gate["reasons"]:
        lines.append(f"  [{reason['level']}] {reason['code']}: {reason['message']}")
    if not gate["reasons"]:
        lines.append("  no gate conditions triggered")
    return lines
