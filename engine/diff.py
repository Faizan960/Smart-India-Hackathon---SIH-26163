"""Assessment diff: compare two WATCHTOWER assessments (Phase 5, item 9; extended Phase 6).

Findings are matched by their stable content fingerprint (not the per-run WT-*
id, which is just an ordering label). The diff reports what changed — new,
resolved, unchanged, status/severity/score/verification-result changes, and
attack-surface additions/removals — as observed facts. It deliberately does NOT
infer causality: it will surface the recorded commit of each run as context, but
never claims a commit *caused* a change unless that linkage is present in the data.

Both operands may be either a full ``report.json`` (schema 1.1) or a canonical
``watchtower-baseline`` (schema 1.0) produced by engine.baseline. The baseline
intentionally omits ephemeral fields, so every field this diff reads is looked up
in a way that works for both shapes: the finding fingerprint (identical in both),
the risk-score value (report ``score.value`` OR baseline ``risk_score``), the
verification ``result``, and the commit/timestamp context (report ``scan`` OR
baseline ``target``/``assessment``).
"""
from __future__ import annotations

import hashlib


def _recompute_fingerprint(fd: dict) -> str:
    """Mirror model.finding.Finding.fingerprint for reports lacking a stored one."""
    evidence = fd.get("evidence") or {}
    rule = str(evidence.get("rule") or "") if isinstance(evidence, dict) else ""
    line = fd.get("line")
    parts = [fd.get("tool") or "", rule, fd.get("title") or "", fd.get("file") or "",
             str(line if line is not None else ""), fd.get("endpoint") or ""]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _finding_key(fd: dict) -> str:
    return fd.get("fingerprint") or _recompute_fingerprint(fd)


def _score_value(fd: dict):
    """Risk-score value for a finding, from either shape.

    A report stores it nested at ``score.value``; a canonical baseline flattens it to
    ``risk_score``. Membership is tested explicitly (not truthiness) so a legitimate
    score of ``0.0`` — e.g. a false positive — is never mistaken for "absent".
    """
    if "risk_score" in fd:
        return fd.get("risk_score")
    return (fd.get("score") or {}).get("value")


def _verification_result(fd: dict):
    """The explicit verification RESULT string, or None when none was recorded.

    Both shapes keep it at ``verification.result``. A missing verification block or a
    null result both read as None so that mutual absence is never treated as a change.
    """
    verification = fd.get("verification")
    return verification.get("result") if isinstance(verification, dict) else None


def _index_findings(report: dict) -> dict:
    return {_finding_key(fd): fd for fd in (report.get("findings") or [])}


def _brief(fd: dict) -> dict:
    return {"fingerprint": _finding_key(fd), "id": fd.get("id"), "title": fd.get("title"),
            "tool": fd.get("tool"), "severity": fd.get("severity"),
            "status": fd.get("status"), "score": _score_value(fd),
            "verification_result": _verification_result(fd)}


def _context(report: dict) -> dict:
    """Commit/timestamp context, resolved from a report (``scan``) or a baseline.

    Report shape wins on ``scan`` (unchanged behaviour); a baseline exposes the same
    facts under ``target.commit`` and ``assessment.timestamp``.
    """
    scan = report.get("scan") or {}
    target = report.get("target") or {}
    assessment = report.get("assessment") or {}
    return {
        "timestamp": scan.get("timestamp") or assessment.get("timestamp"),
        "commit": scan.get("commit") or target.get("commit") or assessment.get("commit"),
    }


def _endpoint_paths(report: dict) -> dict:
    surface = report.get("attack_surface") or {}
    out = {}
    for ep in surface.get("endpoints", []) or []:
        out[ep.get("path")] = ep
    return out


def diff_reports(old_report: dict, new_report: dict) -> dict:
    """Compare two assessments (report and/or baseline) and return observed differences.

    Each shared finding (matched by fingerprint) is classified as either *changed* — it
    appears in one or more of the status / severity / score / verification-result change
    lists — or *unchanged*. A finding is never both new and unchanged. State comparisons
    read from whichever shape each operand has, so a report and a baseline compare cleanly.
    """
    old, new = _index_findings(old_report), _index_findings(new_report)
    old_keys, new_keys = set(old), set(new)

    new_findings = [_brief(new[k]) for k in new_keys - old_keys]
    resolved = [_brief(old[k]) for k in old_keys - new_keys]

    status_changes, severity_changes, score_changes = [], [], []
    verification_changes, unchanged = [], []
    for key in old_keys & new_keys:
        o, n = old[key], new[key]
        changed = False
        if o.get("status") != n.get("status"):
            status_changes.append({"fingerprint": key, "id": n.get("id"),
                                   "title": n.get("title"), "from": o.get("status"),
                                   "to": n.get("status")})
            changed = True
        if o.get("severity") != n.get("severity"):
            severity_changes.append({"fingerprint": key, "id": n.get("id"),
                                     "title": n.get("title"), "from": o.get("severity"),
                                     "to": n.get("severity")})
            changed = True
        o_score, n_score = _score_value(o), _score_value(n)
        if o_score != n_score:
            score_changes.append({"fingerprint": key, "id": n.get("id"),
                                  "title": n.get("title"), "from": o_score, "to": n_score})
            changed = True
        o_res, n_res = _verification_result(o), _verification_result(n)
        # Only an explicit change in the recorded verification RESULT counts. Mutual absence
        # (both None) is equal, so a change is never invented from missing verification data,
        # and it is never derived from the lifecycle status.
        if o_res != n_res:
            verification_changes.append({"fingerprint": key, "id": n.get("id"),
                                         "title": n.get("title"), "from": o_res, "to": n_res})
            changed = True
        if not changed:
            unchanged.append(_brief(n))

    old_eps, new_eps = _endpoint_paths(old_report), _endpoint_paths(new_report)
    surface_additions = sorted(set(new_eps) - set(old_eps))
    surface_removals = sorted(set(old_eps) - set(new_eps))

    def _fp(entry):
        return entry.get("fingerprint") or ""

    return {
        "baseline": _context(old_report),
        "current": _context(new_report),
        "new_findings": sorted(new_findings, key=_fp),
        "resolved_findings": sorted(resolved, key=_fp),
        "unchanged_findings": sorted(unchanged, key=_fp),
        "status_changes": sorted(status_changes, key=_fp),
        "severity_changes": sorted(severity_changes, key=_fp),
        "score_changes": sorted(score_changes, key=_fp),
        "verification_changes": sorted(verification_changes, key=_fp),
        "attack_surface_additions": surface_additions,
        "attack_surface_removals": surface_removals,
        "counts": {
            "new": len(new_findings), "resolved": len(resolved),
            "unchanged": len(unchanged),
            "status_changed": len(status_changes),
            "severity_changed": len(severity_changes),
            "score_changed": len(score_changes),
            "verification_changed": len(verification_changes),
            "surface_added": len(surface_additions),
            "surface_removed": len(surface_removals),
        },
        "note": ("Differences are observed between the two assessments. Causality is NOT "
                 "inferred; the commit of each run is shown as context only. A change in "
                 "status may reflect a code change, a runtime/config difference, or which "
                 "tools were available — the diff does not attribute a cause."),
    }

