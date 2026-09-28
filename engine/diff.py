"""Assessment diff: compare two WATCHTOWER reports (Phase 5, item 9).

Findings are matched by their stable content fingerprint (not the per-run WT-*
id, which is just an ordering label). The diff reports what changed — new,
resolved, status/severity/score changes, and attack-surface additions/removals —
as observed facts. It deliberately does NOT infer causality: it will surface the
recorded commit of each run as context, but never claims a commit *caused* a
change unless that linkage is present in the data.
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


def _index_findings(report: dict) -> dict:
    return {_finding_key(fd): fd for fd in (report.get("findings") or [])}


def _brief(fd: dict) -> dict:
    return {"id": fd.get("id"), "title": fd.get("title"), "tool": fd.get("tool"),
            "severity": fd.get("severity"), "status": fd.get("status"),
            "score": (fd.get("score") or {}).get("value")}


def _endpoint_paths(report: dict) -> dict:
    surface = report.get("attack_surface") or {}
    out = {}
    for ep in surface.get("endpoints", []) or []:
        out[ep.get("path")] = ep
    return out


def diff_reports(old_report: dict, new_report: dict) -> dict:
    """Compare two reports and return the observed differences."""
    old, new = _index_findings(old_report), _index_findings(new_report)
    old_keys, new_keys = set(old), set(new)

    new_findings = [_brief(new[k]) for k in new_keys - old_keys]
    resolved = [_brief(old[k]) for k in old_keys - new_keys]

    status_changes, severity_changes, score_changes = [], [], []
    for key in old_keys & new_keys:
        o, n = old[key], new[key]
        if o.get("status") != n.get("status"):
            status_changes.append({"id": n.get("id"), "title": n.get("title"),
                                   "from": o.get("status"), "to": n.get("status")})
        if o.get("severity") != n.get("severity"):
            severity_changes.append({"id": n.get("id"), "title": n.get("title"),
                                     "from": o.get("severity"), "to": n.get("severity")})
        o_score = (o.get("score") or {}).get("value")
        n_score = (n.get("score") or {}).get("value")
        if o_score != n_score:
            score_changes.append({"id": n.get("id"), "title": n.get("title"),
                                  "from": o_score, "to": n_score})

    old_eps, new_eps = _endpoint_paths(old_report), _endpoint_paths(new_report)
    surface_additions = sorted(set(new_eps) - set(old_eps))
    surface_removals = sorted(set(old_eps) - set(new_eps))

    old_scan, new_scan = old_report.get("scan", {}), new_report.get("scan", {})
    return {
        "baseline": {"timestamp": old_scan.get("timestamp"),
                     "commit": old_scan.get("commit")},
        "current": {"timestamp": new_scan.get("timestamp"),
                    "commit": new_scan.get("commit")},
        "new_findings": sorted(new_findings, key=lambda x: x["id"] or ""),
        "resolved_findings": sorted(resolved, key=lambda x: x["id"] or ""),
        "status_changes": sorted(status_changes, key=lambda x: x["id"] or ""),
        "severity_changes": sorted(severity_changes, key=lambda x: x["id"] or ""),
        "score_changes": sorted(score_changes, key=lambda x: x["id"] or ""),
        "attack_surface_additions": surface_additions,
        "attack_surface_removals": surface_removals,
        "counts": {
            "new": len(new_findings), "resolved": len(resolved),
            "status_changed": len(status_changes),
            "severity_changed": len(severity_changes),
            "score_changed": len(score_changes),
            "surface_added": len(surface_additions),
            "surface_removed": len(surface_removals),
        },
        "note": ("Differences are observed between the two reports. Causality is NOT "
                 "inferred; the commit of each run is shown as context only. A change in "
                 "status may reflect a code change, a runtime/config difference, or which "
                 "tools were available — the diff does not attribute a cause."),
    }

