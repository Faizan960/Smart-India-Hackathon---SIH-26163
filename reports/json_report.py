"""Assemble the machine-readable JSON report from scored findings and scan metadata.

Summary counts are computed from the actual findings — never hand-set — so the
report cannot claim more (or fewer) findings than were produced.
"""
from __future__ import annotations

import json

from engine import explainer
from engine.attack_surface import link_findings
from engine.correlator import correlation_groups
from engine.dedup import duplicate_groups
from engine.diff import diff_reports
from engine.evidence_graph import build_evidence_graph
from engine.gate import evaluate_gate
from engine.lifecycle import CONFIRMED, INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Severity, Status

# Schema 1.2 (Phase 6): additive — same 1.1 fields, plus structured "diff" and "gate"
# sections. No 1.1 field was renamed or removed, so 1.1 consumers keep working.
SCHEMA_VERSION = "1.2"

# Tools whose findings come from Phase-4 active verification probes (kept distinct from
# the passive scanners so the report never conflates "a scanner ran" with "a probe verified").
ACTIVE_PROBE_TOOLS = ("cors", "rate-limit", "auth-mcp", "ssrf")


def _summary(findings) -> dict:
    sev = {s: 0 for s in Severity.ALL}
    status = {s: 0 for s in Status.ALL}
    verification = {CONFIRMED: 0, REFUTED: 0, INCONCLUSIVE: 0, NOT_APPLICABLE: 0}
    active_probe_findings = 0
    for finding in findings:
        sev[finding.severity] = sev.get(finding.severity, 0) + 1
        status[finding.status] = status.get(finding.status, 0) + 1
        result = (finding.verification or {}).get("result")
        if result in verification:
            verification[result] += 1
        if finding.tool in ACTIVE_PROBE_TOOLS:
            active_probe_findings += 1
    return {
        "total_findings": len(findings),
        "critical": sev[Severity.CRITICAL],
        "high": sev[Severity.HIGH],
        "medium": sev[Severity.MEDIUM],
        "low": sev[Severity.LOW],
        "info": sev[Severity.INFO],
        # Lifecycle status counts — the heart of the Phase-3 assessment.
        "suspected": status.get(Status.SUSPECTED, 0),
        "correlated": status.get(Status.CORRELATED, 0),
        "verified": status.get(Status.VERIFIED, 0),
        "false_positive": status.get(Status.FALSE_POSITIVE, 0),
        "needs_manual_review": status.get(Status.NEEDS_MANUAL_REVIEW, 0),
        # Explicit, unambiguous correlation terminology (a correlation GROUP is a cluster of
        # corroborating findings; a finding is "currently correlated" only if its lifecycle
        # STATUS is still `correlated` — verification later moves members to a terminal status,
        # so these two numbers routinely differ and must not be conflated).
        "findings_currently_correlated": status.get(Status.CORRELATED, 0),
        # Verification-result counts (Phase 4) — the raw probe verdict, kept separate from the
        # lifecycle status it maps to (confirmed->verified, refuted/not_applicable->false_positive,
        # inconclusive->needs_manual_review).
        "verification_results": {
            "confirmed": verification[CONFIRMED],
            "refuted": verification[REFUTED],
            "inconclusive": verification[INCONCLUSIVE],
            "not_applicable": verification[NOT_APPLICABLE],
        },
        "active_probe_findings": active_probe_findings,
        # Evidence confidence (Phase 5) — completeness of evidence, kept SEPARATE from
        # severity, WATCHTOWER Risk Score and lifecycle status.
        "evidence_confidence": explainer.confidence_counts(findings),
    }


def _execution_metrics(execution) -> dict:
    execution = execution or []
    skipped = [e.get("tool") for e in execution if e.get("status") == "skipped"]
    failed = [e.get("tool") for e in execution if e.get("status") == "failed"]
    return {
        "scanners_run": [e.get("tool") for e in execution if e.get("status") == "success"],
        "scanners_skipped": skipped,
        "scanners_failed": failed,
        "skipped_count": len(skipped),
        "execution_times": {e.get("tool"): e.get("duration_seconds") for e in execution},
    }


def _assessment_limitations(findings, surface_dict, execution) -> dict:
    """Report honestly what was NOT covered (Phase 5, item 7).

    Never makes the assessment look more comprehensive than it was: skipped
    scanners/probes, endpoints the probes never exercised, and dev-vs-production
    caveats are all surfaced explicitly.
    """
    execution = execution or []
    skipped = [e.get("tool") for e in execution if e.get("status") == "skipped"]
    failed = [e.get("tool") for e in execution if e.get("status") == "failed"]
    probes_skipped = [t for t in skipped if t in ACTIVE_PROBE_TOOLS]
    scanners_skipped = [t for t in skipped if t not in ACTIVE_PROBE_TOOLS]

    dev_runtime, unavailable = [], []
    for f in findings:
        rationale = ((f.verification or {}).get("rationale") or "").lower()
        result = (f.verification or {}).get("result")
        if result == INCONCLUSIVE and ("production" in rationale or "serverless" in rationale
                                       or "development" in rationale or "404" in rationale):
            unavailable.append({"id": f.id, "endpoint": f.endpoint, "tool": f.tool})
            dev_runtime.append(f.id)

    endpoints = (surface_dict or {}).get("endpoints", []) if surface_dict else []
    untested = [{"path": ep.get("path"), "risk_tags": ep.get("risk_tags", [])}
                for ep in endpoints
                if not ep.get("tested") and ep.get("risk_tags")]

    notes = []
    if scanners_skipped:
        notes.append(f"{len(scanners_skipped)} scanner(s) not installed/skipped: "
                     f"{', '.join(sorted(scanners_skipped))}.")
    if failed:
        notes.append(f"{len(failed)} tool(s) failed to run: {', '.join(sorted(failed))}.")
    if probes_skipped:
        notes.append(f"Active probe(s) skipped: {', '.join(sorted(probes_skipped))}.")
    if unavailable:
        notes.append(f"{len(unavailable)} endpoint(s) responded only under the local "
                     "development runtime; the production/serverless surface was not exercised.")
    if untested:
        notes.append(f"{len(untested)} attack-surface endpoint(s) carrying risk tags were not "
                     "exercised by any probe (static candidates only).")
    notes.append("Assessment targeted a LOCAL instance only; no public infrastructure was scanned.")
    return {
        "scanners_skipped": sorted(scanners_skipped),
        "scanners_failed": sorted(failed),
        "probes_skipped": sorted(probes_skipped),
        "unavailable_runtime_surfaces": unavailable,
        "development_vs_production": {
            "affected_findings": dev_runtime,
            "note": ("Some endpoints were only reachable via the local dev runtime; verdicts "
                     "for those reflect dev behaviour, not production.") if dev_runtime else
                    "No dev-vs-production discrepancies were recorded.",
        },
        "untested_attack_paths": untested,
        "notes": notes,
    }


def _enrich_findings(findings, graph, reverse_links) -> list:
    """Serialise findings and attach fingerprint, confidence, explanation, chain."""
    enriched = []
    for f in findings:
        fd = f.to_dict()
        fid = f.id or f.fingerprint()
        fd["fingerprint"] = f.fingerprint()
        fd["evidence_confidence"] = explainer.evidence_confidence(f)
        fd["explanation"] = explainer.explain(f)
        fd["evidence_chain"] = graph.chain_for(fid)
        fd["related_endpoints"] = reverse_links.get(f.id, [])
        enriched.append(fd)
    return enriched


def build_report(findings, scan: dict, watchtower_version: str, execution: list | None = None,
                 attack_surface=None, environment: dict | None = None,
                 assessment_id: str | None = None, baseline: dict | None = None) -> dict:
    """Build the report dict. `findings` are Finding objects; output holds plain dicts.

    `execution` is the list of per-tool ToolExecution records (as dicts). `attack_surface`
    is an AttackSurface (Phase 5) whose endpoints are linked to findings. Duplicate groups
    are the same advisory reported by multiple tools; correlation groups are independent
    tools corroborating the same underlying issue (which raises confidence, not verification).

    `baseline` is an optional prior assessment (a report.json OR a canonical baseline; both
    shapes are accepted by engine.diff). When supplied, the report embeds the structured
    ``diff`` (engine.diff.diff_reports(baseline, report), reused verbatim) and a
    baseline-aware ``gate``. When it is None, ``diff`` is null — NOT an empty diff, because
    "no baseline" is not "no changes" — and the gate still evaluates the current findings
    with ``baseline_aware`` false. The embedded ``gate`` is always engine.gate.evaluate_gate
    run against this very report, so report["gate"] cannot drift from the gate engine.
    """
    summary = _summary(findings)
    summary.update(_execution_metrics(execution))
    correlation = correlation_groups(findings)
    summary["correlation_groups_count"] = len(correlation)

    surface_dict = attack_surface.to_dict() if attack_surface is not None else None
    endpoint_dicts = surface_dict["endpoints"] if surface_dict else []
    reverse_links = link_findings(endpoint_dicts, findings) if endpoint_dicts else {}
    summary["attack_surface_count"] = len(endpoint_dicts)

    graph = build_evidence_graph(findings, endpoint_dicts, reverse_links, correlation)
    limitations = _assessment_limitations(findings, surface_dict, execution)

    report = {
        "schema_version": SCHEMA_VERSION,
        "watchtower_version": watchtower_version,
        "assessment": {"id": assessment_id, "timestamp": scan.get("timestamp"),
                       "target": scan.get("target"), "repository": scan.get("repository"),
                       "commit": scan.get("commit"), "branch": scan.get("branch")},
        "environment": environment or {},
        "scan": scan,
        "execution": execution or [],
        "summary": summary,
        "attack_surface": surface_dict or {"summary": {"endpoint_count": 0}, "endpoints": [],
                                           "security_modules": [], "integrations": [],
                                           "env_references": [], "notes": []},
        "assessment_limitations": limitations,
        "duplicate_groups": duplicate_groups(findings),
        "correlation_groups": correlation,
        "evidence_graph": graph.to_dict(),
        "findings": _enrich_findings(findings, graph, reverse_links),
    }

    # Phase-6 additive sections. Compute from the assembled report so both stay consistent
    # with their engines; diff_reports/evaluate_gate ignore the very keys we are adding.
    diff = diff_reports(baseline, report) if baseline is not None else None
    report["diff"] = diff
    report["gate"] = evaluate_gate(report, diff)
    return report


def write_json_report(path: str, report: dict) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return path
