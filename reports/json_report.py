"""Assemble the machine-readable JSON report from scored findings and scan metadata.

Summary counts are computed from the actual findings — never hand-set — so the
report cannot claim more (or fewer) findings than were produced.
"""
from __future__ import annotations

import json

from engine.correlator import correlation_groups
from engine.dedup import duplicate_groups
from model.finding import Severity, Status

SCHEMA_VERSION = "1.0"


def _summary(findings) -> dict:
    sev = {s: 0 for s in Severity.ALL}
    status = {s: 0 for s in Status.ALL}
    for finding in findings:
        sev[finding.severity] = sev.get(finding.severity, 0) + 1
        status[finding.status] = status.get(finding.status, 0) + 1
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


def build_report(findings, scan: dict, watchtower_version: str, execution: list | None = None) -> dict:
    """Build the report dict. `findings` are Finding objects; output holds plain dicts.

    `execution` is the list of per-tool ToolExecution records (as dicts). Duplicate groups
    are the same advisory reported by multiple tools; correlation groups are independent
    tools corroborating the same underlying issue (which raises confidence, not verification).
    """
    summary = _summary(findings)
    summary.update(_execution_metrics(execution))
    return {
        "schema_version": SCHEMA_VERSION,
        "watchtower_version": watchtower_version,
        "scan": scan,
        "execution": execution or [],
        "summary": summary,
        "duplicate_groups": duplicate_groups(findings),
        "correlation_groups": correlation_groups(findings),
        "findings": [f.to_dict() for f in findings],
    }


def write_json_report(path: str, report: dict) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return path
