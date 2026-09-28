"""Assemble the machine-readable JSON report from scored findings and scan metadata.

Summary counts are computed from the actual findings — never hand-set — so the
report cannot claim more (or fewer) findings than were produced.
"""
from __future__ import annotations

import json

from engine.dedup import duplicate_groups
from model.finding import Severity

SCHEMA_VERSION = "1.0"


def _summary(findings) -> dict:
    counts = {s: 0 for s in Severity.ALL}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "total_findings": len(findings),
        "critical": counts[Severity.CRITICAL],
        "high": counts[Severity.HIGH],
        "medium": counts[Severity.MEDIUM],
        "low": counts[Severity.LOW],
        "info": counts[Severity.INFO],
    }


def build_report(findings, scan: dict, watchtower_version: str, execution: list | None = None) -> dict:
    """Build the report dict. `findings` are Finding objects; output holds plain dicts.

    `execution` is the list of per-tool ToolExecution records (as dicts). Duplicate
    groups are computed from the findings' shared identifiers — not correlation.
    """
    return {
        "schema_version": SCHEMA_VERSION,
        "watchtower_version": watchtower_version,
        "scan": scan,
        "execution": execution or [],
        "summary": _summary(findings),
        "duplicate_groups": duplicate_groups(findings),
        "findings": [f.to_dict() for f in findings],
    }


def write_json_report(path: str, report: dict) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    return path
