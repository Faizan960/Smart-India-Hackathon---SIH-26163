"""SARIF 2.1.0 output for WATCHTOWER findings (Phase 5, item 10).

Emitted alongside report.json and report.html. Two correctness rules matter here:

  1. Source locations are never fabricated. A finding gets a physicalLocation only
     when it actually carries a source file; runtime/endpoint-only findings are
     expressed with a logicalLocation (the endpoint) and NO artifact location.
  2. SARIF `kind`/`level` follow the WATCHTOWER lifecycle honestly — only a
     verified finding is a `fail`; a false positive is `pass`/`notApplicable`;
     needs-review is `review`; suspected/correlated are `open`.
"""
from __future__ import annotations

import json
import re

SARIF_VERSION = "2.1.0"
_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/Faizan960/Smart-India-Hackathon---SIH-26163"

# WATCHTOWER severity -> SARIF level (only applied when kind == "fail").
_SEVERITY_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                   "low": "note", "info": "note"}


def _kind_and_level(fd: dict) -> tuple:
    status = fd.get("status")
    result = (fd.get("verification") or {}).get("result")
    if status == "verified":
        return "fail", _SEVERITY_LEVEL.get(fd.get("severity"), "warning")
    if status == "false_positive":
        return ("notApplicable" if result == "not_applicable" else "pass"), "none"
    if status == "needs_manual_review":
        return "review", "none"
    return "open", "none"          # suspected / correlated


def _rule_id(fd: dict) -> str:
    base = fd.get("cwe") or fd.get("tool") or "finding"
    return f"{fd.get('tool', 'watchtower')}/{base}".replace(" ", "-")


def _slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip()).strip("-")[:60] or "rule"


def _build_rules(findings: list) -> tuple:
    rules, index = [], {}
    for fd in findings:
        rid = _rule_id(fd)
        if rid in index:
            continue
        index[rid] = len(rules)
        tags = [fd.get("tool")]
        if fd.get("cwe"):
            tags.append(fd["cwe"])
        rules.append({
            "id": rid,
            "name": _slug(f"{fd.get('tool')}-{fd.get('cwe') or fd.get('title')}"),
            "shortDescription": {"text": fd.get("cwe") or fd.get("title") or rid},
            "properties": {"tags": [t for t in tags if t]},
        })
    return rules, index


def _location(fd: dict) -> list:
    """physicalLocation only for findings with a real source file; else a logical
    location naming the endpoint. Never fabricate a source path for runtime findings."""
    if fd.get("file"):
        region = {}
        if fd.get("line"):
            region = {"region": {"startLine": int(fd["line"])}}
        return [{"physicalLocation": {"artifactLocation": {"uri": fd["file"]}, **region}}]
    if fd.get("endpoint"):
        return [{"logicalLocations": [{"fullyQualifiedName": fd["endpoint"],
                                       "kind": "resource"}]}]
    return []


def _result(fd: dict, rule_index: dict) -> dict:
    kind, level = _kind_and_level(fd)
    rid = _rule_id(fd)
    verification = fd.get("verification") or {}
    message = fd.get("title") or rid
    if verification.get("rationale"):
        message = f"{message} — {verification['rationale']}"
    result = {
        "ruleId": rid,
        "ruleIndex": rule_index.get(rid, 0),
        "kind": kind,
        "level": level,
        "message": {"text": message},
        "properties": {
            "watchtower_id": fd.get("id"),
            "lifecycle_status": fd.get("status"),
            "verification_result": verification.get("result"),
            "evidence_confidence": fd.get("evidence_confidence"),
            "watchtower_risk_score": (fd.get("score") or {}).get("value"),
            "severity": fd.get("severity"),
            "tool": fd.get("tool"),
            "endpoint": fd.get("endpoint"),
        },
    }
    locations = _location(fd)
    if locations:
        result["locations"] = locations
    fingerprint = fd.get("fingerprint")
    if fingerprint:
        result["partialFingerprints"] = {"watchtowerFingerprint/v1": fingerprint}
    return result


def build_sarif(report: dict) -> dict:
    findings = report.get("findings") or []
    rules, rule_index = _build_rules(findings)
    scan = report.get("scan", {})
    invocation = {"executionSuccessful": True}
    if scan.get("timestamp"):
        invocation["startTimeUtc"] = scan["timestamp"]
    return {
        "$schema": _SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "WATCHTOWER",
                "version": report.get("watchtower_version", "0.0.0"),
                "informationUri": _INFO_URI,
                "rules": rules,
            }},
            "automationDetails": {"id": (report.get("assessment") or {}).get("id", "")},
            "invocations": [invocation],
            "results": [_result(fd, rule_index) for fd in findings],
            "properties": {
                "target": scan.get("target"),
                "repository": scan.get("repository"),
                "commit": scan.get("commit"),
                "note": ("WATCHTOWER SARIF: `kind=fail` marks only verified findings. "
                         "Runtime-only findings carry a logical location (the endpoint), "
                         "never a fabricated source path."),
            },
        }],
    }


def write_sarif(path: str, report: dict) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_sarif(report), handle, indent=2, ensure_ascii=False)
    return path

