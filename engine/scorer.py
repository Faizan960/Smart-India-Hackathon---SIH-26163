"""WATCHTOWER Risk Score — a transparent prioritisation number, explicitly NOT CVSS.

    score = base_severity x verification_multiplier x asset_multiplier

capped at 10.0 and rounded to 2 decimals. Every input factor is recorded on the
finding so the number is fully recomputable. See docs/09-risk-scoring.md.
"""
from __future__ import annotations

from model.finding import AssetKind, Finding, Severity, Status

SCORE_MODEL = "watchtower-risk-score-v1"
SCORE_CAP = 10.0

BASE_SEVERITY = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.INFO: 0.0,
}

VERIFICATION_MULTIPLIER = {
    Status.SUSPECTED: 1.0,
    Status.CORRELATED: 1.2,
    Status.VERIFIED: 1.5,
    Status.NEEDS_MANUAL_REVIEW: 1.0,
    Status.FALSE_POSITIVE: 0.0,
}

ASSET_MULTIPLIER = {
    AssetKind.AUTHENTICATION: 1.5,
    AssetKind.API_KEY: 1.5,
    AssetKind.MCP: 1.5,
    AssetKind.API: 1.2,
    AssetKind.UI: 1.0,
    AssetKind.OTHER: 1.0,
}


def score_finding(finding: Finding) -> Finding:
    """Compute and attach the risk score. Also records the asset weight used."""
    base = BASE_SEVERITY.get(finding.severity, 0.0)
    verification = VERIFICATION_MULTIPLIER.get(finding.status, 1.0)

    asset_kind = (finding.asset or {}).get("kind", AssetKind.OTHER)
    asset = ASSET_MULTIPLIER.get(asset_kind, 1.0)

    raw = base * verification * asset
    value = round(min(raw, SCORE_CAP), 2)

    # Surface the weight that was actually applied.
    if finding.asset is None:
        finding.asset = {}
    finding.asset["weight"] = asset

    finding.score = {
        "model": SCORE_MODEL,
        "value": value,
        "capped": raw > SCORE_CAP,
        "factors": {
            "base_severity": base,
            "verification_multiplier": verification,
            "asset_multiplier": asset,
        },
    }
    return finding


def score_all(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        score_finding(finding)
    return findings
