"""The single normalized Finding structure shared by every collector and probe.

Scanners and probes never emit this directly; the normalizer converts their raw
output into Findings so correlation, scoring, and reporting stay tool-agnostic.
See docs/08-finding-schema.md.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    ALL = (CRITICAL, HIGH, MEDIUM, LOW, INFO)


class Status:
    """Finding lifecycle. Never "confirmed" — a probe result is "verified"."""

    SUSPECTED = "suspected"
    CORRELATED = "correlated"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"
    ALL = (SUSPECTED, CORRELATED, VERIFIED, FALSE_POSITIVE, NEEDS_MANUAL_REVIEW)


class AssetKind:
    AUTHENTICATION = "authentication"
    API_KEY = "api_key"
    MCP = "mcp"
    API = "api"
    UI = "ui"
    OTHER = "other"
    ALL = (AUTHENTICATION, API_KEY, MCP, API, UI, OTHER)


def _default_asset() -> dict:
    return {"kind": AssetKind.OTHER, "ref": None, "weight": 1.0}


def _default_verification() -> dict:
    return {
        "method": "none",       # none | active_probe | correlation
        "probe": None,          # probe identifier, if any
        "result": None,         # confirmed | refuted | inconclusive | None
        "rationale": "",
        "timestamp": None,
    }


@dataclass
class Finding:
    """One normalized observation. Required: tool, title, description."""

    tool: str
    title: str
    description: str
    severity: str = Severity.INFO
    status: str = Status.SUSPECTED
    id: Optional[str] = None
    cwe: Optional[str] = None          # e.g. "CWE-79"; None when the tool gives none
    file: Optional[str] = None
    line: Optional[int] = None
    endpoint: Optional[str] = None
    evidence: dict = field(default_factory=dict)
    score: dict = field(default_factory=dict)
    asset: dict = field(default_factory=_default_asset)
    verification: dict = field(default_factory=_default_verification)
    fix: Optional[dict] = None
    references: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in Severity.ALL:
            raise ValueError(
                f"Invalid severity {self.severity!r}; expected one of {Severity.ALL}"
            )
        if self.status not in Status.ALL:
            raise ValueError(
                f"Invalid status {self.status!r}; expected one of {Status.ALL}"
            )

    def fingerprint(self) -> str:
        """Stable content hash — the true identity of a finding across runs.

        The human-facing ``id`` (WT-SEM-0001) is a per-run sequence label; this
        fingerprint is what actually identifies a finding regardless of ordering.
        """
        rule = ""
        if isinstance(self.evidence, dict):
            rule = str(self.evidence.get("rule") or "")
        parts = [
            self.tool or "",
            rule,
            self.title or "",
            self.file or "",
            str(self.line if self.line is not None else ""),
            self.endpoint or "",
        ]
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return digest[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
