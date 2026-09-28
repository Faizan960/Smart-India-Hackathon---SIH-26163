"""Per-tool execution records — an honest, uniform account of every collector run.

Each stage in the orchestrator owns one ToolExecution. It captures whether the tool
succeeded, failed, or was skipped, plus timing, exit code, and (filled in after
normalization) how many findings it contributed. Tool FAILURES are never hidden:
a missing tool is 'skipped', a crash/parse error is 'failed', and both carry the
reason in ``error``.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

SUCCESS = "success"
FAILED = "failed"
SKIPPED = "skipped"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ToolExecution:
    """Mutable record of one tool's run, serialized into the report."""

    tool: str
    status: str = SKIPPED
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_seconds: float = 0.0
    exit_code: Optional[int] = None
    finding_count: int = 0
    error: Optional[str] = None
    _monotonic_start: Optional[float] = field(default=None, repr=False)

    def start(self) -> "ToolExecution":
        self.started_at = _now_iso()
        self._monotonic_start = time.monotonic()
        return self

    def _stop(self) -> None:
        self.finished_at = _now_iso()
        if self._monotonic_start is not None:
            self.duration_seconds = round(time.monotonic() - self._monotonic_start, 3)

    def success(self, exit_code: Optional[int] = None) -> "ToolExecution":
        self.status = SUCCESS
        self.exit_code = exit_code
        self._stop()
        return self

    def failed(self, error: str, exit_code: Optional[int] = None) -> "ToolExecution":
        self.status = FAILED
        self.error = error
        self.exit_code = exit_code
        self._stop()
        return self

    def skip(self, reason: str) -> "ToolExecution":
        self.status = SKIPPED
        self.error = reason
        # A skip may occur before start(); only stop the clock if it was started.
        if self._monotonic_start is not None:
            self._stop()
        return self

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "finding_count": self.finding_count,
            "error": self.error,
        }
