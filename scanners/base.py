"""Shared plumbing for external-tool adapters.

Centralizes safe subprocess execution (argument arrays, never shell=True; timeout
and missing-binary handling) and a common CollectorResult shape so the orchestrator
can treat every scanner identically. Individual tools never define WATCHTOWER's
finding schema — they return raw output here, and the normalizer maps it to Finding.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@dataclass
class CommandRun:
    """Outcome of one subprocess invocation."""

    launched: bool
    returncode: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    error: Optional[str] = None
    timed_out: bool = False


def run_command(command: list[str], timeout: int, cwd: Optional[str] = None) -> CommandRun:
    """Run a command as an argument array (no shell) and capture its output."""
    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return CommandRun(True, None, "", "", int((time.monotonic() - start) * 1000),
                          error=f"Timed out after {timeout}s.", timed_out=True)
    except FileNotFoundError as exc:
        return CommandRun(False, None, "", "", int((time.monotonic() - start) * 1000),
                          error=f"Executable not found: {exc}")
    except OSError as exc:
        return CommandRun(False, None, "", "", int((time.monotonic() - start) * 1000),
                          error=f"Failed to launch: {exc}")
    return CommandRun(True, completed.returncode, completed.stdout, completed.stderr,
                      int((time.monotonic() - start) * 1000))


@dataclass
class CollectorResult:
    """Uniform, pre-normalization result returned by every tool adapter."""

    tool: str
    available: bool = False
    executed: bool = False
    skipped: bool = False
    parsed: object = None            # parsed JSON (dict or list), when successful
    raw: str = ""                    # raw output preserved for the evidence store
    stderr: str = ""
    returncode: Optional[int] = None
    duration_ms: Optional[int] = None
    version: Optional[str] = None
    command: list = field(default_factory=list)
    error: Optional[str] = None

    @classmethod
    def unavailable(cls, tool: str, message: str) -> "CollectorResult":
        return cls(tool=tool, available=False, executed=False, skipped=True, error=message)
