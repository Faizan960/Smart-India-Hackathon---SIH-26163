"""Semgrep adapter — safe subprocess execution and JSON capture.

Design rules enforced here:
  * Commands are built as argument arrays and run WITHOUT shell=True.
  * A missing executable is reported as "skipped" with install guidance, never
    as a crash and never as a fake result.
  * A non-zero exit code is NOT automatically an error: Semgrep exits non-zero
    in normal situations (e.g. blocking findings). We classify a run as an
    execution error only when the JSON output cannot be parsed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

INSTALL_GUIDANCE = (
    "Semgrep is not installed. Install it with 'pip install semgrep' "
    "(or 'brew install semgrep'), then re-run. See https://semgrep.dev/docs/getting-started/"
)


@dataclass
class SemgrepResult:
    """Structured outcome of one Semgrep invocation (raw, pre-normalization)."""

    available: bool
    executed: bool
    skipped: bool
    parsed: Optional[dict] = None       # parsed Semgrep JSON, when successful
    raw_stdout: str = ""                # preserved for the evidence store
    stderr: str = ""
    returncode: Optional[int] = None
    duration_ms: Optional[int] = None
    version: Optional[str] = None
    command: list[str] = field(default_factory=list)
    error: Optional[str] = None         # human-readable failure/skip reason

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        if self.error:
            return "failed"
        return "ran"

    @property
    def result_count(self) -> int:
        if not self.parsed:
            return 0
        return len(self.parsed.get("results", []) or [])


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def get_version() -> Optional[str]:
    if not semgrep_available():
        return None
    try:
        completed = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    return completed.stdout.strip() or None


def run_semgrep(repo_path: str, timeout: int, config: str = "auto") -> SemgrepResult:
    """Run Semgrep over ``repo_path`` and capture its JSON output.

    Returns a SemgrepResult in all cases — it never raises for the expected
    failure modes (missing binary, timeout, unparseable output).
    """
    if not semgrep_available():
        return SemgrepResult(
            available=False,
            executed=False,
            skipped=True,
            error=INSTALL_GUIDANCE,
        )

    command = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--json",
        "--metrics=off",
        repo_path,
    ]
    version = get_version()
    start = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return SemgrepResult(
            available=True,
            executed=True,
            skipped=False,
            command=command,
            version=version,
            duration_ms=int((time.monotonic() - start) * 1000),
            error=f"Semgrep timed out after {timeout}s.",
        )
    except OSError as exc:
        return SemgrepResult(
            available=True,
            executed=False,
            skipped=False,
            command=command,
            version=version,
            error=f"Failed to launch Semgrep: {exc}",
        )

    duration_ms = int((time.monotonic() - start) * 1000)

    # Non-zero exit is fine as long as we can parse the JSON. Only unparseable
    # output counts as an execution error.
    parsed: Optional[dict] = None
    parse_error: Optional[str] = None
    if completed.stdout.strip():
        try:
            parsed = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            parse_error = f"Could not parse Semgrep JSON output: {exc}"
    else:
        parse_error = "Semgrep produced no output to parse."

    if parsed is None:
        return SemgrepResult(
            available=True,
            executed=True,
            skipped=False,
            raw_stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            duration_ms=duration_ms,
            version=version,
            command=command,
            error=parse_error,
        )

    return SemgrepResult(
        available=True,
        executed=True,
        skipped=False,
        parsed=parsed,
        raw_stdout=completed.stdout,
        stderr=completed.stderr,
        returncode=completed.returncode,
        duration_ms=duration_ms,
        version=version,
        command=command,
    )
