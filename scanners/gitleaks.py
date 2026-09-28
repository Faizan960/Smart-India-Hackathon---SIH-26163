"""Gitleaks adapter — detect secret-like matches in the target repository.

Security-critical rule: this adapter NEVER lets a real secret value leave the
process. Gitleaks is invoked with ``--redact`` and, as belt-and-suspenders, every
parsed entry is redacted again here (``Match``/``Secret`` -> "[REDACTED]") before it
is returned, saved as evidence, or normalized. What we preserve is the *metadata* of
a match (rule, file, line, commit) — enough to act on, without exposing the secret.

Only the repository is scanned (never the network). Severity is NOT invented: it is
read from Gitleaks rule metadata when present and otherwise left for the normalizer
to record as tool-unspecified.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Optional

from scanners.base import CollectorResult, run_command, tool_available

TOOL = "gitleaks"

INSTALL_GUIDANCE = (
    "Gitleaks is not installed. Install a release binary from "
    "https://github.com/gitleaks/gitleaks/releases (or 'brew install gitleaks'), "
    "then re-run. WATCHTOWER does not install it for you."
)

# Fields that may carry the raw secret; always overwritten before use.
_SENSITIVE_FIELDS = ("Match", "Secret")
_REDACTED = "[REDACTED]"


def gitleaks_available() -> bool:
    return tool_available("gitleaks")


def get_version() -> Optional[str]:
    if not gitleaks_available():
        return None
    run = run_command(["gitleaks", "version"], timeout=30)
    if run.launched and run.stdout:
        return run.stdout.strip() or None
    return None


def redact_entry(entry: dict) -> dict:
    """Return a copy of one Gitleaks finding with all secret-bearing fields masked."""
    if not isinstance(entry, dict):
        return entry
    safe = dict(entry)
    for key in _SENSITIVE_FIELDS:
        if key in safe and safe[key] not in (None, "", _REDACTED):
            original = safe[key]
            safe[key] = _REDACTED
            # Preserve a non-sensitive fact — the length — so triage has a signal.
            safe.setdefault(f"{key}Length", len(str(original)))
    return safe


def redact_output(entries) -> list:
    """Redact a whole list of Gitleaks findings (no secret values survive)."""
    if not isinstance(entries, list):
        return []
    return [redact_entry(e) for e in entries]


def parse_output(text: str) -> list:
    """Parse Gitleaks JSON report text into a redacted list of findings.

    Raises json.JSONDecodeError on malformed input so callers can classify it.
    """
    if not text or not text.strip():
        return []
    data = json.loads(text)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("Gitleaks JSON report was not a list of findings.")
    return redact_output(data)


def run_gitleaks(repo_path: str, timeout: int) -> CollectorResult:
    """Scan ``repo_path`` for secrets. Returns a redacted CollectorResult in all cases."""
    if not gitleaks_available():
        return CollectorResult.unavailable(TOOL, INSTALL_GUIDANCE)

    # Gitleaks writes JSON to a report file; we read, redact, then discard it.
    fd, report_path = tempfile.mkstemp(prefix="wt-gitleaks-", suffix=".json")
    os.close(fd)
    command = [
        "gitleaks", "detect",
        "--source", repo_path,
        "--no-git",
        "--report-format", "json",
        "--report-path", report_path,
        "--redact",
        "--no-banner",
    ]
    version = get_version()
    try:
        run = run_command(command, timeout=timeout)
        report_text = ""
        try:
            with open(report_path, "r", encoding="utf-8") as handle:
                report_text = handle.read()
        except OSError:
            report_text = ""
    finally:
        try:
            os.remove(report_path)
        except OSError:
            pass

    if not run.launched:
        return CollectorResult(tool=TOOL, available=True, executed=False, skipped=False,
                               command=command, version=version, error=run.error)
    if run.timed_out:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               command=command, version=version,
                               duration_ms=run.duration_ms, error=run.error)

    # Prefer the report file; fall back to stdout if the tool streamed JSON there.
    source_text = report_text if report_text.strip() else run.stdout
    try:
        parsed = parse_output(source_text)
    except (json.JSONDecodeError, ValueError) as exc:
        # No parsable report. Gitleaks exits 0 (no leaks) or 1 (leaks); anything
        # else with no report is a genuine execution error we must not hide.
        if run.returncode in (0, 1) and not source_text.strip():
            parsed = []
        else:
            return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                                   raw=source_text, stderr=run.stderr, returncode=run.returncode,
                                   duration_ms=run.duration_ms, version=version, command=command,
                                   error=f"Could not parse Gitleaks output: {exc}")

    raw_redacted = json.dumps(parsed, indent=2)
    return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                           parsed=parsed, raw=raw_redacted, stderr=run.stderr,
                           returncode=run.returncode, duration_ms=run.duration_ms,
                           version=version, command=command)
