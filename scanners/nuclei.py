"""Nuclei adapter — controlled, non-destructive template scan of the LOCAL target.

Nuclei is run only against the local application, with a deliberately restricted and
non-destructive configuration: destructive/intrusive/dos/fuzzing/brute-force template
tags are excluded, out-of-band interactsh callbacks (which use third-party infra) are
disabled, and a rate limit is applied. Output is JSONL, one finding per line. Every
match is recorded with status "suspected": a template severity is a classification,
not a WATCHTOWER verification.
"""
from __future__ import annotations

import json
from typing import Optional

from scanners.base import CollectorResult, run_command, tool_available

TOOL = "nuclei"

# Tags excluded to keep the scan non-destructive and local-only.
_EXCLUDED_TAGS = "dos,intrusive,fuzz,fuzzing,brute-force,bruteforce"

INSTALL_GUIDANCE = (
    "Nuclei is not installed. Install a release binary from "
    "https://github.com/projectdiscovery/nuclei/releases (or 'go install "
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'), then re-run. "
    "WATCHTOWER does not install it for you."
)


def nuclei_available() -> bool:
    return tool_available("nuclei")


def get_version() -> Optional[str]:
    if not nuclei_available():
        return None
    run = run_command(["nuclei", "-version"], timeout=30)
    text = (run.stdout or "") + (run.stderr or "")
    text = text.strip()
    return text.splitlines()[0] if text else None


def build_command(target_url: str) -> list:
    """The controlled, non-destructive Nuclei command line."""
    return [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-disable-update-check",
        "-no-interactsh",
        "-severity", "low,medium,high,critical",
        "-exclude-tags", _EXCLUDED_TAGS,
        "-rate-limit", "50",
    ]


def parse_output(text: str) -> list:
    """Parse Nuclei JSONL (one JSON object per line) into a list of findings.

    Raises ValueError if the output is non-empty but no line is valid JSON.
    """
    if not text or not text.strip():
        return []
    findings = []
    saw_line = False
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        saw_line = True
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if saw_line and not findings:
        raise ValueError("Nuclei output contained no parsable JSON lines.")
    return findings


def run_nuclei(target_url: str, timeout: int) -> CollectorResult:
    """Run a controlled Nuclei scan against ``target_url``. Returns a CollectorResult always."""
    if not nuclei_available():
        return CollectorResult.unavailable(TOOL, INSTALL_GUIDANCE)

    command = build_command(target_url)
    version = get_version()
    run = run_command(command, timeout=timeout)

    if not run.launched:
        return CollectorResult(tool=TOOL, available=True, executed=False, skipped=False,
                               command=command, version=version, error=run.error)
    if run.timed_out:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               command=command, version=version,
                               duration_ms=run.duration_ms, error=run.error)

    try:
        parsed = parse_output(run.stdout)
    except ValueError as exc:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               raw=run.stdout, stderr=run.stderr, returncode=run.returncode,
                               duration_ms=run.duration_ms, version=version, command=command,
                               error=f"Could not parse Nuclei output: {exc}")

    return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                           parsed=parsed, raw=run.stdout, stderr=run.stderr,
                           returncode=run.returncode, duration_ms=run.duration_ms,
                           version=version, command=command)
