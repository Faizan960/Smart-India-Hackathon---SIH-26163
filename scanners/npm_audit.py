"""npm audit adapter — advisories for the target's npm dependency tree.

Runs ``npm audit --json`` inside the TARGET repository (never against WATCHTOWER
itself). npm audit and OSV-Scanner overlap but are kept as separate sources: each
finding records that it came from npm audit, and the deduplication step groups —
never merges — advisories that share an identifier. Advisory metadata (id, title,
severity, url, vulnerable range, fix availability) is preserved as reported.
"""
from __future__ import annotations

import json
import shutil
from typing import Optional

from scanners.base import CollectorResult, run_command

TOOL = "npm-audit"

INSTALL_GUIDANCE = (
    "npm is not installed / not on PATH. Install Node.js (which bundles npm) from "
    "https://nodejs.org/, then re-run. WATCHTOWER does not install it for you."
)

NO_LOCKFILE_HINT = (
    "npm audit reported an error (commonly a missing package-lock.json). Run "
    "'npm install' in the target repository to generate a lockfile, then re-run."
)


def npm_available() -> bool:
    return shutil.which("npm") is not None


def _npm_executable() -> str:
    # Resolve the real path so the Windows npm.cmd shim is launched correctly.
    return shutil.which("npm") or "npm"


def get_version() -> Optional[str]:
    if not npm_available():
        return None
    run = run_command([_npm_executable(), "--version"], timeout=30)
    if run.launched and run.stdout:
        return run.stdout.strip() or None
    return None


def parse_output(text: str) -> dict:
    """Parse ``npm audit --json`` output.

    Returns the parsed object. Raises ValueError if npm reported a top-level error
    (e.g. no lockfile), and json.JSONDecodeError on malformed input.
    """
    if not text or not text.strip():
        raise ValueError("npm audit produced no output.")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("npm audit JSON output was not an object.")
    if "error" in data:
        err = data.get("error") or {}
        summary = err.get("summary") if isinstance(err, dict) else str(err)
        raise ValueError(f"npm audit error: {summary or 'unspecified'}")
    data.setdefault("vulnerabilities", {})
    return data


def run_npm_audit(repo_path: str, timeout: int) -> CollectorResult:
    """Run ``npm audit --json`` in ``repo_path``. Returns a CollectorResult always."""
    if not npm_available():
        return CollectorResult.unavailable(TOOL, INSTALL_GUIDANCE)

    command = [_npm_executable(), "audit", "--json"]
    version = get_version()
    run = run_command(command, timeout=timeout, cwd=repo_path)

    if not run.launched:
        return CollectorResult(tool=TOOL, available=True, executed=False, skipped=False,
                               command=command, version=version, error=run.error)
    if run.timed_out:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               command=command, version=version,
                               duration_ms=run.duration_ms, error=run.error)

    # npm audit exits non-zero when advisories exist; that is not an execution error.
    try:
        parsed = parse_output(run.stdout)
    except ValueError as exc:
        detail = str(exc)
        if "npm audit error" in detail:
            detail = f"{detail} — {NO_LOCKFILE_HINT}"
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               raw=run.stdout, stderr=run.stderr, returncode=run.returncode,
                               duration_ms=run.duration_ms, version=version, command=command,
                               error=detail)
    except json.JSONDecodeError as exc:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               raw=run.stdout, stderr=run.stderr, returncode=run.returncode,
                               duration_ms=run.duration_ms, version=version, command=command,
                               error=f"Could not parse npm audit output: {exc}")

    return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                           parsed=parsed, raw=run.stdout, stderr=run.stderr,
                           returncode=run.returncode, duration_ms=run.duration_ms,
                           version=version, command=command)
