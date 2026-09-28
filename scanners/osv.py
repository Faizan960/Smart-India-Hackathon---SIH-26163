"""OSV-Scanner adapter — dependency vulnerabilities from manifests/lockfiles.

These are DEPENDENCY findings reported by OSV; they are not WATCHTOWER discoveries.
The adapter runs OSV-Scanner over the target repository, captures its JSON verbatim
for the evidence store, and hands the parsed structure to the normalizer. Vulnerability
identifiers (GHSA-*, CVE-*) and any ecosystem-provided severity are preserved exactly —
nothing is invented here.
"""
from __future__ import annotations

import json
from typing import Optional

from scanners.base import CollectorResult, run_command, tool_available

TOOL = "osv-scanner"

INSTALL_GUIDANCE = (
    "OSV-Scanner is not installed. Install a release binary from "
    "https://github.com/google/osv-scanner/releases (or 'go install "
    "github.com/google/osv-scanner/cmd/osv-scanner@latest'), then re-run. "
    "WATCHTOWER does not install it for you."
)


def osv_available() -> bool:
    return tool_available("osv-scanner")


def get_version() -> Optional[str]:
    if not osv_available():
        return None
    run = run_command(["osv-scanner", "--version"], timeout=30)
    if run.launched and run.stdout:
        return run.stdout.strip().splitlines()[0] if run.stdout.strip() else None
    return None


def parse_output(text: str) -> dict:
    """Parse OSV-Scanner JSON. Empty output (no vulns) becomes an empty result set.

    Raises json.JSONDecodeError on malformed non-empty input.
    """
    if not text or not text.strip():
        return {"results": []}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("OSV-Scanner JSON output was not an object.")
    data.setdefault("results", [])
    return data


def run_osv(repo_path: str, timeout: int) -> CollectorResult:
    """Scan ``repo_path`` dependency manifests/lockfiles. Returns a CollectorResult always."""
    if not osv_available():
        return CollectorResult.unavailable(TOOL, INSTALL_GUIDANCE)

    command = ["osv-scanner", "--format", "json", "--recursive", repo_path]
    version = get_version()
    run = run_command(command, timeout=timeout)

    if not run.launched:
        return CollectorResult(tool=TOOL, available=True, executed=False, skipped=False,
                               command=command, version=version, error=run.error)
    if run.timed_out:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               command=command, version=version,
                               duration_ms=run.duration_ms, error=run.error)

    # OSV-Scanner exits non-zero when it finds vulnerabilities; that is not an error.
    try:
        parsed = parse_output(run.stdout)
    except (json.JSONDecodeError, ValueError) as exc:
        # Exit code 128 == "no packages found"; treat as an empty, honest result.
        if run.returncode == 128 and not run.stdout.strip():
            parsed = {"results": []}
        else:
            return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                                   raw=run.stdout, stderr=run.stderr, returncode=run.returncode,
                                   duration_ms=run.duration_ms, version=version, command=command,
                                   error=f"Could not parse OSV-Scanner output: {exc}")

    return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                           parsed=parsed, raw=run.stdout, stderr=run.stderr,
                           returncode=run.returncode, duration_ms=run.duration_ms,
                           version=version, command=command)
