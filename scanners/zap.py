"""OWASP ZAP baseline adapter — passive web scan of the LOCAL target only.

Runs ZAP's *baseline* scan (spider + passive rules); it never launches an active
attack scan, and it only ever targets the local application. ZAP can be provided
two ways and this adapter prefers whichever is present without installing anything:

  * a native ``zap-baseline.py`` on PATH, or
  * the official ``ghcr.io/zaproxy/zaproxy`` Docker image, IF the daemon is running
    and the image is already pulled (we do not auto-pull).

Every alert ZAP raises is recorded with status "suspected": a scanner's risk rating
is a classification, not a WATCHTOWER verification.
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Optional
from urllib.parse import urlparse, urlunparse

from scanners.base import CollectorResult, run_command, tool_available

TOOL = "zap"
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy"
_REPORT_NAME = "wt-zap-report.json"

INSTALL_GUIDANCE = (
    "OWASP ZAP is not runnable. Install ZAP so 'zap-baseline.py' is on PATH "
    "(https://www.zaproxy.org/download/), OR start Docker Desktop and pre-pull the "
    "image with 'docker pull ghcr.io/zaproxy/zaproxy'. WATCHTOWER does not install "
    "or pull it for you."
)


def _native_available() -> bool:
    return tool_available("zap-baseline.py")


def _docker_ready(timeout: int = 20) -> bool:
    if not tool_available("docker"):
        return False
    return run_command(["docker", "info"], timeout=timeout).returncode == 0


def _image_present(image: str, timeout: int = 20) -> bool:
    return run_command(["docker", "image", "inspect", image], timeout=timeout).returncode == 0


def zap_mode() -> Optional[str]:
    """Return 'native', 'docker', or None depending on what is usable right now."""
    if _native_available():
        return "native"
    if _docker_ready() and _image_present(ZAP_IMAGE):
        return "docker"
    return None


def _docker_target(target_url: str) -> str:
    """Rewrite a loopback target so it is reachable from inside a container."""
    parsed = urlparse(target_url)
    host = (parsed.hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        port = f":{parsed.port}" if parsed.port else ""
        netloc = f"host.docker.internal{port}"
        return urlunparse(parsed._replace(netloc=netloc))
    return target_url


def parse_output(text: str) -> dict:
    """Parse a ZAP JSON report. Raises json.JSONDecodeError on malformed input."""
    if not text or not text.strip():
        return {"site": []}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("ZAP JSON report was not an object.")
    data.setdefault("site", [])
    return data


def run_zap(target_url: str, timeout: int) -> CollectorResult:
    """Run a ZAP baseline scan against ``target_url``. Returns a CollectorResult always."""
    mode = zap_mode()
    if mode is None:
        return CollectorResult.unavailable(TOOL, INSTALL_GUIDANCE)

    work_dir = tempfile.mkdtemp(prefix="wt-zap-")
    report_host_path = os.path.join(work_dir, _REPORT_NAME)
    if mode == "native":
        # -I: do not exit non-zero on warnings; baseline is passive by default.
        command = ["zap-baseline.py", "-t", target_url, "-J", _REPORT_NAME, "-I"]
        cwd = work_dir
    else:
        command = [
            "docker", "run", "--rm",
            "-v", f"{work_dir}:/zap/wrk/:rw",
            ZAP_IMAGE, "zap-baseline.py",
            "-t", _docker_target(target_url),
            "-J", _REPORT_NAME, "-I",
        ]
        cwd = None

    try:
        run = run_command(command, timeout=timeout, cwd=cwd)
        report_text = ""
        try:
            with open(report_host_path, "r", encoding="utf-8") as handle:
                report_text = handle.read()
        except OSError:
            report_text = ""
    finally:
        try:
            os.remove(report_host_path)
        except OSError:
            pass
        try:
            os.rmdir(work_dir)
        except OSError:
            pass

    if not run.launched:
        return CollectorResult(tool=TOOL, available=True, executed=False, skipped=False,
                               command=command, error=run.error)
    if run.timed_out:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               command=command, duration_ms=run.duration_ms, error=run.error)

    if not report_text.strip():
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               raw=run.stdout, stderr=run.stderr, returncode=run.returncode,
                               duration_ms=run.duration_ms, command=command,
                               error="ZAP produced no JSON report (target unreachable or scan aborted).")
    try:
        parsed = parse_output(report_text)
    except (json.JSONDecodeError, ValueError) as exc:
        return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                               raw=report_text, stderr=run.stderr, returncode=run.returncode,
                               duration_ms=run.duration_ms, command=command,
                               error=f"Could not parse ZAP report: {exc}")

    return CollectorResult(tool=TOOL, available=True, executed=True, skipped=False,
                           parsed=parsed, raw=report_text, stderr=run.stderr,
                           returncode=run.returncode, duration_ms=run.duration_ms,
                           command=command)
