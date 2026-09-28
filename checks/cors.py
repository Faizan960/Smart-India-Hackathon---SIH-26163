"""CORS verification probe — does the LOCAL target accept unsafe cross-origin requests?

An *active* probe: it sends a real request carrying a hostile ``Origin`` (and an
OPTIONS preflight) to the local target and inspects the CORS response headers. It
never sends credentials to an external origin — it only observes whether the target
*would* allow one. Classification is deliberately conservative: the mere presence of
an ``Access-Control-Allow-Origin`` header is not a weakness; a policy that reflects an
arbitrary origin *and* allows credentials is.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from checks.active_base import ProbeVerdict, is_local_url
from engine.lifecycle import CONFIRMED, INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Severity

# A deliberately hostile origin that the target should never trust.
EVIL_ORIGIN = "https://evil.example"
REFERENCES = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
              "https://portswigger.net/web-security/cors"]

_CORS_HEADERS = ("Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
                 "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Vary")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _collect(headers) -> dict:
    """Case-insensitive pull of the CORS-relevant response headers."""
    if headers is None:
        return {h: None for h in _CORS_HEADERS}
    try:
        lowered = {str(k).lower(): v for k, v in dict(headers).items()}
    except (TypeError, ValueError):
        lowered = {}
    return {h: lowered.get(h.lower()) for h in _CORS_HEADERS}


@dataclass
class CorsProbeResult:
    url: str
    origin_sent: str = EVIL_ORIGIN
    reachable: bool = False
    refused: bool = False              # non-local target; probe declined to run
    status_code: Optional[int] = None
    simple: dict = field(default_factory=dict)      # headers from the GET-with-Origin
    preflight_status: Optional[int] = None
    preflight: dict = field(default_factory=dict)   # headers from the OPTIONS preflight
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)


def run_cors_probe(target_url: str, *, timeout: int = 10,
                   origin: str = EVIL_ORIGIN, allow_nonlocal: bool = False) -> CorsProbeResult:
    """Send a hostile-Origin GET and an OPTIONS preflight to the target root."""
    url = target_url.rstrip("/") + "/"
    if not allow_nonlocal and not is_local_url(url):
        return CorsProbeResult(url=url, origin_sent=origin, refused=True,
                               error="Refused: active CORS probe is restricted to local targets.")
    result = CorsProbeResult(url=url, origin_sent=origin)
    try:
        resp = requests.get(url, headers={"Origin": origin}, timeout=timeout,
                            allow_redirects=True)
        result.reachable = True
        result.status_code = resp.status_code
        result.simple = _collect(resp.headers)
    except requests.exceptions.RequestException as exc:
        result.error = f"Could not connect to {url}: {exc}"
        return result
    try:
        pre = requests.options(url, headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,authorization",
        }, timeout=timeout, allow_redirects=True)
        result.preflight_status = pre.status_code
        result.preflight = _collect(pre.headers)
    except requests.exceptions.RequestException as exc:
        result.error = f"Preflight failed: {exc}"
    return result


def _reflects_arbitrary_origin(allow_origin: Optional[str], origin_sent: str) -> bool:
    if not allow_origin:
        return False
    return allow_origin == "*" or allow_origin.strip() == origin_sent


def classify_cors(evidence: dict) -> ProbeVerdict:
    """Decide the CORS verdict from probe evidence (pure; safe to unit-test offline)."""
    if evidence.get("refused"):
        return ProbeVerdict(NOT_APPLICABLE, "Target is not local; active CORS probe did "
                            "not run.", Severity.INFO)
    if not evidence.get("reachable"):
        return ProbeVerdict(INCONCLUSIVE, "Target was unreachable for the CORS probe; no "
                            "cross-origin behaviour could be observed.", Severity.INFO)

    origin = evidence.get("origin_sent", EVIL_ORIGIN)
    simple = evidence.get("simple") or {}
    pre = evidence.get("preflight") or {}
    allow_origin = simple.get("Access-Control-Allow-Origin") or pre.get("Access-Control-Allow-Origin")
    allow_creds = str(simple.get("Access-Control-Allow-Credentials")
                      or pre.get("Access-Control-Allow-Credentials") or "").strip().lower()
    reflects = _reflects_arbitrary_origin(allow_origin, origin)
    ev = {"observed_allow_origin": allow_origin,
          "observed_allow_credentials": allow_creds or None,
          "reflects_arbitrary_origin": reflects}

    if reflects and allow_creds == "true":
        return ProbeVerdict(
            CONFIRMED,
            f"The target returned Access-Control-Allow-Origin='{allow_origin}' for the "
            f"hostile origin {origin} together with Access-Control-Allow-Credentials: true. "
            "A cross-origin site could read authenticated responses.",
            Severity.HIGH, ev,
            remediation="Echo only trusted origins from an allow-list and never combine a "
                        "reflected/wildcard origin with credentials.")
    if reflects:
        return ProbeVerdict(
            INCONCLUSIVE,
            f"The target allowed the arbitrary origin ({allow_origin}) but did not enable "
            "credentials. Whether this is a weakness depends on the sensitivity of the "
            "responses; manual review is required.",
            Severity.MEDIUM, ev,
            remediation="Restrict Access-Control-Allow-Origin to a trusted allow-list if the "
                        "responses are not intended to be public.")
    return ProbeVerdict(
        REFUTED,
        f"The target did not grant the hostile origin {origin} "
        f"(Access-Control-Allow-Origin={allow_origin!r}); the unsafe-CORS concern is refuted.",
        Severity.INFO, ev)
