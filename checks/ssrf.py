"""SSRF local-canary probe — does the target make a server-side request we control?

This is the most sensitive probe, so its safety rails are the strictest in WATCHTOWER:

  * The canary HTTP server binds ONLY to a loopback address (127.0.0.1 by default) and
    is torn down in a ``finally`` block after the probe — it is never externally reachable.
  * The ONLY URL ever fed to the target is the loopback canary URL. The probe never asks
    the target to fetch cloud-metadata endpoints, public IPs, or any third-party host.
  * A unique per-run token (``WT-SSRF-<random>``) is embedded in the canary path, so a
    received request is unambiguously attributable to this probe.

The verdict is evidence-driven: SSRF is CONFIRMED only when the target actually causes the
loopback canary to receive a request carrying our token. A URL merely echoed in a client
response proves nothing and is never treated as SSRF.
"""
from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

import requests

from checks.active_base import LOOPBACK_HOSTS, ProbeVerdict, is_local_url
from engine.lifecycle import CONFIRMED, INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Severity

REFERENCES = ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
              "https://portswigger.net/web-security/ssrf"]

DEFAULT_CANARY_HOST = "127.0.0.1"
DEFAULT_CANARY_PORT = 9001
# Response headers worth recording from the canary callback (never secrets — these are the
# headers the *target* attached to its own outbound fetch).
_RECORD_HEADERS = ("user-agent", "accept", "host", "x-forwarded-for", "via")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_canary_token() -> str:
    """A unique, unguessable per-run marker embedded in the canary URL path."""
    return f"WT-SSRF-{secrets.token_hex(8)}"


class _CanaryHandler(BaseHTTPRequestHandler):
    """Records every request it receives on the owning server, then replies 200."""

    def _record(self):
        headers = {k.lower(): v for k, v in self.headers.items()
                   if k.lower() in _RECORD_HEADERS}
        hit = {"method": self.command, "path": self.path, "headers": headers,
               "client": self.client_address[0], "timestamp": _now()}
        with self.server.lock:                       # type: ignore[attr-defined]
            self.server.hits.append(hit)             # type: ignore[attr-defined]
        body = b"WT-CANARY-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Any verb the target might use to fetch the canary is recorded identically.
    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _record

    def log_message(self, *args):        # silence the default stderr access log
        return


class CanaryServer:
    """A loopback-only HTTP listener that records requests the target is coaxed into making.

    Refuses to bind to anything but a loopback host, so it can never be exposed externally.
    Use as a context manager; it always shuts down on exit.
    """

    def __init__(self, host: str = DEFAULT_CANARY_HOST, port: int = DEFAULT_CANARY_PORT):
        if host not in LOOPBACK_HOSTS:
            raise ValueError(f"Canary refuses to bind to non-loopback host {host!r}; "
                             f"allowed: {sorted(LOOPBACK_HOSTS)}")
        self.host = host
        self.requested_port = port
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.hits: list = []

    @property
    def port(self) -> int:
        return self._server.server_address[1] if self._server else self.requested_port

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    def start(self) -> "CanaryServer":
        server = ThreadingHTTPServer((self.host, self.requested_port), _CanaryHandler)
        server.hits = self.hits                      # type: ignore[attr-defined]
        server.lock = threading.Lock()               # type: ignore[attr-defined]
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def received(self, marker: str) -> Optional[dict]:
        """Return the first recorded hit whose path contains ``marker`` (token/index)."""
        with self._server.lock:                      # type: ignore[attr-defined]
            for hit in self.hits:
                if marker in hit.get("path", ""):
                    return hit
        return None

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False


def default_candidates() -> list:
    """Local WM endpoints that accept URL-like input and may fetch it server-side.

    These are *surfaces to test*, not asserted vulnerabilities — the RSS/MCP proxies are
    the plausible server-side-fetch paths. The verdict comes solely from the canary.
    """
    return [
        {"path": "/api/rss-proxy", "params": ["url", "feed", "u"], "method": "GET"},
        {"path": "/api/mcp-proxy", "params": ["url", "target"], "method": "GET"},
    ]


@dataclass
class SsrfObservation:
    endpoint: str
    method: str
    params_tested: list = field(default_factory=list)
    canary_base: str = ""
    canary_token: str = ""
    canary_received: bool = False
    triggering_param: Optional[str] = None
    canary_request_method: Optional[str] = None
    canary_headers: Optional[dict] = None
    response_status_by_param: dict = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)


@dataclass
class SsrfProbeResult:
    target: str
    canary_token: str = ""
    canary_base: str = ""
    refused: bool = False
    canary_bound: bool = False
    observations: list = field(default_factory=list)    # list[SsrfObservation-as-dict]
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)


def _await_hit(canary, marker, *, attempts=15, delay=0.1):
    """Poll briefly for a canary hit — the target's fetch may lag the HTTP response."""
    for _ in range(attempts):
        hit = canary.received(marker)
        if hit:
            return hit
        time.sleep(delay)
    return canary.received(marker)


def run_ssrf_probe(target_url: str, *, candidates=None, canary_host: str = DEFAULT_CANARY_HOST,
                   canary_port: int = DEFAULT_CANARY_PORT, timeout: int = 10,
                   allow_nonlocal: bool = False) -> SsrfProbeResult:
    """Coax the target into fetching a loopback canary URL and observe the callback."""
    base = target_url.rstrip("/")
    if not allow_nonlocal and not is_local_url(base + "/"):
        return SsrfProbeResult(target=base, refused=True,
                               error="Refused: active SSRF probe is restricted to local targets.")
    candidates = candidates if candidates is not None else default_candidates()
    token = new_canary_token()
    result = SsrfProbeResult(target=base, canary_token=token)
    try:
        canary = CanaryServer(host=canary_host, port=canary_port).start()
    except (ValueError, OSError) as exc:
        result.error = f"Could not start loopback canary: {exc}"
        return result
    result.canary_bound = True
    result.canary_base = canary.base_url
    try:
        for idx, cand in enumerate(candidates):
            url = base + cand["path"]
            method = cand.get("method", "GET").upper()
            params = cand.get("params", ["url"])
            obs = SsrfObservation(endpoint=url, method=method, params_tested=list(params),
                                  canary_base=canary.base_url, canary_token=token)
            for param in params:
                marker = f"{token}/{idx}-{param}"
                canary_url = f"{canary.base_url}/{marker}"
                try:
                    if method == "POST":
                        resp = requests.post(url, json={param: canary_url}, timeout=timeout,
                                             allow_redirects=False)
                    else:
                        resp = requests.get(url, params={param: canary_url}, timeout=timeout,
                                            allow_redirects=False)
                    obs.response_status_by_param[param] = resp.status_code
                except requests.exceptions.RequestException as exc:
                    obs.response_status_by_param[param] = None
                    obs.error = f"{param}: {exc}"
                    continue
                hit = _await_hit(canary, marker)
                if hit:
                    obs.canary_received = True
                    obs.triggering_param = param
                    obs.canary_request_method = hit.get("method")
                    obs.canary_headers = hit.get("headers")
                    break        # SSRF demonstrated for this endpoint; stop probing params
            result.observations.append(vars(obs))
    finally:
        canary.stop()            # the canary is ALWAYS torn down
    return result


def classify_ssrf(evidence: dict) -> ProbeVerdict:
    """Classify a single SSRF observation's evidence (pure; offline-testable)."""
    if evidence.get("refused"):
        return ProbeVerdict(NOT_APPLICABLE, "Target is not local; active SSRF probe did not "
                            "run.", Severity.INFO)
    endpoint = evidence.get("endpoint", "the endpoint")
    statuses = evidence.get("response_status_by_param") or {}
    ev = {"endpoint": endpoint, "canary_token": evidence.get("canary_token"),
          "canary_base": evidence.get("canary_base"),
          "canary_received": bool(evidence.get("canary_received")),
          "triggering_param": evidence.get("triggering_param"),
          "canary_request_method": evidence.get("canary_request_method"),
          "canary_headers": evidence.get("canary_headers"),
          "response_status_by_param": statuses}

    if evidence.get("canary_received"):
        return ProbeVerdict(
            CONFIRMED,
            f"{endpoint} caused the loopback canary to receive a request carrying our token "
            f"via the '{evidence.get('triggering_param')}' parameter — a server-side request was "
            "made to an attacker-controlled URL. SSRF is demonstrated.",
            Severity.HIGH, ev,
            remediation="Validate and allow-list outbound fetch destinations; block loopback, "
                        "link-local and metadata ranges, and re-check the target after every redirect.")

    codes = [c for c in statuses.values() if c is not None]
    if not codes:
        return ProbeVerdict(
            INCONCLUSIVE,
            f"No response was obtained from {endpoint} (endpoint absent or unreachable); SSRF "
            "could not be tested here.", Severity.INFO, ev)
    if all(400 <= c < 500 for c in codes):
        return ProbeVerdict(
            REFUTED,
            f"{endpoint} rejected the URL input (HTTP {sorted(set(codes))}) and the canary was "
            "never contacted; no server-side request to our URL occurred, so SSRF is refuted here.",
            Severity.INFO, ev)
    return ProbeVerdict(
        INCONCLUSIVE,
        f"{endpoint} accepted the input (HTTP {sorted(set(codes))}) but the canary was not "
        "contacted. No server-side fetch of our URL was observed; a client-side echo would not "
        "prove SSRF, and a single controlled attempt cannot rule it out. Manual review required.",
        Severity.LOW, ev,
        remediation="Manually review whether this endpoint performs a server-side fetch and "
                    "whether outbound destinations are validated.")
