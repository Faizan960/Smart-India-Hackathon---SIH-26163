"""Auth / MCP access-control probe — is protected functionality reachable without creds?

Targets the LOCAL World Monitor MCP surface and candidate protected APIs. For each
candidate it issues *unauthenticated*, *invalid-bearer*, and *malformed-auth* requests
and records how the target responds. It NEVER guesses or brute-forces credentials, never
reuses a real user's token, and never stores response bodies — only status codes and a
few non-sensitive response headers / metadata.

Verdicts:
  * 401 / 403 on the unauthenticated request  -> REFUTED (auth correctly enforced)
  * 404 on the unauthenticated request         -> INCONCLUSIVE (the route may be unmounted under
    the runtime under test — e.g. a dev server — not necessarily absent from production)
  * 2xx on an endpoint we expect to be protected (or an MCP tool listing returned without
    creds)                                     -> CONFIRMED (protected operation exposed)
  * 2xx on a known-public endpoint             -> NOT_APPLICABLE (public by design)
  * 2xx on an unknown endpoint, or 4xx/5xx we can't interpret -> INCONCLUSIVE
A bare HTTP 200 is never, on its own, treated as a vulnerability.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from checks.active_base import ProbeVerdict, is_local_url
from engine.lifecycle import CONFIRMED, INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Severity

REFERENCES = ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
              "https://modelcontextprotocol.io/specification"]

# A syntactically valid but entirely bogus token; never a real credential.
_INVALID_BEARER = "Bearer wt-invalid-000000000000000000000000"
_MALFORMED_AUTH = "Basic not-base64!!"
_MCP_BODY = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
# Non-sensitive response headers worth recording (never Set-Cookie / Authorization echoes).
_SAFE_HEADERS = ("www-authenticate", "content-type", "allow")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_candidates() -> list:
    """Local WM auth/MCP surfaces to probe. Relative paths; joined to the target base.

    ``expected`` is a conservative prior: 'protected' surfaces should refuse anonymous
    access, 'public' are intended to be open, 'unknown' means we make no assumption and
    a success is reported as inconclusive rather than a vulnerability.
    """
    return [
        {"path": "/api/mcp", "kind": "mcp", "expected": "protected"},
        {"path": "/api/mcp-proxy", "kind": "mcp", "expected": "protected"},
    ]


def _safe_headers(headers) -> dict:
    if headers is None:
        return {}
    try:
        lowered = {str(k).lower(): v for k, v in dict(headers).items()}
    except (TypeError, ValueError):
        return {}
    return {h: lowered[h] for h in _SAFE_HEADERS if h in lowered}


def _looks_like_tool_listing(resp) -> Optional[bool]:
    """True if an MCP response *metadata* indicates a tool listing — no contents stored."""
    ctype = (resp.headers.get("content-type") or "").lower() if resp.headers else ""
    if "json" not in ctype and "event-stream" not in ctype:
        return False
    try:
        data = resp.json()
    except (ValueError, requests.exceptions.RequestException):
        return None
    if isinstance(data, dict):
        result = data.get("result")
        if isinstance(result, dict) and "tools" in result:
            return True
        if "tools" in data:
            return True
        if "error" in data:            # a JSON-RPC error envelope is not an exposed tool list
            return False
    return False


@dataclass
class AuthObservation:
    endpoint: str
    kind: str                          # "http" | "mcp"
    expected: str                      # "protected" | "public" | "unknown"
    method: str = "GET"
    status_by_state: dict = field(default_factory=dict)   # auth_state -> status code (or None)
    headers: dict = field(default_factory=dict)           # safe headers from the no-auth request
    mcp_exposed_tools: Optional[bool] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)


@dataclass
class AuthProbeResult:
    target: str
    refused: bool = False
    reachable: bool = False
    observations: list = field(default_factory=list)   # list[AuthObservation-as-dict]
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)


def _one_request(url, kind, auth_state, timeout):
    """Issue a single request in a given auth state. Returns (status, resp) or (None, None)."""
    headers = {}
    if auth_state == "invalid_bearer":
        headers["Authorization"] = _INVALID_BEARER
    elif auth_state == "malformed":
        headers["Authorization"] = _MALFORMED_AUTH
    if kind == "mcp":
        headers["Accept"] = "application/json, text/event-stream"
        resp = requests.post(url, json=_MCP_BODY, headers=headers, timeout=timeout,
                             allow_redirects=False)
    else:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
    return resp.status_code, resp


def run_auth_probe(target_url: str, *, candidates=None, timeout: int = 10,
                   allow_nonlocal: bool = False) -> AuthProbeResult:
    """Probe each candidate in three auth states; record status codes + safe metadata."""
    base = target_url.rstrip("/")
    if not allow_nonlocal and not is_local_url(base + "/"):
        return AuthProbeResult(target=base, refused=True,
                               error="Refused: active auth/MCP probe is restricted to local targets.")
    candidates = candidates if candidates is not None else default_candidates()
    result = AuthProbeResult(target=base)
    for cand in candidates:
        url = base + cand["path"]
        kind = cand.get("kind", "http")
        method = "POST" if kind == "mcp" else "GET"
        obs = AuthObservation(endpoint=url, kind=kind,
                              expected=cand.get("expected", "unknown"), method=method)
        for state in ("none", "invalid_bearer", "malformed"):
            try:
                status, resp = _one_request(url, kind, state, timeout)
            except requests.exceptions.RequestException as exc:
                obs.status_by_state[state] = None
                obs.error = f"{state}: {exc}"
                continue
            result.reachable = True
            obs.status_by_state[state] = status
            if state == "none":
                obs.headers = _safe_headers(resp.headers)
                if kind == "mcp" and 200 <= status < 300:
                    obs.mcp_exposed_tools = _looks_like_tool_listing(resp)
        result.observations.append(vars(obs))
    return result


def classify_auth(evidence: dict) -> ProbeVerdict:
    """Classify a single endpoint observation's evidence (pure; offline-testable)."""
    if evidence.get("refused"):
        return ProbeVerdict(NOT_APPLICABLE, "Target is not local; active auth/MCP probe did "
                            "not run.", Severity.INFO)
    status_by_state = evidence.get("status_by_state") or {}
    status = status_by_state.get("none")
    endpoint = evidence.get("endpoint", "the endpoint")
    expected = evidence.get("expected", "unknown")
    ev = {"endpoint": endpoint, "status_by_state": status_by_state,
          "expected": expected, "mcp_exposed_tools": evidence.get("mcp_exposed_tools"),
          "safe_headers": evidence.get("headers")}

    if status is None:
        return ProbeVerdict(INCONCLUSIVE, f"Could not obtain an unauthenticated response from "
                            f"{endpoint}; access control could not be observed.", Severity.INFO, ev)
    if status in (401, 403):
        return ProbeVerdict(REFUTED, f"{endpoint} refused the unauthenticated request "
                            f"(HTTP {status}); authentication is enforced, so the unauth-access "
                            "concern is refuted.", Severity.INFO, ev)
    if status == 404:
        return ProbeVerdict(
            INCONCLUSIVE,
            f"{endpoint} returned HTTP 404. A 404 does NOT establish that the MCP surface is "
            "absent from the target's actual configured runtime — the route may simply be "
            "unmounted under the development runtime exercised here, while the "
            "production/serverless API surface was not exercised. MCP exposure can be neither "
            "confirmed nor ruled out; manual review required.",
            Severity.INFO, ev,
            remediation="Re-run the auth/MCP probe against the production/serverless runtime "
                        "(where the /api functions are actually mounted) to determine whether the "
                        "MCP surface enforces authentication.")
    if 200 <= status < 300:
        if evidence.get("mcp_exposed_tools") is True:
            return ProbeVerdict(
                CONFIRMED,
                f"{endpoint} returned an MCP tool listing to an unauthenticated request "
                f"(HTTP {status}); protected MCP functionality is exposed without credentials.",
                Severity.HIGH, ev,
                remediation="Require a valid credential (Clerk session or wm_ API key) before "
                            "serving MCP tool discovery/invocation; reject anonymous requests with 401.")
        if expected == "protected":
            return ProbeVerdict(
                CONFIRMED,
                f"{endpoint} served an unauthenticated request with HTTP {status} despite being "
                "expected to require authentication; a protected operation is reachable without creds.",
                Severity.HIGH, ev,
                remediation="Enforce authentication on this endpoint and return 401/403 to "
                            "anonymous requests.")
        if expected == "public":
            return ProbeVerdict(NOT_APPLICABLE, f"{endpoint} is public by design and returned "
                                f"HTTP {status}; open access is expected, not a weakness.",
                                Severity.INFO, ev)
        return ProbeVerdict(
            INCONCLUSIVE,
            f"{endpoint} returned HTTP {status} without credentials, but whether this data is "
            "meant to be protected is unknown; HTTP 200 alone does not prove a weakness. Manual "
            "review required.", Severity.MEDIUM, ev,
            remediation="Confirm whether this endpoint exposes protected data; if so, enforce auth.")
    return ProbeVerdict(
        INCONCLUSIVE,
        f"{endpoint} returned HTTP {status} to the unauthenticated request; the access-control "
        "behaviour is ambiguous and needs manual review.", Severity.INFO, ev)
