"""Security-headers / CSP probe — a real HTTP GET against the running target.

This is an *active probe*: it observes what the live target actually returns, so
its findings carry status "verified". It never fabricates a result — if the
target cannot be reached, that is reported as an unreachable probe (and the
normalizer emits no vulnerability findings for it).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

# Header -> whether its ABSENCE is treated as a (low) weakness by default.
# Values are the missing-severity to use; presence is always informational.
SECURITY_HEADERS = {
    "Content-Security-Policy": "low",
    "Strict-Transport-Security": "low",
    "X-Content-Type-Options": "low",
    "X-Frame-Options": "low",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}

REFERENCES = ["https://owasp.org/www-project-secure-headers/"]


@dataclass
class HeadersProbeResult:
    """Raw, pre-normalization outcome of the headers probe."""

    url: str
    reachable: bool
    scheme: str = ""
    host: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[int] = None
    # Mapping of canonical header name -> observed value (or None if absent).
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def status(self) -> str:
        return "ran" if self.reachable else "failed"


def _extract(headers, name: str) -> Optional[str]:
    """Case-insensitive header lookup that tolerates plain dicts (for tests)."""
    if headers is None:
        return None
    # requests uses a CaseInsensitiveDict; a direct get works there.
    try:
        value = headers.get(name)
        if value is not None:
            return value
    except AttributeError:
        pass
    lowered = {str(k).lower(): v for k, v in dict(headers).items()}
    return lowered.get(name.lower())


def run_headers_probe(target_url: str, timeout: int) -> HeadersProbeResult:
    """GET the target root and record the security-relevant response headers."""
    url = target_url.rstrip("/") + "/"
    parsed = urlparse(url)
    scheme, host = parsed.scheme, parsed.hostname or ""

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.exceptions.RequestException as exc:
        return HeadersProbeResult(
            url=url,
            reachable=False,
            scheme=scheme,
            host=host,
            error=f"Could not connect to target {url}: {exc}",
        )

    observed = {name: _extract(response.headers, name) for name in SECURITY_HEADERS}
    return HeadersProbeResult(
        url=url,
        reachable=True,
        scheme=scheme,
        host=host,
        status_code=response.status_code,
        response_time_ms=int(response.elapsed.total_seconds() * 1000),
        headers=observed,
    )


def is_loopback(host: str) -> bool:
    return host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
