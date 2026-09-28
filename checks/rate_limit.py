"""Rate-limit ENFORCEMENT probe — is a bounded burst throttled by the LOCAL target?

This is an *enforcement* probe, never a stress test. It sends a small, bounded number
of ordinary GET requests (default 10) to one representative local endpoint, with a
conservative pause between them, and inspects the responses for evidence that a rate
limiter exists: an HTTP 429, a ``Retry-After`` header, or ``X-RateLimit-*`` headers.

Design constraint (honesty + safety): a bounded, non-abusive probe can *demonstrate the
presence* of rate limiting (-> the missing-rate-limit concern is REFUTED) but it can
never *prove its absence* — that would require flooding, which is forbidden. So the only
verdicts this probe can reach are REFUTED (enforcement seen), INCONCLUSIVE (no signal in
a bounded sample, or unreachable), or NOT_APPLICABLE (non-local). It will NEVER claim a
"rate-limiting vulnerability confirmed" from a handful of requests.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from checks.active_base import ProbeVerdict, is_local_url
from engine.lifecycle import INCONCLUSIVE, NOT_APPLICABLE, REFUTED
from model.finding import Severity

REFERENCES = ["https://owasp.org/www-community/controls/Rate_limiting",
              "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429"]

DEFAULT_COUNT = 10
DEFAULT_INTERVAL = 0.2          # seconds between requests — deliberately gentle
_RL_HEADERS = ("Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining",
               "X-RateLimit-Reset", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rl_headers(headers) -> dict:
    if headers is None:
        return {}
    try:
        lowered = {str(k).lower(): v for k, v in dict(headers).items()}
    except (TypeError, ValueError):
        return {}
    return {h: lowered[h.lower()] for h in _RL_HEADERS if h.lower() in lowered}


@dataclass
class RateLimitProbeResult:
    url: str
    request_count: int = 0
    refused: bool = False               # non-local target; probe declined to run
    reachable: bool = False
    statuses: list = field(default_factory=list)      # status code per request, in order
    rate_limit_headers: dict = field(default_factory=dict)  # any RL headers seen (last wins)
    retry_after: Optional[str] = None
    saw_429: bool = False
    timings_ms: list = field(default_factory=list)
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now)

    @property
    def timing_summary(self) -> dict:
        if not self.timings_ms:
            return {"min_ms": None, "max_ms": None, "avg_ms": None}
        return {"min_ms": min(self.timings_ms), "max_ms": max(self.timings_ms),
                "avg_ms": round(sum(self.timings_ms) / len(self.timings_ms), 1)}


def run_rate_limit_probe(target_url: str, *, count: int = DEFAULT_COUNT,
                         interval: float = DEFAULT_INTERVAL, timeout: int = 10,
                         allow_nonlocal: bool = False) -> RateLimitProbeResult:
    """Send a bounded, evenly-paced burst and record throttling signals.

    ``count`` is clamped to a hard ceiling so the probe can never be turned into a
    stress test by configuration. ``interval`` inserts a conservative pause between
    requests (set to 0 only in tests).
    """
    url = target_url.rstrip("/") + "/"
    count = max(1, min(int(count), 25))    # hard non-abusive ceiling
    if not allow_nonlocal and not is_local_url(url):
        return RateLimitProbeResult(url=url, refused=True,
                                    error="Refused: active rate-limit probe is restricted to local targets.")
    result = RateLimitProbeResult(url=url)
    for i in range(count):
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
        except requests.exceptions.RequestException as exc:
            result.error = f"Request {i + 1} failed: {exc}"
            break
        result.reachable = True
        result.request_count += 1
        result.statuses.append(resp.status_code)
        result.timings_ms.append(int(resp.elapsed.total_seconds() * 1000))
        seen = _rl_headers(resp.headers)
        if seen:
            result.rate_limit_headers.update(seen)
        if resp.status_code == 429:
            result.saw_429 = True
        ra = seen.get("Retry-After")
        if ra is not None:
            result.retry_after = ra
        if i < count - 1 and interval > 0:
            time.sleep(interval)
    return result


def classify_rate_limit(evidence: dict) -> ProbeVerdict:
    """Decide the rate-limit verdict from probe evidence (pure; offline-testable)."""
    if evidence.get("refused"):
        return ProbeVerdict(NOT_APPLICABLE, "Target is not local; active rate-limit probe "
                            "did not run.", Severity.INFO)
    if not evidence.get("reachable"):
        return ProbeVerdict(INCONCLUSIVE, "Target was unreachable for the rate-limit probe; "
                            "enforcement could not be observed.", Severity.INFO)

    statuses = evidence.get("statuses") or []
    rl_headers = evidence.get("rate_limit_headers") or {}
    retry_after = evidence.get("retry_after")
    count = evidence.get("request_count", len(statuses))
    ev = {"request_count": count, "statuses": statuses,
          "rate_limit_headers": rl_headers, "retry_after": retry_after,
          "timing": evidence.get("timing_summary")}

    if evidence.get("saw_429") or 429 in statuses:
        return ProbeVerdict(
            REFUTED,
            f"The target returned HTTP 429 within {count} bounded requests; rate-limit "
            "enforcement is demonstrably present, so the missing-rate-limit concern is refuted.",
            Severity.INFO, ev)
    if rl_headers or retry_after:
        return ProbeVerdict(
            REFUTED,
            f"The target advertised rate-limit headers ({', '.join(sorted(rl_headers)) or 'Retry-After'}) "
            f"over {count} requests; an enforcement mechanism is present, so the concern is refuted.",
            Severity.INFO, ev)
    return ProbeVerdict(
        INCONCLUSIVE,
        f"No throttling signal (no 429, no rate-limit headers) appeared in {count} bounded, "
        "non-abusive requests. This is NOT proof that rate limiting is absent — demonstrating "
        "absence would require prohibited stress testing. Manual review required.",
        Severity.LOW, ev,
        remediation="If this endpoint is sensitive, confirm a rate limiter (e.g. Upstash/Redis "
                    "token bucket) is applied; verify with a controlled load test in a safe environment.")
