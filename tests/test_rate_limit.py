"""Tests for the rate-limit ENFORCEMENT probe (checks/rate_limit.py).

The probe is bounded and non-abusive by construction: this suite proves the request
count is clamped to a hard ceiling, that enforcement signals (HTTP 429 / Retry-After /
X-RateLimit-* headers) are read as REFUTED (a limiter is present), and that the absence
of a signal is only ever INCONCLUSIVE — the probe must NEVER claim a rate-limit
"vulnerability confirmed" from a small sample. HTTP is mocked throughout.
"""
import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from checks import rate_limit  # noqa: E402
from checks.rate_limit import classify_rate_limit, run_rate_limit_probe  # noqa: E402
from engine import lifecycle  # noqa: E402
from model.finding import Severity  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, headers=None, ms=5):
        self.status_code = status_code
        self.headers = headers or {}
        self.elapsed = datetime.timedelta(milliseconds=ms)


def _evidence(*, refused=False, reachable=True, statuses=None, saw_429=False,
              rate_limit_headers=None, retry_after=None, request_count=None):
    statuses = statuses if statuses is not None else [200, 200]
    return {"refused": refused, "reachable": reachable, "statuses": statuses,
            "saw_429": saw_429, "rate_limit_headers": rate_limit_headers or {},
            "retry_after": retry_after,
            "request_count": request_count if request_count is not None else len(statuses)}


class TestRateLimitProbe(unittest.TestCase):
    def test_refuses_nonlocal_target(self):
        result = run_rate_limit_probe("http://example.com", count=5, interval=0)
        self.assertTrue(result.refused)
        self.assertEqual(result.request_count, 0)

    def test_bounded_count_is_respected(self):
        with mock.patch.object(rate_limit.requests, "get",
                               return_value=FakeResponse(200)) as m_get:
            result = run_rate_limit_probe("http://localhost:3000", count=5, interval=0)
        self.assertEqual(m_get.call_count, 5)
        self.assertEqual(result.request_count, 5)

    def test_count_clamped_to_hard_ceiling(self):
        # Even a hostile-looking count can never turn this into a stress test.
        with mock.patch.object(rate_limit.requests, "get",
                               return_value=FakeResponse(200)) as m_get:
            run_rate_limit_probe("http://localhost:3000", count=1000, interval=0)
        self.assertLessEqual(m_get.call_count, 25)

    def test_429_recorded(self):
        with mock.patch.object(rate_limit.requests, "get",
                               return_value=FakeResponse(429, {"Retry-After": "30"})):
            result = run_rate_limit_probe("http://localhost:3000", count=3, interval=0)
        self.assertTrue(result.saw_429)
        self.assertEqual(result.retry_after, "30")

    def test_connection_error_breaks_loop(self):
        with mock.patch.object(rate_limit.requests, "get",
                               side_effect=requests.exceptions.ConnectionError("no")):
            result = run_rate_limit_probe("http://localhost:3000", count=5, interval=0)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)


class TestClassifyRateLimit(unittest.TestCase):
    def test_429_is_refuted(self):
        v = classify_rate_limit(_evidence(statuses=[200, 429], saw_429=True))
        self.assertEqual(v.result, lifecycle.REFUTED)

    def test_rate_limit_headers_refuted(self):
        v = classify_rate_limit(_evidence(
            rate_limit_headers={"X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "0"}))
        self.assertEqual(v.result, lifecycle.REFUTED)

    def test_retry_after_refuted(self):
        self.assertEqual(classify_rate_limit(_evidence(retry_after="10")).result,
                         lifecycle.REFUTED)

    def test_no_signal_is_inconclusive_never_confirmed(self):
        v = classify_rate_limit(_evidence(statuses=[200] * 10))
        self.assertEqual(v.result, lifecycle.INCONCLUSIVE)
        self.assertEqual(v.severity, Severity.LOW)
        self.assertIn("NOT proof", v.rationale)

    def test_unreachable_inconclusive(self):
        self.assertEqual(classify_rate_limit(_evidence(reachable=False)).result,
                         lifecycle.INCONCLUSIVE)

    def test_nonlocal_refused_not_applicable(self):
        self.assertEqual(classify_rate_limit(_evidence(refused=True)).result,
                         lifecycle.NOT_APPLICABLE)

    def test_never_returns_confirmed(self):
        # Whatever the (bounded) evidence, this probe must never CONFIRM a rate-limit gap.
        for ev in (_evidence(statuses=[200] * 25), _evidence(statuses=[200, 429], saw_429=True),
                   _evidence(reachable=False), _evidence(refused=True),
                   _evidence(retry_after="5")):
            self.assertNotEqual(classify_rate_limit(ev).result, lifecycle.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
