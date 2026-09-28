"""Tests for the SSRF local-canary probe (checks/ssrf.py) — the most safety-critical probe.

These tests prove the safety rails hold: the canary refuses to bind to anything but a
loopback host, only a loopback canary URL is ever handed to the target, a unique per-run
token marks genuine callbacks, and the canary is always torn down. The verdict is
evidence-driven: SSRF is CONFIRMED only when the canary actually receives the token-bearing
request; a rejected input is REFUTED; an accepted-but-no-callback case is INCONCLUSIVE.
The target side is mocked — no real World Monitor is required.
"""
import os
import sys
import unittest
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from checks import ssrf  # noqa: E402
from checks.ssrf import (  # noqa: E402
    CanaryServer, classify_ssrf, new_canary_token, run_ssrf_probe,
)
from engine import lifecycle  # noqa: E402
from model.finding import Severity  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


_RSS = [{"path": "/api/rss-proxy", "params": ["url"], "method": "GET"}]


class TestCanaryServer(unittest.TestCase):
    def test_refuses_to_bind_nonloopback(self):
        for host in ("0.0.0.0", "10.0.0.1", "example.com"):
            with self.assertRaises(ValueError):
                CanaryServer(host=host)

    def test_records_request_carrying_token(self):
        canary = CanaryServer(port=0).start()
        try:
            marker = "WT-SSRF-abc123/0-url"
            urllib.request.urlopen(f"{canary.base_url}/{marker}", timeout=2).read()
            hit = canary.received(marker)
        finally:
            canary.stop()
        self.assertIsNotNone(hit)
        self.assertEqual(hit["method"], "GET")
        self.assertIn(marker, hit["path"])

    def test_binds_only_loopback_base_url(self):
        canary = CanaryServer(port=0).start()
        try:
            self.assertTrue(canary.base_url.startswith("http://127.0.0.1:"))
        finally:
            canary.stop()

    def test_stop_tears_down_server(self):
        canary = CanaryServer(port=0).start()
        canary.stop()
        self.assertIsNone(canary._server)


class TestRunSsrfProbe(unittest.TestCase):
    def test_refuses_nonlocal_target(self):
        result = run_ssrf_probe("http://example.com", candidates=_RSS)
        self.assertTrue(result.refused)
        self.assertFalse(result.canary_bound)

    def test_confirmed_when_canary_receives_request(self):
        # Simulate a vulnerable target: it fetches the canary URL it was handed.
        def fake_get(url, params=None, timeout=None, allow_redirects=None):
            canary_url = next(iter(params.values()))
            urllib.request.urlopen(canary_url, timeout=2).read()
            return FakeResponse(200)

        with mock.patch.object(ssrf.requests, "get", side_effect=fake_get):
            result = run_ssrf_probe("http://localhost:3000", candidates=_RSS, canary_port=0)
        obs = result.observations[0]
        self.assertTrue(obs["canary_received"])
        self.assertEqual(obs["triggering_param"], "url")
        self.assertEqual(classify_ssrf(obs).result, lifecycle.CONFIRMED)

    def test_only_loopback_url_is_sent_to_target(self):
        sent = {}

        def fake_get(url, params=None, timeout=None, allow_redirects=None):
            sent["canary_url"] = next(iter(params.values()))
            return FakeResponse(400)   # reject; never contact the canary

        with mock.patch.object(ssrf.requests, "get", side_effect=fake_get):
            run_ssrf_probe("http://localhost:3000", candidates=_RSS, canary_port=0)
        # The ONLY URL ever fed to the target must be a loopback canary URL.
        self.assertRegex(sent["canary_url"], r"^http://127\.0\.0\.1:\d+/")

    def test_rejected_input_is_refuted(self):
        with mock.patch.object(ssrf.requests, "get", return_value=FakeResponse(400)):
            result = run_ssrf_probe("http://localhost:3000", candidates=_RSS, canary_port=0)
        obs = result.observations[0]
        self.assertFalse(obs["canary_received"])
        self.assertEqual(classify_ssrf(obs).result, lifecycle.REFUTED)

    def test_canary_always_torn_down(self):
        real_stop = CanaryServer.stop
        with mock.patch.object(ssrf.requests, "get", return_value=FakeResponse(404)), \
             mock.patch.object(CanaryServer, "stop", autospec=True,
                               side_effect=real_stop) as m_stop:
            run_ssrf_probe("http://localhost:3000", candidates=_RSS, canary_port=0)
        self.assertTrue(m_stop.called)

    def test_unique_token_per_run(self):
        self.assertTrue(new_canary_token().startswith("WT-SSRF-"))
        self.assertNotEqual(new_canary_token(), new_canary_token())

    def test_connection_error_does_not_confirm(self):
        with mock.patch.object(ssrf.requests, "get",
                               side_effect=requests.exceptions.ConnectionError("no")):
            result = run_ssrf_probe("http://localhost:3000", candidates=_RSS, canary_port=0)
        obs = result.observations[0]
        self.assertFalse(obs["canary_received"])
        # No response codes obtained -> inconclusive, never confirmed.
        self.assertEqual(classify_ssrf(obs).result, lifecycle.INCONCLUSIVE)


class TestClassifySsrf(unittest.TestCase):
    def test_canary_received_confirmed_high(self):
        v = classify_ssrf({"canary_received": True, "triggering_param": "url",
                           "response_status_by_param": {"url": 200}})
        self.assertEqual(v.result, lifecycle.CONFIRMED)
        self.assertEqual(v.severity, Severity.HIGH)

    def test_all_4xx_refuted(self):
        v = classify_ssrf({"canary_received": False,
                           "response_status_by_param": {"url": 400, "feed": 403}})
        self.assertEqual(v.result, lifecycle.REFUTED)

    def test_accepted_but_no_callback_inconclusive_low(self):
        v = classify_ssrf({"canary_received": False,
                           "response_status_by_param": {"url": 200}})
        self.assertEqual(v.result, lifecycle.INCONCLUSIVE)
        self.assertEqual(v.severity, Severity.LOW)

    def test_no_codes_inconclusive(self):
        v = classify_ssrf({"canary_received": False, "response_status_by_param": {}})
        self.assertEqual(v.result, lifecycle.INCONCLUSIVE)

    def test_nonlocal_refused_not_applicable(self):
        self.assertEqual(classify_ssrf({"refused": True}).result, lifecycle.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
