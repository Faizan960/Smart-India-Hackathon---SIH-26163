"""Tests for the security-headers probe and its normalization.

HTTP is mocked, so these tests never require a running target.
"""
import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from checks import security_headers  # noqa: E402
from checks.security_headers import run_headers_probe  # noqa: E402
from engine.normalizer import normalize_headers  # noqa: E402
from model.finding import Severity, Status  # noqa: E402


class FakeResponse:
    def __init__(self, headers, status_code=200, ms=12):
        self.headers = headers
        self.status_code = status_code
        self.elapsed = datetime.timedelta(milliseconds=ms)


ALL_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "Strict-Transport-Security": "max-age=63072000",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
}


class TestHeadersProbe(unittest.TestCase):
    def _findings_for(self, headers):
        with mock.patch.object(security_headers.requests, "get",
                               return_value=FakeResponse(headers)):
            result = run_headers_probe("http://localhost:3000", timeout=5)
        self.assertTrue(result.reachable)
        return {f.evidence["header"]: f for f in normalize_headers(result)}

    def test_present_header_is_informational(self):
        findings = self._findings_for(dict(ALL_HEADERS))
        csp = findings["Content-Security-Policy"]
        self.assertEqual(csp.severity, Severity.INFO)
        self.assertEqual(csp.status, Status.VERIFIED)
        self.assertEqual(csp.verification["result"], "refuted")

    def test_missing_header_is_low_and_confirmed(self):
        headers = dict(ALL_HEADERS)
        del headers["X-Frame-Options"]
        xfo = self._findings_for(headers)["X-Frame-Options"]
        self.assertEqual(xfo.severity, Severity.LOW)
        self.assertEqual(xfo.verification["result"], "confirmed")

    def test_missing_hsts_on_http_localhost_is_not_a_weakness(self):
        headers = dict(ALL_HEADERS)
        del headers["Strict-Transport-Security"]
        hsts = self._findings_for(headers)["Strict-Transport-Security"]
        self.assertEqual(hsts.severity, Severity.INFO)
        self.assertEqual(hsts.verification["result"], "not_applicable")

    def test_case_insensitive_header_match(self):
        # Server returns lowercased header names; probe must still detect them.
        lowered = {k.lower(): v for k, v in ALL_HEADERS.items()}
        csp = self._findings_for(lowered)["Content-Security-Policy"]
        self.assertEqual(csp.severity, Severity.INFO)

    def test_unreachable_target_yields_no_findings(self):
        with mock.patch.object(security_headers.requests, "get",
                               side_effect=requests.exceptions.ConnectionError("refused")):
            result = run_headers_probe("http://localhost:3000", timeout=5)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)
        self.assertEqual(normalize_headers(result), [])


if __name__ == "__main__":
    unittest.main()
