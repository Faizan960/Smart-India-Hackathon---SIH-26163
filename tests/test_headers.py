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
from checks.verifiers import SecurityHeaderVerifier  # noqa: E402
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
        """Normalize the probe result, then run the security-header verifier.

        Verdict (verified + refuted/confirmed/not_applicable) is assigned by the verifier,
        not by normalization — normalization only records the raw observation (suspected).
        """
        with mock.patch.object(security_headers.requests, "get",
                               return_value=FakeResponse(headers)):
            result = run_headers_probe("http://localhost:3000", timeout=5)
        self.assertTrue(result.reachable)
        findings = normalize_headers(result)
        # Before verification, every observation is suspected — nothing auto-verified.
        for f in findings:
            self.assertEqual(f.status, Status.SUSPECTED)
        verifier = SecurityHeaderVerifier()
        for f in findings:
            verifier.verify(f)
        return {f.evidence["header"]: f for f in findings}

    def test_present_header_is_informational(self):
        # PART 0: a present header refutes the missing-header concern -> false_positive.
        findings = self._findings_for(dict(ALL_HEADERS))
        csp = findings["Content-Security-Policy"]
        self.assertEqual(csp.severity, Severity.INFO)
        self.assertEqual(csp.status, Status.FALSE_POSITIVE)
        self.assertEqual(csp.verification["result"], "refuted")
        self.assertEqual(csp.evidence["verification_status"], "refuted")

    def test_missing_header_is_low_and_confirmed(self):
        headers = dict(ALL_HEADERS)
        del headers["X-Frame-Options"]
        xfo = self._findings_for(headers)["X-Frame-Options"]
        self.assertEqual(xfo.severity, Severity.LOW)
        self.assertEqual(xfo.status, Status.VERIFIED)
        self.assertEqual(xfo.verification["result"], "confirmed")
        self.assertIn("X-Frame-Options", xfo.evidence["remediation"])

    def test_missing_hsts_on_http_localhost_is_not_a_weakness(self):
        # PART 0: HSTS is not_applicable on plain-HTTP loopback -> false_positive, not verified.
        headers = dict(ALL_HEADERS)
        del headers["Strict-Transport-Security"]
        hsts = self._findings_for(headers)["Strict-Transport-Security"]
        self.assertEqual(hsts.severity, Severity.INFO)
        self.assertEqual(hsts.status, Status.FALSE_POSITIVE)
        self.assertEqual(hsts.verification["result"], "not_applicable")

    def test_case_insensitive_header_match(self):
        # Server returns lowercased header names; probe must still detect them.
        lowered = {k.lower(): v for k, v in ALL_HEADERS.items()}
        csp = self._findings_for(lowered)["Content-Security-Policy"]
        self.assertEqual(csp.severity, Severity.INFO)

    def test_expected_property_and_url_recorded(self):
        csp = self._findings_for(dict(ALL_HEADERS))["Content-Security-Policy"]
        self.assertIn("default-src", csp.evidence["expected_property"])
        self.assertEqual(csp.evidence["url_tested"], "http://localhost:3000/")
        self.assertEqual(csp.evidence["http_status"], 200)

    def test_unreachable_target_yields_no_findings(self):
        with mock.patch.object(security_headers.requests, "get",
                               side_effect=requests.exceptions.ConnectionError("refused")):
            result = run_headers_probe("http://localhost:3000", timeout=5)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)
        self.assertEqual(normalize_headers(result), [])


if __name__ == "__main__":
    unittest.main()
