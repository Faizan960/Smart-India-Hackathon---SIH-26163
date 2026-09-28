"""Tests for the CORS active probe (checks/cors.py).

HTTP is mocked, so nothing here needs a running target. Covers the probe's hostile-origin
request, its refusal to run against non-local targets, and the conservative classifier
(reflected-origin + credentials -> confirmed; reflected-only -> inconclusive; not
granted -> refuted; unreachable -> inconclusive; non-local -> not_applicable).
"""
import datetime
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from checks import cors  # noqa: E402
from checks.cors import EVIL_ORIGIN, classify_cors, run_cors_probe  # noqa: E402
from engine import lifecycle  # noqa: E402
from model.finding import Severity  # noqa: E402


class FakeResponse:
    def __init__(self, headers, status_code=200):
        self.headers = headers
        self.status_code = status_code


def _evidence(*, refused=False, reachable=True, simple=None, preflight=None,
              origin_sent=EVIL_ORIGIN):
    return {"refused": refused, "reachable": reachable, "origin_sent": origin_sent,
            "simple": simple or {}, "preflight": preflight or {}}


class TestCorsProbe(unittest.TestCase):
    def test_refuses_nonlocal_target(self):
        result = run_cors_probe("http://example.com", timeout=1)
        self.assertTrue(result.refused)
        self.assertFalse(result.reachable)
        self.assertIn("local", result.error.lower())

    def test_allow_nonlocal_override_runs(self):
        with mock.patch.object(cors.requests, "get",
                               return_value=FakeResponse({}, 200)), \
             mock.patch.object(cors.requests, "options",
                               return_value=FakeResponse({}, 204)):
            result = run_cors_probe("http://example.com", timeout=1, allow_nonlocal=True)
        self.assertFalse(result.refused)
        self.assertTrue(result.reachable)

    def test_sends_hostile_origin_and_records_headers(self):
        simple = {"Access-Control-Allow-Origin": EVIL_ORIGIN,
                  "Access-Control-Allow-Credentials": "true"}
        with mock.patch.object(cors.requests, "get",
                               return_value=FakeResponse(simple, 200)) as m_get, \
             mock.patch.object(cors.requests, "options",
                               return_value=FakeResponse({}, 204)):
            result = run_cors_probe("http://localhost:3000", timeout=1)
        # The probe must actually send the hostile Origin header.
        self.assertEqual(m_get.call_args.kwargs["headers"]["Origin"], EVIL_ORIGIN)
        self.assertTrue(result.reachable)
        self.assertEqual(result.simple["Access-Control-Allow-Origin"], EVIL_ORIGIN)

    def test_connection_error_marks_unreachable(self):
        with mock.patch.object(cors.requests, "get",
                               side_effect=requests.exceptions.ConnectionError("no")):
            result = run_cors_probe("http://localhost:3000", timeout=1)
        self.assertFalse(result.reachable)
        self.assertIsNotNone(result.error)


class TestClassifyCors(unittest.TestCase):
    def test_reflected_origin_with_credentials_confirmed(self):
        ev = _evidence(simple={"Access-Control-Allow-Origin": EVIL_ORIGIN,
                               "Access-Control-Allow-Credentials": "true"})
        verdict = classify_cors(ev)
        self.assertEqual(verdict.result, lifecycle.CONFIRMED)
        self.assertEqual(verdict.severity, Severity.HIGH)

    def test_reflected_origin_without_credentials_inconclusive(self):
        ev = _evidence(simple={"Access-Control-Allow-Origin": EVIL_ORIGIN})
        verdict = classify_cors(ev)
        self.assertEqual(verdict.result, lifecycle.INCONCLUSIVE)
        self.assertEqual(verdict.severity, Severity.MEDIUM)

    def test_wildcard_without_credentials_inconclusive(self):
        ev = _evidence(simple={"Access-Control-Allow-Origin": "*"})
        self.assertEqual(classify_cors(ev).result, lifecycle.INCONCLUSIVE)

    def test_origin_not_permitted_refuted(self):
        ev = _evidence(simple={"Access-Control-Allow-Origin": "https://trusted.example"})
        self.assertEqual(classify_cors(ev).result, lifecycle.REFUTED)

    def test_no_cors_headers_refuted(self):
        # ACAO simply absent -> the hostile origin was not granted.
        self.assertEqual(classify_cors(_evidence()).result, lifecycle.REFUTED)

    def test_unreachable_inconclusive(self):
        self.assertEqual(classify_cors(_evidence(reachable=False)).result,
                         lifecycle.INCONCLUSIVE)

    def test_nonlocal_refused_not_applicable(self):
        self.assertEqual(classify_cors(_evidence(refused=True)).result,
                         lifecycle.NOT_APPLICABLE)

    def test_preflight_headers_also_considered(self):
        ev = _evidence(simple={},
                       preflight={"Access-Control-Allow-Origin": EVIL_ORIGIN,
                                  "Access-Control-Allow-Credentials": "true"})
        self.assertEqual(classify_cors(ev).result, lifecycle.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
