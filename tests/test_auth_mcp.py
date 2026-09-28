"""Tests for the auth / MCP access-control probe (checks/auth_mcp.py).

The probe issues unauthenticated / invalid-bearer / malformed-auth requests and reads
only status codes and a few non-sensitive headers. This suite proves it refuses non-local
targets, classifies 401/403 as REFUTED (auth enforced), treats an exposed MCP tool listing
or a reachable protected operation as CONFIRMED, a bare 200 on an unknown/public endpoint
as inconclusive/not_applicable (never an automatic vulnerability), and — critically — that
it never guesses credentials and never stores secrets or response bodies. HTTP is mocked.
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402

from checks import auth_mcp  # noqa: E402
from checks.auth_mcp import classify_auth, run_auth_probe  # noqa: E402
from engine import lifecycle  # noqa: E402
from model.finding import Severity  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, headers=None, payload=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def _evidence(status, *, expected="protected", mcp_tools=None, endpoint="http://localhost:3000/api/mcp"):
    return {"refused": False, "endpoint": endpoint, "expected": expected,
            "status_by_state": {"none": status, "invalid_bearer": status, "malformed": status},
            "mcp_exposed_tools": mcp_tools, "headers": {"www-authenticate": "Bearer"}}


class TestAuthProbe(unittest.TestCase):
    _MCP = [{"path": "/api/mcp", "kind": "mcp", "expected": "protected"}]

    def test_refuses_nonlocal_target(self):
        result = run_auth_probe("http://example.com", candidates=self._MCP)
        self.assertTrue(result.refused)
        self.assertIn("local", result.error.lower())

    def test_records_status_for_each_auth_state(self):
        with mock.patch.object(auth_mcp.requests, "post",
                               return_value=FakeResponse(401, {"www-authenticate": "Bearer"})):
            result = run_auth_probe("http://localhost:3000", candidates=self._MCP)
        obs = result.observations[0]
        self.assertEqual(set(obs["status_by_state"]), {"none", "invalid_bearer", "malformed"})
        self.assertEqual(obs["status_by_state"]["none"], 401)

    def test_detects_exposed_mcp_tool_listing(self):
        payload = {"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "search"}]}}
        with mock.patch.object(auth_mcp.requests, "post",
                               return_value=FakeResponse(200, {"content-type": "application/json"},
                                                         payload)):
            result = run_auth_probe("http://localhost:3000", candidates=self._MCP)
        self.assertTrue(result.observations[0]["mcp_exposed_tools"])

    def test_no_secret_or_body_is_stored(self):
        # An observation must carry status codes + safe headers only — never the bogus
        # Authorization token we sent, and never the response body.
        payload = {"result": {"tools": []}, "secret": "sk-do-not-store"}
        with mock.patch.object(auth_mcp.requests, "post",
                               return_value=FakeResponse(200, {"content-type": "application/json",
                                                               "set-cookie": "sid=abc"}, payload)):
            result = run_auth_probe("http://localhost:3000", candidates=self._MCP)
        blob = repr(result.observations[0])
        self.assertNotIn("wt-invalid", blob)          # our invalid bearer never leaks
        self.assertNotIn("sk-do-not-store", blob)     # response body never stored
        self.assertNotIn("set-cookie", blob)          # sensitive header not recorded
        self.assertNotIn("sid=abc", blob)

    def test_connection_error_is_recorded(self):
        with mock.patch.object(auth_mcp.requests, "post",
                               side_effect=requests.exceptions.ConnectionError("no")):
            result = run_auth_probe("http://localhost:3000", candidates=self._MCP)
        self.assertIsNone(result.observations[0]["status_by_state"]["none"])


class TestClassifyAuth(unittest.TestCase):
    def test_401_is_refuted(self):
        self.assertEqual(classify_auth(_evidence(401)).result, lifecycle.REFUTED)

    def test_403_is_refuted(self):
        self.assertEqual(classify_auth(_evidence(403)).result, lifecycle.REFUTED)

    def test_404_is_inconclusive(self):
        # A 404 (e.g. route unmounted under a dev runtime) is NOT proof the surface is absent;
        # it must need manual review against the production/serverless runtime, never false_positive.
        v = classify_auth(_evidence(404))
        self.assertEqual(v.result, lifecycle.INCONCLUSIVE)
        self.assertIn("production/serverless", v.rationale)

    def test_exposed_mcp_tools_confirmed(self):
        v = classify_auth(_evidence(200, mcp_tools=True))
        self.assertEqual(v.result, lifecycle.CONFIRMED)
        self.assertEqual(v.severity, Severity.HIGH)

    def test_protected_2xx_confirmed(self):
        v = classify_auth(_evidence(200, expected="protected"))
        self.assertEqual(v.result, lifecycle.CONFIRMED)

    def test_public_2xx_not_applicable(self):
        self.assertEqual(classify_auth(_evidence(200, expected="public")).result,
                         lifecycle.NOT_APPLICABLE)

    def test_unknown_2xx_inconclusive_not_a_vuln(self):
        # A bare HTTP 200 on an endpoint of unknown intent is never an automatic finding.
        v = classify_auth(_evidence(200, expected="unknown"))
        self.assertEqual(v.result, lifecycle.INCONCLUSIVE)
        self.assertEqual(v.severity, Severity.MEDIUM)

    def test_no_response_inconclusive(self):
        ev = _evidence(200)
        ev["status_by_state"]["none"] = None
        self.assertEqual(classify_auth(ev).result, lifecycle.INCONCLUSIVE)

    def test_nonlocal_refused_not_applicable(self):
        self.assertEqual(classify_auth({"refused": True}).result, lifecycle.NOT_APPLICABLE)


if __name__ == "__main__":
    unittest.main()
