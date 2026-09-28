"""Tests for the OWASP ZAP baseline adapter and normalizer — synthetic output only.

Verifies riskcode->severity mapping, HTML stripping, CWE extraction, loopback
container-target rewriting, and that a passive alert is never auto-marked verified.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import normalizer  # noqa: E402
from model.finding import AssetKind, Severity, Status  # noqa: E402
from scanners import zap  # noqa: E402
from scanners.base import CollectorResult  # noqa: E402

_ZAP = {
    "site": [{
        "@name": "http://localhost:3000",
        "@host": "localhost",
        "@port": "3000",
        "alerts": [{
            "pluginid": "10038",
            "alertRef": "10038-1",
            "alert": "Content Security Policy (CSP) Header Not Set",
            "name": "Content Security Policy (CSP) Header Not Set",
            "riskcode": "2",
            "confidence": "3",
            "riskdesc": "Medium (High)",
            "desc": "<p>Content Security Policy (CSP) is an added layer of security.</p>",
            "solution": "<p>Ensure that your web server sets the CSP header.</p>",
            "reference": "<p>https://developer.mozilla.org/docs/Web/HTTP/CSP</p>",
            "cweid": "693",
            "count": "1",
            "instances": [{
                "uri": "http://localhost:3000/api/users",
                "method": "GET",
                "param": "",
                "evidence": "",
            }],
        }],
    }]
}


def _result(parsed):
    return CollectorResult(tool="zap", parsed=parsed, raw=json.dumps(parsed))


class TestZapNormalize(unittest.TestCase):
    def test_maps_alert(self):
        f = normalizer.normalize_zap(_result(_ZAP))[0]
        self.assertEqual(f.tool, "zap")
        self.assertEqual(f.severity, Severity.MEDIUM)  # riskcode 2 -> medium
        self.assertEqual(f.status, Status.SUSPECTED)  # scanner rating, not verified
        self.assertEqual(f.cwe, "CWE-693")
        self.assertEqual(f.endpoint, "http://localhost:3000/api/users")
        self.assertEqual(f.asset["kind"], AssetKind.API)  # /api/ path

    def test_html_stripped_from_description(self):
        f = normalizer.normalize_zap(_result(_ZAP))[0]
        self.assertNotIn("<", f.description)
        self.assertNotIn(">", f.description)
        self.assertIn("Content Security Policy", f.description)

    def test_riskcode_severity_mapping(self):
        for code, expected in ((3, Severity.HIGH), (2, Severity.MEDIUM),
                               (1, Severity.LOW), (0, Severity.INFO)):
            data = json.loads(json.dumps(_ZAP))
            data["site"][0]["alerts"][0]["riskcode"] = str(code)
            f = normalizer.normalize_zap(_result(data))[0]
            self.assertEqual(f.severity, expected, f"riskcode {code}")

    def test_placeholder_cwe_ignored(self):
        for placeholder in ("-1", "0"):
            data = json.loads(json.dumps(_ZAP))
            data["site"][0]["alerts"][0]["cweid"] = placeholder
            f = normalizer.normalize_zap(_result(data))[0]
            self.assertIsNone(f.cwe, f"cweid {placeholder!r} should not become a CWE")

    def test_evidence_preserved(self):
        f = normalizer.normalize_zap(_result(_ZAP))[0]
        self.assertEqual(f.evidence["pluginid"], "10038")
        self.assertEqual(f.evidence["riskdesc"], "Medium (High)")
        self.assertEqual(f.evidence["instance_count"], 1)
        self.assertNotIn("<", f.evidence["solution"])

    def test_empty(self):
        self.assertEqual(normalizer.normalize_zap(_result({"site": []})), [])
        self.assertEqual(normalizer.normalize_zap(CollectorResult(tool="zap", parsed=None)), [])


class TestZapParsing(unittest.TestCase):
    def test_empty_text(self):
        self.assertEqual(zap.parse_output(""), {"site": []})

    def test_malformed_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            zap.parse_output("<<not json>>")

    def test_non_object_raises(self):
        with self.assertRaises(ValueError):
            zap.parse_output("[1, 2, 3]")

    def test_docker_target_rewrites_loopback(self):
        self.assertEqual(
            zap._docker_target("http://localhost:3000"),
            "http://host.docker.internal:3000",
        )
        self.assertEqual(
            zap._docker_target("http://127.0.0.1:8080/app"),
            "http://host.docker.internal:8080/app",
        )

    def test_docker_target_leaves_remote_host(self):
        self.assertEqual(
            zap._docker_target("http://example.test:80"),
            "http://example.test:80",
        )

    def test_unavailable_is_skipped(self):
        original = zap.zap_mode
        zap.zap_mode = lambda: None
        try:
            result = zap.run_zap("http://localhost:3000", timeout=5)
        finally:
            zap.zap_mode = original
        self.assertTrue(result.skipped)
        self.assertFalse(result.available)


if __name__ == "__main__":
    unittest.main()
