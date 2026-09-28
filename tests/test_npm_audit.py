"""Tests for the npm audit adapter and normalizer — synthetic output only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import normalizer  # noqa: E402
from model.finding import AssetKind, Severity, Status  # noqa: E402
from scanners import npm_audit  # noqa: E402
from scanners.base import CollectorResult  # noqa: E402

_ADVISORY = {
    "source": 1065,
    "name": "lodash",
    "dependency": "lodash",
    "title": "Prototype Pollution in lodash",
    "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695",
    "severity": "moderate",
    "cwe": ["CWE-1321"],
    "range": "<4.17.12",
}
_AUDIT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "moderate",
            "via": [_ADVISORY],
            "range": "<4.17.12",
            "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": False},
        }
    },
}


def _result(parsed):
    return CollectorResult(tool="npm-audit", parsed=parsed, raw=json.dumps(parsed))


class TestNpmAuditNormalize(unittest.TestCase):
    def test_maps_advisory(self):
        f = normalizer.normalize_npm_audit(_result(_AUDIT))[0]
        self.assertEqual(f.tool, "npm-audit")
        self.assertEqual(f.severity, Severity.MEDIUM)  # moderate -> medium
        self.assertEqual(f.status, Status.SUSPECTED)
        self.assertEqual(f.asset["kind"], AssetKind.OTHER)
        self.assertEqual(f.cwe, "CWE-1321")

    def test_preserves_source_metadata(self):
        f = normalizer.normalize_npm_audit(_result(_AUDIT))[0]
        self.assertEqual(f.evidence["advisory_id"], 1065)
        self.assertEqual(f.evidence["vulnerable_range"], "<4.17.12")
        self.assertEqual(f.evidence["fixed_version"], "4.17.21")
        self.assertIn("GHSA-JF85-CPCP-J695", f.evidence["identifiers"])

    def test_deduplicates_same_advisory_across_packages(self):
        audit = json.loads(json.dumps(_AUDIT))
        # Same advisory surfaced under a second package must not double-count.
        audit["vulnerabilities"]["other"] = {
            "name": "other", "severity": "moderate", "via": [_ADVISORY],
            "range": "*", "fixAvailable": True,
        }
        findings = normalizer.normalize_npm_audit(_result(audit))
        self.assertEqual(len(findings), 1)

    def test_empty(self):
        self.assertEqual(normalizer.normalize_npm_audit(_result({"vulnerabilities": {}})), [])


class TestNpmAuditParsing(unittest.TestCase):
    def test_error_object_raises(self):
        with self.assertRaises(ValueError):
            npm_audit.parse_output('{"error": {"code": "EUSAGE", "summary": "no lockfile"}}')

    def test_empty_output_raises(self):
        with self.assertRaises(ValueError):
            npm_audit.parse_output("")

    def test_malformed_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            npm_audit.parse_output("not json at all")

    def test_valid_parses(self):
        parsed = npm_audit.parse_output(json.dumps(_AUDIT))
        self.assertIn("lodash", parsed["vulnerabilities"])

    def test_unavailable_is_skipped(self):
        original = npm_audit.npm_available
        npm_audit.npm_available = lambda: False
        try:
            result = npm_audit.run_npm_audit("/nonexistent", timeout=5)
        finally:
            npm_audit.npm_available = original
        self.assertTrue(result.skipped)
        self.assertFalse(result.available)


if __name__ == "__main__":
    unittest.main()
