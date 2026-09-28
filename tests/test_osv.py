"""Tests for the OSV-Scanner adapter and normalizer — synthetic output only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import normalizer  # noqa: E402
from model.finding import AssetKind, Severity, Status  # noqa: E402
from scanners import osv  # noqa: E402
from scanners.base import CollectorResult  # noqa: E402

_OSV = {
    "results": [{
        "source": {"path": "/repo/package-lock.json", "type": "lockfile"},
        "packages": [{
            "package": {"name": "lodash", "version": "4.17.4", "ecosystem": "npm"},
            "vulnerabilities": [{
                "id": "GHSA-jf85-cpcp-j695",
                "aliases": ["CVE-2019-10744"],
                "summary": "Prototype pollution in lodash",
                "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
                "references": [{"url": "https://example/advisory"}],
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.12"}]}]}],
            }],
        }],
    }]
}


def _result(parsed):
    return CollectorResult(tool="osv-scanner", parsed=parsed, raw=json.dumps(parsed))


class TestOsvNormalize(unittest.TestCase):
    def test_maps_dependency_finding(self):
        f = normalizer.normalize_osv(_result(_OSV), repo_path="/repo")[0]
        self.assertEqual(f.tool, "osv-scanner")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.status, Status.SUSPECTED)
        self.assertEqual(f.asset["kind"], AssetKind.OTHER)
        self.assertEqual(f.cwe, "CWE-1321")

    def test_preserves_identifiers_and_fix(self):
        f = normalizer.normalize_osv(_result(_OSV))[0]
        self.assertIn("GHSA-JF85-CPCP-J695", f.evidence["identifiers"])
        self.assertIn("CVE-2019-10744", f.evidence["identifiers"])
        self.assertEqual(f.evidence["fixed_version"], "4.17.12")
        self.assertEqual(f.evidence["installed_version"], "4.17.4")

    def test_severity_not_invented_when_absent(self):
        data = json.loads(json.dumps(_OSV))
        data["results"][0]["packages"][0]["vulnerabilities"][0].pop("database_specific")
        f = normalizer.normalize_osv(_result(data))[0]
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.evidence["severity_source"], "unspecified-by-tool")

    def test_empty(self):
        self.assertEqual(normalizer.normalize_osv(_result({"results": []})), [])
        self.assertEqual(normalizer.normalize_osv(CollectorResult(tool="osv-scanner", parsed=None)), [])


class TestOsvParsing(unittest.TestCase):
    def test_empty_text(self):
        self.assertEqual(osv.parse_output(""), {"results": []})

    def test_malformed_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            osv.parse_output("<<not json>>")

    def test_non_object_raises(self):
        with self.assertRaises(ValueError):
            osv.parse_output("[1, 2, 3]")

    def test_unavailable_is_skipped(self):
        original = osv.osv_available
        osv.osv_available = lambda: False
        try:
            result = osv.run_osv("/nonexistent", timeout=5)
        finally:
            osv.osv_available = original
        self.assertTrue(result.skipped)
        self.assertFalse(result.available)


if __name__ == "__main__":
    unittest.main()
