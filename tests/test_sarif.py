"""Tests for SARIF 2.1.0 output (Phase 5, item 10)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scorer import score_all  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402
from reports.json_report import build_report  # noqa: E402
from reports.sarif_report import build_sarif, write_sarif  # noqa: E402

SCAN = {"timestamp": "2026-09-28T00:00:00Z", "target": "http://localhost:3000",
        "repository": "repo", "commit": "abc123", "branch": "main"}


def sample_report():
    findings = score_all([
        Finding(tool="semgrep", title="eval injection", description="d", severity=Severity.HIGH,
                status=Status.VERIFIED, id="WT-SEM-0001", cwe="CWE-95", file="api/x.ts", line=7,
                verification={"method": "static", "result": "confirmed", "rationale": "r"}),
        Finding(tool="ssrf", title="SSRF proxy", description="d", severity=Severity.INFO,
                status=Status.FALSE_POSITIVE, id="WT-SSRF-0001",
                endpoint="http://localhost:3000/api/rss-proxy",
                verification={"method": "active_probe", "result": "not_applicable",
                              "rationale": "canary refused"}),
        Finding(tool="auth-mcp", title="MCP auth", description="d", severity=Severity.MEDIUM,
                status=Status.NEEDS_MANUAL_REVIEW, id="WT-AUTH-0001",
                endpoint="http://localhost:3000/api/mcp",
                verification={"method": "active_probe", "result": "inconclusive",
                              "rationale": "404 under dev runtime"}),
    ])
    return build_report(findings, SCAN, "0.1.0")


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.sarif = build_sarif(sample_report())
        self.run = self.sarif["runs"][0]
        self.results = {r["properties"]["watchtower_id"]: r for r in self.run["results"]}

    def test_top_level_shape(self):
        self.assertEqual(self.sarif["version"], "2.1.0")
        self.assertEqual(self.run["tool"]["driver"]["name"], "WATCHTOWER")
        self.assertEqual(len(self.run["results"]), 3)

    def test_verified_is_fail_with_severity_level(self):
        r = self.results["WT-SEM-0001"]
        self.assertEqual(r["kind"], "fail")
        self.assertEqual(r["level"], "error")           # HIGH -> error

    def test_false_positive_not_applicable_kind(self):
        r = self.results["WT-SSRF-0001"]
        self.assertEqual(r["kind"], "notApplicable")
        self.assertEqual(r["level"], "none")

    def test_needs_review_is_review(self):
        self.assertEqual(self.results["WT-AUTH-0001"]["kind"], "review")

    def test_file_finding_has_physical_location(self):
        loc = self.results["WT-SEM-0001"]["locations"][0]
        self.assertEqual(loc["physicalLocation"]["artifactLocation"]["uri"], "api/x.ts")
        self.assertEqual(loc["physicalLocation"]["region"]["startLine"], 7)

    def test_runtime_finding_has_no_fabricated_source(self):
        # Endpoint-only finding must NOT invent a physicalLocation.
        r = self.results["WT-SSRF-0001"]
        loc = r["locations"][0]
        self.assertNotIn("physicalLocation", loc)
        self.assertEqual(loc["logicalLocations"][0]["fullyQualifiedName"],
                         "http://localhost:3000/api/rss-proxy")

    def test_partial_fingerprints_and_properties(self):
        r = self.results["WT-SEM-0001"]
        self.assertIn("watchtowerFingerprint/v1", r["partialFingerprints"])
        self.assertEqual(r["properties"]["lifecycle_status"], "verified")
        self.assertIn(r["properties"]["evidence_confidence"], ("high", "medium", "low"))

    def test_rules_have_valid_indices(self):
        rules = self.run["tool"]["driver"]["rules"]
        for r in self.run["results"]:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])

    def test_write_sarif_produces_valid_json(self):
        tmp = tempfile.mkdtemp(prefix="wt-sarif-")
        try:
            path = write_sarif(os.path.join(tmp, "report.sarif"), sample_report())
            with open(path, encoding="utf-8") as handle:
                data = json.load(handle)
            self.assertEqual(data["version"], "2.1.0")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
