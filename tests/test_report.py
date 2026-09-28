"""Tests for report assembly and safe HTML rendering."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scorer import score_all  # noqa: E402
from model.finding import AssetKind, Finding, Severity, Status  # noqa: E402
from reports.html_report import render_html  # noqa: E402
from reports.json_report import build_report  # noqa: E402


def sample_findings():
    findings = [
        Finding(tool="semgrep", title="eval injection", description="d",
                severity=Severity.HIGH, status=Status.SUSPECTED, file="api/x.py", line=3,
                asset={"kind": AssetKind.API, "ref": "api/x.py", "weight": 1.0}),
        Finding(tool="security-headers", title="CSP assessment", description="d",
                severity=Severity.INFO, status=Status.VERIFIED, endpoint="http://localhost:3000/",
                asset={"kind": AssetKind.UI, "ref": "http://localhost:3000/", "weight": 1.0}),
    ]
    return score_all(findings)


SCAN = {"timestamp": "t", "target": "http://localhost:3000", "repository": "repo",
        "commit": "abc", "branch": "main"}


class TestReport(unittest.TestCase):
    def test_summary_counts_match_findings(self):
        report = build_report(sample_findings(), SCAN, "0.1.0")
        self.assertEqual(report["summary"]["total_findings"], 2)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertEqual(report["summary"]["info"], 1)

    def test_html_renders_with_findings(self):
        html = render_html(build_report(sample_findings(), SCAN, "0.1.0"))
        self.assertIn("WATCHTOWER", html)
        self.assertIn("eval injection", html)

    def test_html_autoescapes_finding_text(self):
        evil = Finding(tool="semgrep", title="<script>alert(1)</script>", description="d",
                       severity=Severity.LOW, status=Status.SUSPECTED)
        html = render_html(build_report(score_all([evil]), SCAN, "0.1.0"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_reports_empty_findings_honestly(self):
        html = render_html(build_report([], SCAN, "0.1.0"))
        self.assertIn("No findings were produced", html)


if __name__ == "__main__":
    unittest.main()
