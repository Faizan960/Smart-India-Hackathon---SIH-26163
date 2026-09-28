"""Tests for the assessment diff engine (Phase 5, item 9)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.diff import diff_reports  # noqa: E402
from engine.scorer import score_all  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402
from reports.json_report import build_report  # noqa: E402


def _surface(paths):
    return AttackSurface(endpoints=[Endpoint(path=p, methods=["GET"], source_file=f"{p}.ts",
                                             component="core") for p in paths])


def _old_report():
    findings = score_all([
        Finding(tool="semgrep", title="eval", description="d", severity=Severity.HIGH,
                status=Status.SUSPECTED, file="api/x.ts", line=3, id="WT-SEM-0001"),
        Finding(tool="security-headers", title="CSP missing", description="d",
                severity=Severity.LOW, status=Status.VERIFIED,
                endpoint="http://localhost:3000/", id="WT-HDR-0001",
                verification={"method": "header_probe", "result": "confirmed"}),
    ])
    return build_report(findings, {"timestamp": "t1", "commit": "aaa"}, "0.1.0",
                        attack_surface=_surface(["/api/a", "/api/b"]))


def _new_report():
    findings = score_all([
        # Same fingerprint as WT-SEM-0001 (tool/title/file/line unchanged) but status &
        # severity changed -> status_change + severity_change + score_change.
        Finding(tool="semgrep", title="eval", description="d", severity=Severity.CRITICAL,
                status=Status.VERIFIED, file="api/x.ts", line=3, id="WT-SEM-0001",
                verification={"method": "static", "result": "confirmed"}),
        # New finding not present in the baseline.
        Finding(tool="cors", title="cors reflect", description="d", severity=Severity.HIGH,
                status=Status.FALSE_POSITIVE, endpoint="http://localhost:3000/api/mcp-proxy",
                id="WT-CORS-0001", verification={"method": "active_probe", "result": "refuted"}),
    ])
    return build_report(findings, {"timestamp": "t2", "commit": "bbb"}, "0.1.0",
                        attack_surface=_surface(["/api/a", "/api/c"]))


class TestAssessmentDiff(unittest.TestCase):
    def setUp(self):
        self.diff = diff_reports(_old_report(), _new_report())

    def test_new_and_resolved(self):
        self.assertEqual(self.diff["counts"]["new"], 1)
        self.assertEqual(self.diff["counts"]["resolved"], 1)
        self.assertEqual(self.diff["new_findings"][0]["id"], "WT-CORS-0001")
        self.assertEqual(self.diff["resolved_findings"][0]["id"], "WT-HDR-0001")

    def test_status_change_detected(self):
        changes = {c["id"]: c for c in self.diff["status_changes"]}
        self.assertIn("WT-SEM-0001", changes)
        self.assertEqual(changes["WT-SEM-0001"]["from"], "suspected")
        self.assertEqual(changes["WT-SEM-0001"]["to"], "verified")

    def test_severity_and_score_changes(self):
        sev = {c["id"]: c for c in self.diff["severity_changes"]}
        self.assertEqual(sev["WT-SEM-0001"]["from"], "high")
        self.assertEqual(sev["WT-SEM-0001"]["to"], "critical")
        self.assertTrue(self.diff["score_changes"])

    def test_attack_surface_additions_and_removals(self):
        self.assertEqual(self.diff["attack_surface_additions"], ["/api/c"])
        self.assertEqual(self.diff["attack_surface_removals"], ["/api/b"])

    def test_commit_context_and_no_causality(self):
        self.assertEqual(self.diff["baseline"]["commit"], "aaa")
        self.assertEqual(self.diff["current"]["commit"], "bbb")
        self.assertIn("Causality is NOT inferred", self.diff["note"])

    def test_identical_reports_show_no_change(self):
        same = _old_report()
        diff = diff_reports(same, same)
        self.assertEqual(diff["counts"]["new"], 0)
        self.assertEqual(diff["counts"]["resolved"], 0)
        self.assertEqual(diff["counts"]["status_changed"], 0)


if __name__ == "__main__":
    unittest.main()
