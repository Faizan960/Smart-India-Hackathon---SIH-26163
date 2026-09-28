"""Tests for the assessment diff engine (Phase 5, item 9; Phase 6 regression extensions)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.baseline import build_baseline  # noqa: E402
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

    # --- Phase 6: existing behaviour must keep working after the extensions ---

    def test_new_finding_still_detected(self):
        self.assertEqual(self.diff["counts"]["new"], 1)
        self.assertEqual({f["id"] for f in self.diff["new_findings"]}, {"WT-CORS-0001"})

    def test_resolved_finding_still_detected(self):
        self.assertEqual(self.diff["counts"]["resolved"], 1)
        self.assertEqual({f["id"] for f in self.diff["resolved_findings"]}, {"WT-HDR-0001"})

    def test_attack_surface_change_still_detected(self):
        self.assertEqual(self.diff["attack_surface_additions"], ["/api/c"])
        self.assertEqual(self.diff["attack_surface_removals"], ["/api/b"])
        self.assertEqual(self.diff["counts"]["surface_added"], 1)
        self.assertEqual(self.diff["counts"]["surface_removed"], 1)

    def test_no_causality_inference(self):
        note = self.diff["note"]
        self.assertIn("Causality is NOT inferred", note)
        # The diff describes observed change only; it must not assert a commit as a cause.
        self.assertNotIn("introduced", note)
        self.assertNotIn("caused", note)


def _regression_old():
    findings = score_all([
        # Stays identical across both assessments (same fingerprint, same state).
        Finding(tool="semgrep", title="sql injection", description="d", severity=Severity.HIGH,
                status=Status.SUSPECTED, file="api/db.ts", line=10, id="WT-SEM-0002"),
        # Verification result will change: confirmed -> inconclusive.
        Finding(tool="cors", title="cors reflect", description="d", severity=Severity.HIGH,
                status=Status.VERIFIED, endpoint="http://localhost:3000/api/x", id="WT-CORS-0002",
                verification={"method": "active_probe", "result": "confirmed"}),
        # Lifecycle status will change (suspected -> correlated) with NO verification result
        # on either side -> must NOT be reported as a verification-result change.
        Finding(tool="zap", title="open redirect", description="d", severity=Severity.MEDIUM,
                status=Status.SUSPECTED, endpoint="http://localhost:3000/api/y", id="WT-ZAP-0002"),
    ])
    return build_report(findings, {"timestamp": "t1", "commit": "c1"}, "0.1.0",
                        attack_surface=_surface(["/api/a", "/api/b"]))


def _regression_new():
    findings = score_all([
        Finding(tool="semgrep", title="sql injection", description="d", severity=Severity.HIGH,
                status=Status.SUSPECTED, file="api/db.ts", line=10, id="WT-SEM-0002"),
        Finding(tool="cors", title="cors reflect", description="d", severity=Severity.HIGH,
                status=Status.NEEDS_MANUAL_REVIEW, endpoint="http://localhost:3000/api/x",
                id="WT-CORS-0002",
                verification={"method": "active_probe", "result": "inconclusive"}),
        Finding(tool="zap", title="open redirect", description="d", severity=Severity.MEDIUM,
                status=Status.CORRELATED, endpoint="http://localhost:3000/api/y", id="WT-ZAP-0002"),
    ])
    return build_report(findings, {"timestamp": "t2", "commit": "c2"}, "0.1.0",
                        attack_surface=_surface(["/api/a", "/api/b"]))


class TestDiffRegression(unittest.TestCase):
    """Phase 6: unchanged findings, verification-result changes, baseline compatibility."""

    def setUp(self):
        self.diff = diff_reports(_regression_old(), _regression_new())

    def test_unchanged_findings(self):
        unchanged = {f["id"] for f in self.diff["unchanged_findings"]}
        self.assertEqual(unchanged, {"WT-SEM-0002"})
        self.assertEqual(self.diff["counts"]["unchanged"], 1)
        # An unchanged finding is never double-counted as new or resolved.
        self.assertNotIn("WT-SEM-0002", {f["id"] for f in self.diff["new_findings"]})
        self.assertNotIn("WT-SEM-0002", {f["id"] for f in self.diff["resolved_findings"]})

    def test_verification_result_change(self):
        changes = {c["id"]: c for c in self.diff["verification_changes"]}
        self.assertIn("WT-CORS-0002", changes)
        self.assertEqual(changes["WT-CORS-0002"]["from"], "confirmed")
        self.assertEqual(changes["WT-CORS-0002"]["to"], "inconclusive")
        self.assertEqual(self.diff["counts"]["verification_changed"], 1)

    def test_verification_result_change_is_distinct_from_status_change(self):
        status_ids = {c["id"] for c in self.diff["status_changes"]}
        verif_ids = {c["id"] for c in self.diff["verification_changes"]}
        # ZAP: lifecycle status changed but the verification result did not -> status list only.
        self.assertIn("WT-ZAP-0002", status_ids)
        self.assertNotIn("WT-ZAP-0002", verif_ids)
        # CORS: both changed, tracked independently in their own lists (not derived one another).
        self.assertIn("WT-CORS-0002", status_ids)
        self.assertIn("WT-CORS-0002", verif_ids)

    def test_identical_reports_have_all_findings_unchanged(self):
        same = _regression_old()
        diff = diff_reports(same, same)
        self.assertEqual(diff["counts"]["new"], 0)
        self.assertEqual(diff["counts"]["resolved"], 0)
        self.assertEqual(diff["counts"]["unchanged"], 3)
        for key in ("status_changes", "severity_changes", "score_changes",
                    "verification_changes", "attack_surface_additions",
                    "attack_surface_removals"):
            self.assertEqual(diff[key], [])
        self.assertEqual({f["id"] for f in diff["unchanged_findings"]},
                         {"WT-SEM-0002", "WT-CORS-0002", "WT-ZAP-0002"})

    def test_baseline_can_be_compared_with_report(self):
        report = _regression_old()
        baseline = build_baseline(report)
        # A baseline omits ephemeral fields, yet compares cleanly against its own report:
        # identical assessment state -> everything unchanged, nothing invented, both directions.
        for old, new in ((report, baseline), (baseline, report)):
            diff = diff_reports(old, new)
            self.assertEqual(diff["counts"]["new"], 0)
            self.assertEqual(diff["counts"]["resolved"], 0)
            self.assertEqual(diff["counts"]["unchanged"], 3)
            self.assertEqual(diff["counts"]["verification_changed"], 0)
            self.assertEqual(diff["counts"]["score_changed"], 0)
            self.assertEqual(diff["attack_surface_additions"], [])
            self.assertEqual(diff["attack_surface_removals"], [])

    def test_diff_is_deterministic(self):
        d1 = diff_reports(_regression_old(), _regression_new())
        d2 = diff_reports(_regression_old(), _regression_new())
        self.assertEqual(d1, d2)
        self.assertEqual(json.dumps(d1, sort_keys=True), json.dumps(d2, sort_keys=True))

    def test_absent_verification_data_invents_no_change(self):
        # Two scanner-only findings with NO explicit verification result on either side. The
        # lifecycle status differs, but with no verification result present a verification-
        # result change must NOT be invented from the status change or from missing data.
        old = build_report(score_all([
            Finding(tool="gitleaks", title="aws key", description="d", severity=Severity.HIGH,
                    status=Status.SUSPECTED, file="s.env", line=1, id="WT-GL-0001")]),
            {"timestamp": "t1", "commit": "c1"}, "0.1.0")
        new = build_report(score_all([
            Finding(tool="gitleaks", title="aws key", description="d", severity=Severity.HIGH,
                    status=Status.NEEDS_MANUAL_REVIEW, file="s.env", line=1, id="WT-GL-0001")]),
            {"timestamp": "t2", "commit": "c2"}, "0.1.0")
        diff = diff_reports(old, new)
        self.assertEqual(diff["verification_changes"], [])
        self.assertEqual(diff["counts"]["verification_changed"], 0)
        self.assertEqual(diff["counts"]["status_changed"], 1)   # the status itself DID change


if __name__ == "__main__":
    unittest.main()
