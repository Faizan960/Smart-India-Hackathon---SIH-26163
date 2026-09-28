"""Tests for the deterministic security gate (Phase 6, Step 4).

The gate is a policy layer over structured assessment data only. These tests pin its policy
(FAIL > WARN > PASS), its lifecycle/severity rules (only VERIFIED Critical/High fail; false
positives, suspected and correlated never fail; needs_manual_review only warns), its
fingerprint-based newly-verified detection via the structured diff, the no-baseline case,
exit codes (only FAIL is non-zero), determinism, and that it never parses rendered text.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.baseline import build_baseline  # noqa: E402
from engine.diff import diff_reports  # noqa: E402
from engine.gate import GATE_POLICY, evaluate_gate, exit_code_for  # noqa: E402
from engine.scorer import score_all  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402
from reports.json_report import build_report  # noqa: E402

SCAN = {"timestamp": "t1", "commit": "c1", "target": "http://localhost:3000",
        "repository": "world-monitor", "branch": "main"}


def _f(tool, title, severity, status, **kw):
    return Finding(tool=tool, title=title, description="d", severity=severity, status=status, **kw)


def _report(findings, execution=None):
    """Build a report from findings. With execution=None every material-limitation section is
    empty, so a report WARNs only when a test explicitly adds needs_manual_review or skips."""
    return build_report(score_all(list(findings)), SCAN, "0.1.0", execution=execution)


def _diff(old_findings, new_report):
    """Structured diff of a canonical baseline (old) against the current report (new)."""
    return diff_reports(build_baseline(_report(old_findings)), new_report)


class TestGatePolicy(unittest.TestCase):
    """Severity + lifecycle rules and PASS/WARN/FAIL priority (no baseline involved)."""

    def test_zero_findings_passes(self):
        gate = evaluate_gate(_report([]))
        self.assertEqual(gate["result"], "PASS")
        self.assertEqual(gate["counts"]["verified_critical"], 0)
        self.assertEqual(gate["reasons"], [])

    def test_verified_critical_fails(self):
        gate = evaluate_gate(_report([
            _f("semgrep", "rce", Severity.CRITICAL, Status.VERIFIED, file="a.ts", line=1)]))
        self.assertEqual(gate["result"], "FAIL")
        self.assertEqual(gate["counts"]["verified_critical"], 1)
        self.assertIn("VERIFIED_CRITICAL", {r["code"] for r in gate["reasons"]})

    def test_verified_high_fails(self):
        gate = evaluate_gate(_report([
            _f("semgrep", "sqli", Severity.HIGH, Status.VERIFIED, file="a.ts", line=2)]))
        self.assertEqual(gate["result"], "FAIL")
        self.assertEqual(gate["counts"]["verified_high"], 1)
        self.assertIn("VERIFIED_HIGH", {r["code"] for r in gate["reasons"]})

    def test_verified_medium_does_not_fail(self):
        gate = evaluate_gate(_report([
            _f("zap", "verbose error", Severity.MEDIUM, Status.VERIFIED, endpoint="/e")]))
        self.assertNotEqual(gate["result"], "FAIL")
        self.assertEqual(gate["result"], "PASS")
        self.assertEqual(gate["counts"]["verified_medium"], 1)

    def test_false_positive_does_not_fail(self):
        # HIGH severity but a false positive -> must never fail (status, not severity, gates).
        gate = evaluate_gate(_report([
            _f("cors", "cors reflect", Severity.HIGH, Status.FALSE_POSITIVE, endpoint="/c")]))
        self.assertEqual(gate["result"], "PASS")
        self.assertEqual(gate["counts"]["verified_high"], 0)

    def test_suspected_does_not_fail(self):
        gate = evaluate_gate(_report([
            _f("semgrep", "maybe", Severity.HIGH, Status.SUSPECTED, file="b.ts", line=3)]))
        self.assertEqual(gate["result"], "PASS")

    def test_correlated_does_not_fail(self):
        gate = evaluate_gate(_report([
            _f("semgrep", "corr", Severity.HIGH, Status.CORRELATED, file="c.ts", line=4)]))
        self.assertEqual(gate["result"], "PASS")

    def test_manual_review_warns(self):
        gate = evaluate_gate(_report([
            _f("zap", "review me", Severity.MEDIUM, Status.NEEDS_MANUAL_REVIEW, endpoint="/r")]))
        self.assertEqual(gate["result"], "WARN")
        self.assertEqual(gate["counts"]["needs_manual_review"], 1)
        self.assertIn("NEEDS_MANUAL_REVIEW", {r["code"] for r in gate["reasons"]})

    def test_manual_review_does_not_fail(self):
        # Even a HIGH needs_manual_review is a WARN, never a FAIL.
        gate = evaluate_gate(_report([
            _f("zap", "big review", Severity.HIGH, Status.NEEDS_MANUAL_REVIEW, endpoint="/r2")]))
        self.assertNotEqual(gate["result"], "FAIL")
        self.assertEqual(gate["result"], "WARN")

    def test_limitations_materially_affecting_coverage_warn(self):
        # A scanner that was meant to run but was skipped is a material coverage gap -> WARN.
        gate = evaluate_gate(_report([], execution=[{"tool": "semgrep", "status": "skipped"}]))
        self.assertEqual(gate["result"], "WARN")
        self.assertIn("ASSESSMENT_LIMITATION", {r["code"] for r in gate["reasons"]})

    def test_gate_priority_fail_over_warn(self):
        # verified High (FAIL) + needs_manual_review (WARN) -> FAIL wins.
        gate = evaluate_gate(_report([
            _f("semgrep", "sqli", Severity.HIGH, Status.VERIFIED, file="d.ts", line=5),
            _f("zap", "review", Severity.MEDIUM, Status.NEEDS_MANUAL_REVIEW, endpoint="/p")]))
        self.assertEqual(gate["result"], "FAIL")
        levels = {r["level"] for r in gate["reasons"]}
        self.assertIn("FAIL", levels)
        self.assertIn("WARN", levels)  # the warn condition is still recorded, priority just wins

    # --- PLACEHOLDER-NEWVERIFIED ---


class TestGateNewVerified(unittest.TestCase):
    """Newly-verified detection by stable fingerprint via the structured diff.

    The cross-baseline findings below keep tool/title/file/line/endpoint identical on both
    sides, so they share a fingerprint and the diff matches them by identity, not position.
    Severities are LOW so the ONLY thing that can fail the gate is the new-verified rule.
    """

    def test_new_verified_finding_fails(self):
        # Absent in baseline, present-and-verified now -> newly verified -> FAIL.
        new = _report([_f("semgrep", "leak", Severity.LOW, Status.VERIFIED, file="x.ts", line=1)])
        gate = evaluate_gate(new, _diff([], new))
        self.assertEqual(gate["result"], "FAIL")
        self.assertEqual(gate["counts"]["new_verified"], 1)
        self.assertIn("NEW_VERIFIED", {r["code"] for r in gate["reasons"]})

    def test_suspected_to_verified_counts_as_new_verified(self):
        old = [_f("semgrep", "leak", Severity.LOW, Status.SUSPECTED, file="x.ts", line=1)]
        new = _report([_f("semgrep", "leak", Severity.LOW, Status.VERIFIED, file="x.ts", line=1)])
        gate = evaluate_gate(new, _diff(old, new))
        self.assertEqual(gate["result"], "FAIL")
        self.assertEqual(gate["counts"]["new_verified"], 1)

    def test_manual_review_to_verified_counts_as_new_verified(self):
        old = [_f("zap", "xss", Severity.LOW, Status.NEEDS_MANUAL_REVIEW, endpoint="/e")]
        new = _report([_f("zap", "xss", Severity.LOW, Status.VERIFIED, endpoint="/e")])
        gate = evaluate_gate(new, _diff(old, new))
        self.assertEqual(gate["result"], "FAIL")
        self.assertEqual(gate["counts"]["new_verified"], 1)

    def test_existing_verified_finding_does_not_count_as_new(self):
        # Verified LOW on BOTH sides (unchanged) -> not new, and LOW never fails on severity.
        both = lambda: _f("zap", "xss", Severity.LOW, Status.VERIFIED, endpoint="/e")  # noqa: E731
        new = _report([both()])
        gate = evaluate_gate(new, _diff([both()], new))
        self.assertEqual(gate["counts"]["new_verified"], 0)
        self.assertEqual(gate["result"], "PASS")

    def test_resolved_verified_finding_is_not_new(self):
        # Verified in baseline, absent now (resolved) -> a resolution, never a new verify.
        old = [_f("zap", "xss", Severity.LOW, Status.VERIFIED, endpoint="/e")]
        new = _report([])
        gate = evaluate_gate(new, _diff(old, new))
        self.assertEqual(gate["counts"]["new_verified"], 0)
        self.assertEqual(gate["result"], "PASS")

    def test_no_baseline_cannot_claim_new_verified(self):
        # No diff: current assessment is still evaluated, but "new verified" is never invented.
        new = _report([_f("zap", "e", Severity.MEDIUM, Status.VERIFIED, endpoint="/m")])
        gate = evaluate_gate(new)  # diff omitted
        self.assertFalse(gate["baseline_aware"])
        self.assertEqual(gate["counts"]["new_verified"], 0)
        self.assertEqual(gate["result"], "PASS")   # verified Medium alone does not fail

    def test_no_baseline_still_enforces_current_severity(self):
        # Without a baseline the severity rules still apply to the current assessment.
        new = _report([_f("semgrep", "rce", Severity.CRITICAL, Status.VERIFIED, file="a.ts", line=1)])
        gate = evaluate_gate(new)
        self.assertFalse(gate["baseline_aware"])
        self.assertEqual(gate["result"], "FAIL")

    # --- PLACEHOLDER-STRUCTURE ---


class TestGateExitCodes(unittest.TestCase):
    def test_gate_exit_code_pass(self):
        self.assertEqual(exit_code_for("PASS"), 0)
        self.assertEqual(exit_code_for(evaluate_gate(_report([]))["result"]), 0)

    def test_gate_exit_code_warn(self):
        # WARN is NOT a process failure.
        self.assertEqual(exit_code_for("WARN"), 0)
        warn = evaluate_gate(_report([
            _f("zap", "r", Severity.LOW, Status.NEEDS_MANUAL_REVIEW, endpoint="/w")]))
        self.assertEqual(warn["result"], "WARN")
        self.assertEqual(exit_code_for(warn["result"]), 0)

    def test_gate_exit_code_fail(self):
        self.assertEqual(exit_code_for("FAIL"), 1)
        fail = evaluate_gate(_report([
            _f("semgrep", "rce", Severity.CRITICAL, Status.VERIFIED, file="a.ts", line=1)]))
        self.assertEqual(exit_code_for(fail["result"]), 1)


class TestGateStructure(unittest.TestCase):
    def test_gate_policy_version_present(self):
        gate = evaluate_gate(_report([]))
        self.assertEqual(gate["policy"], "watchtower-gate-v1")
        self.assertEqual(gate["policy"], GATE_POLICY)

    def test_gate_result_structure(self):
        gate = evaluate_gate(_report([
            _f("semgrep", "sqli", Severity.HIGH, Status.VERIFIED, file="a.ts", line=1)]))
        self.assertEqual(set(gate), {"result", "policy", "baseline_aware", "reasons", "counts"})
        self.assertEqual(set(gate["counts"]), {"verified_critical", "verified_high",
                                               "verified_medium", "needs_manual_review",
                                               "new_verified"})
        for reason in gate["reasons"]:
            # Each reason is machine-readable, not merely a free-form message.
            self.assertIn(reason["level"], {"FAIL", "WARN"})
            self.assertIsInstance(reason["code"], str)
            self.assertIsInstance(reason["count"], int)
            self.assertIsInstance(reason["message"], str)

    def test_gate_does_not_parse_text(self):
        # A benign assessment whose free-form TEXT is full of scary keywords must still PASS:
        # the gate reads structured status/severity, never rendered strings.
        report = _report([_f("semgrep", "verified CRITICAL High FAIL exploit",
                             Severity.INFO, Status.SUSPECTED, file="z.ts", line=9)])
        report["assessment_limitations"]["notes"].append("VERIFIED High CRITICAL FAIL")
        report["scan"]["commit"] = "verifiedCriticalFAIL"
        report["html"] = "<h1>FAIL</h1> verified Critical verified High"
        gate = evaluate_gate(report)
        self.assertEqual(gate["result"], "PASS")
        # Flipping ONLY the structured fields (same scary text) is what changes the verdict.
        report["findings"][0]["status"] = Status.VERIFIED
        report["findings"][0]["severity"] = Severity.HIGH
        self.assertEqual(evaluate_gate(report)["result"], "FAIL")

    def test_gate_is_deterministic(self):
        new = _report([
            _f("semgrep", "sqli", Severity.HIGH, Status.VERIFIED, file="a.ts", line=1),
            _f("zap", "r", Severity.LOW, Status.NEEDS_MANUAL_REVIEW, endpoint="/w")],
            execution=[{"tool": "gitleaks", "status": "skipped"}])
        diff = _diff([_f("semgrep", "sqli", Severity.HIGH, Status.SUSPECTED, file="a.ts", line=1)],
                     new)
        g1, g2 = evaluate_gate(new, diff), evaluate_gate(new, diff)
        self.assertEqual(g1, g2)
        self.assertEqual(json.dumps(g1, sort_keys=True), json.dumps(g2, sort_keys=True))


if __name__ == "__main__":
    unittest.main()


