"""Tests for engine.lifecycle — status-transition enforcement and the audit trail."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import lifecycle  # noqa: E402
from model.finding import Finding, Status  # noqa: E402


def _finding(status=Status.SUSPECTED):
    return Finding(tool="t", title="x", description="d", status=status)


class TestLifecycle(unittest.TestCase):
    def test_allowlist(self):
        self.assertTrue(lifecycle.can_transition(Status.SUSPECTED, Status.CORRELATED))
        self.assertTrue(lifecycle.can_transition(Status.SUSPECTED, Status.VERIFIED))
        self.assertTrue(lifecycle.can_transition(Status.CORRELATED, Status.NEEDS_MANUAL_REVIEW))
        self.assertTrue(lifecycle.can_transition(Status.NEEDS_MANUAL_REVIEW, Status.VERIFIED))
        self.assertFalse(lifecycle.can_transition(Status.VERIFIED, Status.SUSPECTED))
        self.assertFalse(lifecycle.can_transition(Status.FALSE_POSITIVE, Status.VERIFIED))

    def test_apply_records_log(self):
        finding = _finding()
        self.assertTrue(lifecycle.transition(
            finding, Status.CORRELATED, actor="correlator", rationale="two tools"))
        self.assertEqual(finding.status, Status.CORRELATED)
        entry = finding.evidence["lifecycle"][-1]
        self.assertTrue(entry["applied"])
        self.assertEqual(entry["from"], Status.SUSPECTED)
        self.assertEqual(entry["to"], Status.CORRELATED)

    def test_verified_is_terminal(self):
        finding = _finding(Status.VERIFIED)
        self.assertFalse(lifecycle.transition(
            finding, Status.SUSPECTED, actor="x", rationale="reopen attempt"))
        self.assertEqual(finding.status, Status.VERIFIED)
        entry = finding.evidence["lifecycle"][-1]
        self.assertFalse(entry["applied"])
        self.assertEqual(entry["requested"], Status.SUSPECTED)
        self.assertEqual(entry["to"], Status.VERIFIED)  # unchanged

    def test_false_positive_is_terminal(self):
        finding = _finding(Status.FALSE_POSITIVE)
        self.assertFalse(lifecycle.transition(
            finding, Status.VERIFIED, actor="x", rationale="r"))
        self.assertEqual(finding.status, Status.FALSE_POSITIVE)

    def test_verification_dict_updated_on_apply(self):
        finding = _finding()
        lifecycle.transition(finding, Status.VERIFIED, actor="hdr", method="active_probe",
                             probe="security-headers", result="confirmed", rationale="absent")
        self.assertEqual(finding.verification["method"], "active_probe")
        self.assertEqual(finding.verification["result"], "confirmed")
        self.assertEqual(finding.verification["probe"], "security-headers")

    def test_self_transition_allowed_for_annotation(self):
        finding = _finding(Status.CORRELATED)
        self.assertTrue(lifecycle.transition(
            finding, Status.CORRELATED, actor="dep", method="dependency-reachability",
            result="inconclusive", rationale="reachable"))
        self.assertEqual(finding.status, Status.CORRELATED)


if __name__ == "__main__":
    unittest.main()
