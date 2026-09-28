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


class TestResultToStatusMapping(unittest.TestCase):
    """PART 0: the verification result and the lifecycle status are separate concepts,
    joined only by this fixed mapping. A probe can never bypass it."""

    def test_status_for_result_mapping(self):
        self.assertEqual(lifecycle.status_for_result(lifecycle.CONFIRMED), Status.VERIFIED)
        self.assertEqual(lifecycle.status_for_result(lifecycle.INCONCLUSIVE),
                         Status.NEEDS_MANUAL_REVIEW)
        self.assertEqual(lifecycle.status_for_result(lifecycle.REFUTED), Status.FALSE_POSITIVE)
        self.assertEqual(lifecycle.status_for_result(lifecycle.NOT_APPLICABLE),
                         Status.FALSE_POSITIVE)

    def test_unknown_result_rejected(self):
        with self.assertRaises(ValueError):
            lifecycle.status_for_result("definitely-not-a-result")

    def test_confirmed_maps_to_verified(self):
        finding = _finding()
        self.assertTrue(lifecycle.apply_verification(
            finding, result=lifecycle.CONFIRMED, actor="probe", method="active_probe",
            probe="cors", rationale="demonstrated"))
        self.assertEqual(finding.status, Status.VERIFIED)
        self.assertEqual(finding.verification["result"], "confirmed")

    def test_refuted_maps_to_false_positive_never_verified(self):
        finding = _finding()
        self.assertTrue(lifecycle.apply_verification(
            finding, result=lifecycle.REFUTED, actor="probe", method="active_probe",
            probe="security-headers", rationale="present"))
        self.assertEqual(finding.status, Status.FALSE_POSITIVE)
        self.assertEqual(finding.verification["result"], "refuted")

    def test_not_applicable_maps_to_false_positive(self):
        finding = _finding()
        self.assertTrue(lifecycle.apply_verification(
            finding, result=lifecycle.NOT_APPLICABLE, actor="probe", method="active_probe",
            probe="security-headers", rationale="hsts on loopback http"))
        self.assertEqual(finding.status, Status.FALSE_POSITIVE)
        self.assertEqual(finding.verification["result"], "not_applicable")

    def test_inconclusive_maps_to_needs_manual_review(self):
        finding = _finding()
        self.assertTrue(lifecycle.apply_verification(
            finding, result=lifecycle.INCONCLUSIVE, actor="probe", method="active_probe",
            probe="rate-limit", rationale="no signal in bounded sample"))
        self.assertEqual(finding.status, Status.NEEDS_MANUAL_REVIEW)
        self.assertEqual(finding.verification["result"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
