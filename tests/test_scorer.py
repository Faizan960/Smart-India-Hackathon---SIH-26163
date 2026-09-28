"""Tests for the WATCHTOWER Risk Score (explicitly not CVSS)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.scorer import SCORE_CAP, score_finding  # noqa: E402
from model.finding import AssetKind, Finding, Severity, Status  # noqa: E402


def make(severity, status, asset_kind=AssetKind.OTHER):
    return Finding(
        tool="semgrep",
        title="t",
        description="d",
        severity=severity,
        status=status,
        asset={"kind": asset_kind, "ref": None, "weight": 1.0},
    )


class TestScorer(unittest.TestCase):
    def test_high_suspected_api(self):
        f = score_finding(make(Severity.HIGH, Status.SUSPECTED, AssetKind.API))
        self.assertAlmostEqual(f.score["value"], 9.6)   # 8 * 1.0 * 1.2
        self.assertFalse(f.score["capped"])

    def test_low_verified_ui(self):
        f = score_finding(make(Severity.LOW, Status.VERIFIED, AssetKind.UI))
        self.assertAlmostEqual(f.score["value"], 3.0)   # 2 * 1.5 * 1.0

    def test_critical_verified_auth_is_capped(self):
        f = score_finding(make(Severity.CRITICAL, Status.VERIFIED, AssetKind.AUTHENTICATION))
        # 10 * 1.5 * 1.5 = 22.5 -> capped at 10.0
        self.assertEqual(f.score["value"], SCORE_CAP)
        self.assertTrue(f.score["capped"])

    def test_false_positive_scores_zero(self):
        f = score_finding(make(Severity.CRITICAL, Status.FALSE_POSITIVE, AssetKind.AUTHENTICATION))
        self.assertEqual(f.score["value"], 0.0)

    def test_info_scores_zero(self):
        f = score_finding(make(Severity.INFO, Status.VERIFIED, AssetKind.API_KEY))
        self.assertEqual(f.score["value"], 0.0)

    def test_asset_weight_is_recorded(self):
        f = score_finding(make(Severity.MEDIUM, Status.SUSPECTED, AssetKind.MCP))
        self.assertEqual(f.asset["weight"], 1.5)
        self.assertEqual(f.score["factors"]["asset_multiplier"], 1.5)


if __name__ == "__main__":
    unittest.main()
