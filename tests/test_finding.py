"""Tests for the normalized Finding model."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.finding import AssetKind, Finding, Severity, Status  # noqa: E402


class TestFinding(unittest.TestCase):
    def _make(self, **kwargs):
        base = dict(tool="semgrep", title="t", description="d")
        base.update(kwargs)
        return Finding(**base)

    def test_defaults(self):
        f = self._make()
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.status, Status.SUSPECTED)
        self.assertIsNone(f.id)
        self.assertIsNone(f.cwe)
        self.assertEqual(f.asset["kind"], AssetKind.OTHER)
        self.assertEqual(f.references, [])

    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            self._make(severity="catastrophic")

    def test_invalid_status_rejected(self):
        with self.assertRaises(ValueError):
            self._make(status="confirmed")  # 'confirmed' is intentionally not a status

    def test_to_dict_roundtrip_keys(self):
        d = self._make(severity=Severity.HIGH).to_dict()
        for key in ("id", "tool", "title", "severity", "status", "evidence", "score"):
            self.assertIn(key, d)
        self.assertEqual(d["severity"], "high")

    def test_fingerprint_is_stable_hex(self):
        f1 = self._make(file="a.py", line=10, evidence={"rule": "r1"})
        f2 = self._make(file="a.py", line=10, evidence={"rule": "r1"})
        self.assertEqual(f1.fingerprint(), f2.fingerprint())
        self.assertEqual(len(f1.fingerprint()), 16)
        f3 = self._make(file="a.py", line=11, evidence={"rule": "r1"})
        self.assertNotEqual(f1.fingerprint(), f3.fingerprint())


if __name__ == "__main__":
    unittest.main()
