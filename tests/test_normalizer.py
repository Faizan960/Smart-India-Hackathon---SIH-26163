"""Tests for raw-output normalization and deterministic ID assignment."""
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.normalizer import assign_ids, normalize, normalize_semgrep  # noqa: E402
from model.finding import AssetKind, Finding, Severity, Status  # noqa: E402


def fake_semgrep(results):
    return types.SimpleNamespace(parsed={"results": results})


SAMPLE_RESULT = {
    "check_id": "python.lang.security.audit.dangerous-eval",
    "path": "repo/api/auth/login.py",
    "start": {"line": 42},
    "extra": {
        "severity": "ERROR",
        "message": "Use of eval() is dangerous.",
        "metadata": {"cwe": ["CWE-95: Eval Injection"], "references": ["https://example.com/eval"]},
    },
}


class TestNormalizeSemgrep(unittest.TestCase):
    def test_maps_fields_faithfully(self):
        findings = normalize_semgrep(fake_semgrep([SAMPLE_RESULT]), repo_path="repo")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.tool, "semgrep")
        self.assertEqual(f.severity, Severity.HIGH)       # ERROR -> high
        self.assertEqual(f.status, Status.SUSPECTED)
        self.assertEqual(f.cwe, "CWE-95")
        self.assertEqual(f.file, "api/auth/login.py")     # relativized to repo
        self.assertEqual(f.line, 42)
        self.assertEqual(f.asset["kind"], AssetKind.AUTHENTICATION)
        self.assertIn("https://example.com/eval", f.references)

    def test_missing_cwe_stays_none(self):
        result = dict(SAMPLE_RESULT, extra={"severity": "WARNING", "message": "x", "metadata": {}})
        f = normalize_semgrep(fake_semgrep([result]), repo_path="repo")[0]
        self.assertIsNone(f.cwe)
        self.assertEqual(f.severity, Severity.MEDIUM)      # WARNING -> medium

    def test_empty_or_missing_parsed_is_empty(self):
        self.assertEqual(normalize_semgrep(None), [])
        self.assertEqual(normalize_semgrep(types.SimpleNamespace(parsed=None)), [])


class TestAssignIds(unittest.TestCase):
    def test_ids_are_sequential_and_prefixed(self):
        findings = [
            Finding(tool="semgrep", title="a", description="d", file="a.py", line=1),
            Finding(tool="semgrep", title="b", description="d", file="b.py", line=2),
        ]
        assign_ids(findings)
        ids = sorted(f.id for f in findings)
        self.assertEqual(ids, ["WT-SEM-0001", "WT-SEM-0002"])
        for f in findings:
            self.assertEqual(f.evidence["fingerprint"], f.fingerprint())

    def test_normalize_assigns_ids(self):
        findings = normalize(semgrep_result=fake_semgrep([SAMPLE_RESULT]), repo_path="repo")
        self.assertEqual(findings[0].id, "WT-SEM-0001")


if __name__ == "__main__":
    unittest.main()
