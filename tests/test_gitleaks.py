"""Tests for the Gitleaks adapter and normalizer — synthetic output only.

Critically verifies that secret VALUES never survive into parsed output, evidence,
or the normalized Finding (redaction), and that severity is taken from metadata and
not invented.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import normalizer  # noqa: E402
from model.finding import Severity, Status  # noqa: E402
from scanners import gitleaks  # noqa: E402
from scanners.base import CollectorResult  # noqa: E402

SECRET = "AKIAIOSFODNN7EXAMPLE"
_ENTRY = {
    "RuleID": "aws-access-token",
    "Description": "AWS Access Token",
    "File": "src/config/keys.js",
    "StartLine": 12,
    "Secret": SECRET,
    "Match": f"aws_key = {SECRET}",
    "Tags": ["key", "AWS"],
    "Entropy": 3.5,
    "Commit": "",
}


def _result(entries):
    # Mimics what the adapter returns: entries are already redacted.
    parsed = gitleaks.redact_output(entries)
    return CollectorResult(tool="gitleaks", parsed=parsed, raw=json.dumps(parsed))


class TestGitleaksRedaction(unittest.TestCase):
    def test_redact_entry_masks_secret_and_match(self):
        red = gitleaks.redact_entry(_ENTRY)
        self.assertEqual(red["Secret"], "[REDACTED]")
        self.assertEqual(red["Match"], "[REDACTED]")
        self.assertEqual(red["SecretLength"], len(SECRET))

    def test_parse_output_redacts(self):
        text = json.dumps([_ENTRY])
        parsed = gitleaks.parse_output(text)
        self.assertNotIn(SECRET, json.dumps(parsed))

    def test_secret_never_reaches_finding(self):
        findings = normalizer.normalize_gitleaks(_result([_ENTRY]), repo_path="src")
        self.assertEqual(len(findings), 1)
        blob = json.dumps(findings[0].to_dict())
        self.assertNotIn(SECRET, blob)
        self.assertEqual(findings[0].evidence["match"], "[REDACTED]")
        self.assertEqual(findings[0].evidence["secret_length"], len(SECRET))


class TestGitleaksNormalize(unittest.TestCase):
    def test_severity_unspecified_by_default(self):
        findings = normalizer.normalize_gitleaks(_result([_ENTRY]))
        self.assertEqual(findings[0].severity, Severity.INFO)
        self.assertEqual(findings[0].evidence["severity_source"], "unspecified-by-tool")
        self.assertEqual(findings[0].status, Status.SUSPECTED)

    def test_severity_from_tag_metadata(self):
        entry = dict(_ENTRY, Tags=["severity:high"])
        findings = normalizer.normalize_gitleaks(_result([entry]))
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertEqual(findings[0].evidence["severity_source"], "gitleaks-tag")

    def test_missing_optional_fields(self):
        findings = normalizer.normalize_gitleaks(_result([{"RuleID": "generic"}]))
        self.assertEqual(len(findings), 1)
        self.assertIsNone(findings[0].line)

    def test_empty_and_none(self):
        self.assertEqual(normalizer.normalize_gitleaks(_result([])), [])
        self.assertEqual(normalizer.normalize_gitleaks(CollectorResult(tool="gitleaks", parsed=None)), [])


class TestGitleaksParsing(unittest.TestCase):
    def test_empty_text_is_no_findings(self):
        self.assertEqual(gitleaks.parse_output(""), [])
        self.assertEqual(gitleaks.parse_output("[]"), [])

    def test_malformed_json_raises(self):
        with self.assertRaises(json.JSONDecodeError):
            gitleaks.parse_output("{not json")

    def test_non_list_raises(self):
        with self.assertRaises(ValueError):
            gitleaks.parse_output('{"a": 1}')

    def test_unavailable_is_skipped(self):
        original = gitleaks.gitleaks_available
        gitleaks.gitleaks_available = lambda: False
        try:
            result = gitleaks.run_gitleaks("/nonexistent", timeout=5)
        finally:
            gitleaks.gitleaks_available = original
        self.assertTrue(result.skipped)
        self.assertFalse(result.available)
        self.assertIsNotNone(result.error)


if __name__ == "__main__":
    unittest.main()
