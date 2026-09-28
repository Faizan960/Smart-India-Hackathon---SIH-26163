"""Tests for the Nuclei adapter and normalizer — synthetic output only.

Verifies JSONL parsing (including partial/garbage lines), severity mapping, CWE/CVE
extraction, that the command line is the controlled non-destructive one, and that a
template match is recorded as suspected rather than auto-verified.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import normalizer  # noqa: E402
from model.finding import AssetKind, Severity, Status  # noqa: E402
from scanners import nuclei  # noqa: E402
from scanners.base import CollectorResult  # noqa: E402

_ITEM = {
    "template-id": "CVE-2021-1234-detect",
    "info": {
        "name": "Example Disclosure",
        "severity": "high",
        "description": "An example information disclosure detected by a template.",
        "reference": ["https://example.test/advisory"],
        "classification": {"cwe-id": ["CWE-200"], "cve-id": ["CVE-2021-1234"]},
        "tags": ["exposure", "misconfig"],
    },
    "type": "http",
    "host": "http://localhost:3000",
    "matched-at": "http://localhost:3000/api/status",
    "matcher-name": "body",
}


def _result(items):
    return CollectorResult(tool="nuclei", parsed=items, raw="")


class TestNucleiNormalize(unittest.TestCase):
    def test_maps_finding(self):
        f = normalizer.normalize_nuclei(_result([_ITEM]))[0]
        self.assertEqual(f.tool, "nuclei")
        self.assertEqual(f.severity, Severity.HIGH)
        self.assertEqual(f.status, Status.SUSPECTED)  # scanner rating, not verified
        self.assertEqual(f.cwe, "CWE-200")
        self.assertEqual(f.endpoint, "http://localhost:3000/api/status")
        self.assertEqual(f.asset["kind"], AssetKind.API)

    def test_preserves_identifiers_and_metadata(self):
        f = normalizer.normalize_nuclei(_result([_ITEM]))[0]
        self.assertIn("CVE-2021-1234", f.evidence["identifiers"])
        self.assertEqual(f.evidence["template_id"], "CVE-2021-1234-detect")
        self.assertEqual(f.evidence["severity_source"], "nuclei-template")
        self.assertEqual(f.evidence["raw_severity"], "high")

    def test_severity_mapping(self):
        for level, expected in (("critical", Severity.CRITICAL), ("high", Severity.HIGH),
                                ("medium", Severity.MEDIUM), ("low", Severity.LOW),
                                ("info", Severity.INFO), ("unknown", Severity.INFO)):
            item = json.loads(json.dumps(_ITEM))
            item["info"]["severity"] = level
            f = normalizer.normalize_nuclei(_result([item]))[0]
            self.assertEqual(f.severity, expected, level)

    def test_empty(self):
        self.assertEqual(normalizer.normalize_nuclei(_result([])), [])
        self.assertEqual(normalizer.normalize_nuclei(CollectorResult(tool="nuclei", parsed=None)), [])


class TestNucleiParsing(unittest.TestCase):
    def test_empty_text(self):
        self.assertEqual(nuclei.parse_output(""), [])

    def test_valid_jsonl(self):
        text = "\n".join(json.dumps(_ITEM) for _ in range(2))
        self.assertEqual(len(nuclei.parse_output(text)), 2)

    def test_skips_garbage_lines_but_keeps_valid(self):
        text = json.dumps(_ITEM) + "\ngarbage not json\n"
        parsed = nuclei.parse_output(text)
        self.assertEqual(len(parsed), 1)

    def test_all_garbage_raises(self):
        with self.assertRaises(ValueError):
            nuclei.parse_output("not json\nstill not json")

    def test_command_is_controlled_and_nondestructive(self):
        cmd = nuclei.build_command("http://localhost:3000")
        self.assertEqual(cmd[0], "nuclei")
        self.assertIn("-u", cmd)
        self.assertIn("http://localhost:3000", cmd)
        self.assertIn("-no-interactsh", cmd)  # no third-party OOB infra
        self.assertIn("-exclude-tags", cmd)
        excluded = cmd[cmd.index("-exclude-tags") + 1]
        for tag in ("dos", "intrusive", "fuzz", "brute-force"):
            self.assertIn(tag, excluded)
        self.assertIn("-rate-limit", cmd)

    def test_unavailable_is_skipped(self):
        original = nuclei.nuclei_available
        nuclei.nuclei_available = lambda: False
        try:
            result = nuclei.run_nuclei("http://localhost:3000", timeout=5)
        finally:
            nuclei.nuclei_available = original
        self.assertTrue(result.skipped)
        self.assertFalse(result.available)


if __name__ == "__main__":
    unittest.main()
