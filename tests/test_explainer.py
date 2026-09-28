"""Tests for the explanation engine and evidence-confidence rating (Phase 5, items 5-6)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import explainer  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402


def _f(tool, status, *, result=None, method=None, evidence=None, severity=Severity.INFO,
       rationale="", fix=None, fid="WT-X-0001"):
    verification = {}
    if method:
        verification = {"method": method, "result": result, "rationale": rationale,
                        "probe": tool}
    return Finding(tool=tool, title=f"{tool} finding", description="detected something",
                   severity=severity, status=status, id=fid, endpoint="http://localhost:3000/",
                   evidence=evidence or {}, verification=verification, fix=fix)


class TestEvidenceConfidence(unittest.TestCase):
    def test_confirmed_probe_is_high(self):
        f = _f("cors", Status.VERIFIED, result="confirmed", method="active_probe")
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_HIGH)

    def test_refuted_probe_is_high(self):
        f = _f("ssrf", Status.FALSE_POSITIVE, result="refuted", method="active_probe")
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_HIGH)

    def test_not_applicable_is_high(self):
        f = _f("security-headers", Status.FALSE_POSITIVE, result="not_applicable",
               method="header_probe")
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_HIGH)

    def test_inconclusive_probe_is_medium(self):
        f = _f("auth-mcp", Status.NEEDS_MANUAL_REVIEW, result="inconclusive",
               method="active_probe")
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_MEDIUM)

    def test_correlated_is_medium(self):
        f = _f("semgrep", Status.CORRELATED)
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_MEDIUM)

    def test_reachability_analysis_is_medium(self):
        f = _f("npm-audit", Status.NEEDS_MANUAL_REVIEW,
               evidence={"dependency_type": "prod", "reachability_reason": "transitive"})
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_MEDIUM)

    def test_suspected_single_source_is_low(self):
        f = _f("semgrep", Status.SUSPECTED)
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_LOW)

    def test_confidence_is_not_severity(self):
        # High severity + no verification must still be LOW confidence.
        f = _f("semgrep", Status.SUSPECTED, severity=Severity.CRITICAL)
        self.assertEqual(explainer.evidence_confidence(f), explainer.CONFIDENCE_LOW)

    def test_confidence_counts(self):
        findings = [
            _f("cors", Status.VERIFIED, result="confirmed", method="active_probe", fid="a"),
            _f("auth-mcp", Status.NEEDS_MANUAL_REVIEW, result="inconclusive",
               method="active_probe", fid="b"),
            _f("semgrep", Status.SUSPECTED, fid="c"),
        ]
        counts = explainer.confidence_counts(findings)
        self.assertEqual(counts, {"high": 1, "medium": 1, "low": 1})


class TestExplain(unittest.TestCase):
    def test_explanation_has_all_required_sections(self):
        f = _f("security-headers", Status.VERIFIED, result="confirmed",
               method="header_probe", rationale="header absent")
        ex = explainer.explain(f)
        for key in ("what_was_detected", "why_it_matters", "evidence",
                    "verification_performed", "result", "lifecycle_status",
                    "what_was_not_tested", "limitation", "guidance", "evidence_confidence"):
            self.assertIn(key, ex)

    def test_unverified_finding_says_not_verified(self):
        ex = explainer.explain(_f("semgrep", Status.SUSPECTED))
        self.assertEqual(ex["result"], "not verified")
        self.assertIn("not been verified", ex["verification_performed"])

    def test_dev_runtime_limitation_surfaced(self):
        f = _f("auth-mcp", Status.NEEDS_MANUAL_REVIEW, result="inconclusive",
               method="active_probe",
               rationale="route 404 under development runtime; production surface not exercised")
        ex = explainer.explain(f)
        self.assertIn("production", ex["what_was_not_tested"].lower())

    def test_guidance_prefers_fix(self):
        ex = explainer.explain(_f("cors", Status.VERIFIED, result="confirmed",
                                  method="active_probe", fix="Restrict Access-Control-Allow-Origin"))
        self.assertIn("Restrict", ex["guidance"])

    def test_why_it_matters_is_hardening_framed_not_exploit_claim(self):
        ex = explainer.explain(_f("security-headers", Status.VERIFIED, result="confirmed",
                                  method="header_probe"))
        self.assertIn("not a demonstrated exploit", ex["why_it_matters"])

    def test_explain_all_keyed_by_id(self):
        findings = [_f("cors", Status.VERIFIED, result="confirmed", method="active_probe",
                       fid="WT-CORS-0001"),
                    _f("ssrf", Status.FALSE_POSITIVE, result="refuted", method="active_probe",
                       fid="WT-SSRF-0001")]
        allex = explainer.explain_all(findings)
        self.assertEqual(set(allex), {"WT-CORS-0001", "WT-SSRF-0001"})


if __name__ == "__main__":
    unittest.main()

