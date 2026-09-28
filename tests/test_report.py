"""Tests for report assembly and safe HTML rendering."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.baseline import build_baseline  # noqa: E402
from engine.correlator import correlate  # noqa: E402
from engine.diff import diff_reports  # noqa: E402
from engine.gate import evaluate_gate  # noqa: E402
from engine.scorer import score_all  # noqa: E402
from model.finding import AssetKind, Finding, Severity, Status  # noqa: E402
from reports.html_report import render_html  # noqa: E402
from reports.json_report import build_report  # noqa: E402


def sample_findings():
    findings = [
        Finding(tool="semgrep", title="eval injection", description="d",
                severity=Severity.HIGH, status=Status.SUSPECTED, file="api/x.py", line=3,
                asset={"kind": AssetKind.API, "ref": "api/x.py", "weight": 1.0}),
        Finding(tool="security-headers", title="CSP assessment", description="d",
                severity=Severity.INFO, status=Status.VERIFIED, endpoint="http://localhost:3000/",
                asset={"kind": AssetKind.UI, "ref": "http://localhost:3000/", "weight": 1.0}),
    ]
    return score_all(findings)


def probe_findings():
    """Active-probe findings carrying explicit verification results (Phase 4)."""
    def _probe(tool, status, result, severity=Severity.INFO):
        return Finding(tool=tool, title=f"{tool} probe", description="d",
                       severity=severity, status=status,
                       endpoint="http://localhost:3000/",
                       verification={"method": "active_probe", "probe": tool,
                                     "result": result, "rationale": "r", "timestamp": "t"})
    findings = [
        _probe("cors", Status.VERIFIED, "confirmed", Severity.HIGH),
        _probe("rate-limit", Status.NEEDS_MANUAL_REVIEW, "inconclusive", Severity.LOW),
        _probe("auth-mcp", Status.FALSE_POSITIVE, "refuted"),
        _probe("ssrf", Status.FALSE_POSITIVE, "refuted"),
    ]
    return score_all(findings)


SCAN = {"timestamp": "t", "target": "http://localhost:3000", "repository": "repo",
        "commit": "abc", "branch": "main"}


class TestReport(unittest.TestCase):
    def test_summary_counts_match_findings(self):
        report = build_report(sample_findings(), SCAN, "0.1.0")
        self.assertEqual(report["summary"]["total_findings"], 2)
        self.assertEqual(report["summary"]["high"], 1)
        self.assertEqual(report["summary"]["info"], 1)

    def test_verification_result_and_probe_counts(self):
        report = build_report(probe_findings(), SCAN, "0.1.0")
        vr = report["summary"]["verification_results"]
        self.assertEqual(vr["confirmed"], 1)
        self.assertEqual(vr["refuted"], 2)
        self.assertEqual(vr["inconclusive"], 1)
        self.assertEqual(vr["not_applicable"], 0)
        self.assertEqual(report["summary"]["active_probe_findings"], 4)

    def test_html_shows_active_verification_section(self):
        html = render_html(build_report(probe_findings(), SCAN, "0.1.0"))
        self.assertIn("Active verification", html)
        self.assertIn("confirmed", html)

    def test_html_renders_with_findings(self):
        html = render_html(build_report(sample_findings(), SCAN, "0.1.0"))
        self.assertIn("WATCHTOWER", html)
        self.assertIn("eval injection", html)

    def test_html_autoescapes_finding_text(self):
        evil = Finding(tool="semgrep", title="<script>alert(1)</script>", description="d",
                       severity=Severity.LOW, status=Status.SUSPECTED)
        html = render_html(build_report(score_all([evil]), SCAN, "0.1.0"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_reports_empty_findings_honestly(self):
        html = render_html(build_report([], SCAN, "0.1.0"))
        self.assertIn("No findings were produced", html)

    def test_correlation_terminology_counts_are_distinct(self):
        # correlation_groups_count (clusters) and findings_currently_correlated (lifecycle
        # status) are separate keys and must not be conflated.
        pair = [Finding(tool="semgrep", title="xss", description="d", severity=Severity.HIGH,
                        status=Status.SUSPECTED, cwe="CWE-79",
                        endpoint="http://localhost:3000/x"),
                Finding(tool="zap", title="xss", description="d", severity=Severity.HIGH,
                        status=Status.SUSPECTED, cwe="CWE-79",
                        endpoint="http://localhost:3000/x")]
        correlate(pair)                          # 1 group, both members -> correlated status
        report = build_report(score_all(pair), SCAN, "0.1.0")
        self.assertEqual(report["summary"]["correlation_groups_count"], 1)
        self.assertEqual(report["summary"]["findings_currently_correlated"], 2)

    def test_html_renders_correlation_group_shared_keys(self):
        # Regression: a correlation-group dict has a "keys" field; the template must render
        # the shared keys (item access), not the dict.keys builtin — which raised
        # "'builtin_function_or_method' object is not iterable" during join.
        shared = [Finding(tool="semgrep", title="xss", description="d", severity=Severity.HIGH,
                          status=Status.SUSPECTED, cwe="CWE-79",
                          endpoint="http://localhost:3000/x"),
                  Finding(tool="zap", title="xss", description="d", severity=Severity.HIGH,
                          status=Status.SUSPECTED, cwe="CWE-79",
                          endpoint="http://localhost:3000/x")]
        correlate(shared)                       # populates correlation evidence
        report = build_report(score_all(shared), SCAN, "0.1.0")
        self.assertTrue(report["correlation_groups"])
        html = render_html(report)              # must not raise
        self.assertIn("Correlation groups", html)
        self.assertIn("cwe@ep:CWE-79", html)    # the shared key is actually rendered


def _surface():
    return AttackSurface(
        endpoints=[
            Endpoint(path="/api/health", methods=["GET"], source_file="api/health.ts",
                     component="core", authentication="public"),
            Endpoint(path="/api/rss-proxy", methods=["GET"], source_file="api/rss-proxy.ts",
                     component="proxy", authentication=None,
                     risk_tags=["ssrf_candidate", "external_fetch"]),
        ],
        integrations=[{"name": "Clerk", "kind": "auth", "evidence": {}}],
        env_references=["UPSTASH_REDIS_REST_URL"],
        notes=["Attack-surface discovery is static and read-only."],
    )


_ENV = {"assessment_id": "run-abc123", "timestamp": "t", "target": "http://localhost:3000",
        "repository": "repo", "commit": "abc", "branch": "main", "watchtower_version": "0.1.0",
        "python_version": "3.14.0", "platform": "TestPlatform-1.0",
        "probe_versions": {"ssrf": "1", "cors": "1"},
        "scanner_versions": {"semgrep": None}, "scanner_version_note": "not collected"}

_EXEC = [{"tool": "semgrep", "status": "skipped", "duration_seconds": 0.0,
          "exit_code": None, "finding_count": 0, "error": "not installed"}]


class TestHtmlDashboard(unittest.TestCase):
    """Phase 5, item 11 — the upgraded HTML dashboard sections and client-side filters."""

    def setUp(self):
        report = build_report(sample_findings(), SCAN, "0.1.0", execution=_EXEC,
                              attack_surface=_surface(), environment=_ENV,
                              assessment_id="run-abc123")
        self.html = render_html(report)

    def test_reproducibility_section_rendered(self):
        self.assertIn("Reproducibility", self.html)
        self.assertIn("run-abc123", self.html)      # assessment id
        self.assertIn("3.14.0", self.html)          # python version
        self.assertIn("TestPlatform-1.0", self.html)

    def test_attack_surface_section_and_disclaimer(self):
        self.assertIn("Attack surface (static discovery)", self.html)
        self.assertIn("/api/rss-proxy", self.html)
        self.assertIn("ssrf_candidate", self.html)
        # The spec-mandated disclaimer keeps attack-surface entries distinct from findings.
        self.assertIn("NOT", self.html)
        self.assertIn("vulnerabilities", self.html)

    def test_evidence_confidence_summary_and_pill(self):
        self.assertIn("Evidence confidence", self.html)
        self.assertIn("Confidence: high", self.html)
        self.assertIn("confidence:", self.html)     # per-finding pill in the detail cards

    def test_assessment_limitations_section(self):
        self.assertIn("Assessment limitations", self.html)
        # A risk-tagged endpoint no probe exercised must be surfaced as an untested path.
        self.assertIn("/api/rss-proxy", self.html)
        self.assertIn("semgrep", self.html)          # skipped scanner reported honestly

    def test_filter_controls_present(self):
        for fid in ("f-severity", "f-status", "f-confidence", "f-component", "f-tool", "f-probe"):
            self.assertIn(fid, self.html)
        self.assertIn('class="finding-row filterable"', self.html)
        self.assertIn("data-confidence=", self.html)

    def test_evidence_chain_rendered(self):
        # Every finding exposes its evidence chain; relationships are rendered as labels.
        self.assertIn("discovered by", self.html)

    def test_dashboard_still_autoescapes(self):
        evil = Finding(tool="semgrep", title="<script>alert(1)</script>", description="d",
                       severity=Severity.HIGH, status=Status.SUSPECTED, file="api/x.py", line=1)
        html = render_html(build_report(score_all([evil]), SCAN, "0.1.0",
                                        attack_surface=_surface(), environment=_ENV))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


# --- Phase 6, Step 5: versioned machine-readable report (additive diff + gate sections) ---

_1_1_FIELDS = ("assessment", "environment", "scan", "execution", "summary", "attack_surface",
               "assessment_limitations", "duplicate_groups", "correlation_groups",
               "evidence_graph", "findings")

_DIFF_FIELDS = ("new_findings", "resolved_findings", "unchanged_findings", "status_changes",
                "severity_changes", "verification_changes", "score_changes",
                "attack_surface_additions", "attack_surface_removals", "counts",
                "baseline", "current", "note")


def _prior_findings():
    return score_all([Finding(tool="semgrep", title="eval", description="d", severity=Severity.HIGH,
                              status=Status.SUSPECTED, file="a.ts", line=1)])


def _current_findings():
    # Same fingerprint as the prior finding, now VERIFIED -> a newly verified regression.
    return score_all([Finding(tool="semgrep", title="eval", description="d", severity=Severity.HIGH,
                              status=Status.VERIFIED, file="a.ts", line=1)])


class TestVersionedReport(unittest.TestCase):
    """Schema 1.2 embeds the STEP-3 diff and STEP-4 gate, reusing both engines verbatim."""

    def setUp(self):
        self.baseline = build_baseline(build_report(_prior_findings(), SCAN, "0.1.0"))
        self.report = build_report(_current_findings(), SCAN, "0.1.0", baseline=self.baseline)
        self.no_baseline = build_report(_current_findings(), SCAN, "0.1.0")

    def test_report_schema_version_is_1_2(self):
        self.assertEqual(self.report["schema_version"], "1.2")
        self.assertEqual(self.no_baseline["schema_version"], "1.2")

    def test_report_preserves_existing_1_1_fields(self):
        # Additive change: every field a 1.1 consumer relied on is still present.
        for field in _1_1_FIELDS:
            self.assertIn(field, self.report)
            self.assertIn(field, self.no_baseline)

    def test_report_contains_diff_when_available(self):
        diff = self.report["diff"]
        self.assertIsInstance(diff, dict)
        for field in _DIFF_FIELDS:
            self.assertIn(field, diff)
        self.assertIn("Causality is NOT inferred", diff["note"])

    def test_report_diff_is_null_without_baseline(self):
        self.assertIsNone(self.no_baseline["diff"])

    def test_report_has_no_fabricated_diff_without_baseline(self):
        # NO BASELINE != NO CHANGES: the diff is null, and the gate makes no historical claim.
        self.assertIsNone(self.no_baseline["diff"])
        self.assertFalse(self.no_baseline["gate"]["baseline_aware"])
        self.assertEqual(self.no_baseline["gate"]["counts"]["new_verified"], 0)

    def test_report_contains_gate(self):
        # The gate is present in BOTH the baseline-aware and the no-baseline report.
        self.assertIsInstance(self.report["gate"], dict)
        self.assertIsInstance(self.no_baseline["gate"], dict)

    def test_report_gate_is_structured(self):
        gate = self.report["gate"]
        self.assertEqual(set(gate), {"result", "policy", "baseline_aware", "reasons", "counts"})
        self.assertIn(gate["result"], {"PASS", "WARN", "FAIL"})
        self.assertEqual(gate["policy"], "watchtower-gate-v1")
        self.assertIsInstance(gate["reasons"], list)   # structured, not a text blob

    def test_report_gate_matches_gate_engine(self):
        # The embedded gate is exactly what the gate engine yields for this report + diff.
        self.assertEqual(self.report["gate"], evaluate_gate(self.report, self.report["diff"]))
        self.assertEqual(self.no_baseline["gate"], evaluate_gate(self.no_baseline, None))
        # And the baseline-aware gate caught the newly verified finding.
        self.assertTrue(self.report["gate"]["baseline_aware"])
        self.assertEqual(self.report["gate"]["counts"]["new_verified"], 1)
        self.assertEqual(self.report["gate"]["result"], "FAIL")

    def test_report_diff_matches_diff_engine(self):
        # The embedded diff is exactly engine.diff.diff_reports(baseline, report).
        self.assertEqual(self.report["diff"], diff_reports(self.baseline, self.report))

    def test_report_is_json_serializable(self):
        for report in (self.report, self.no_baseline):
            blob = json.dumps(report)                      # must not raise
            self.assertEqual(json.loads(blob), report)     # round-trips exactly

    def test_report_new_sections_are_deterministic(self):
        again = build_report(_current_findings(), SCAN, "0.1.0", baseline=self.baseline)
        self.assertEqual(again["diff"], self.report["diff"])
        self.assertEqual(again["gate"], self.report["gate"])
        self.assertEqual(json.dumps(again["diff"], sort_keys=True),
                         json.dumps(self.report["diff"], sort_keys=True))
        self.assertEqual(json.dumps(again["gate"], sort_keys=True),
                         json.dumps(self.report["gate"], sort_keys=True))

    def test_report_contains_no_secret_values(self):
        # A secret buried in raw evidence must never surface in the NEW diff/gate sections
        # (the diff briefs drop raw evidence; the gate carries only counts and reasons).
        secret = "AKIA-SECRET-DO-NOT-LEAK-EXAMPLE"
        prior = score_all([Finding(tool="gitleaks", title="key", description="d",
                                   severity=Severity.HIGH, status=Status.SUSPECTED, file="s.env",
                                   line=1, evidence={"rule": "aws", "raw": secret})])
        current = score_all([Finding(tool="gitleaks", title="key", description="d",
                                     severity=Severity.HIGH, status=Status.VERIFIED, file="s.env",
                                     line=1, evidence={"rule": "aws", "raw": secret})])
        baseline = build_baseline(build_report(prior, SCAN, "0.1.0"))
        report = build_report(current, SCAN, "0.1.0", baseline=baseline)
        self.assertNotIn(secret, json.dumps(report["diff"]))
        self.assertNotIn(secret, json.dumps(report["gate"]))


if __name__ == "__main__":
    unittest.main()
