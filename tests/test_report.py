"""Tests for report assembly and safe HTML rendering."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.correlator import correlate  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
