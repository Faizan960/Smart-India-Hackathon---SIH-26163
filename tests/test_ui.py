"""Tests for the WATCHTOWER UI surfaces (landing page + SecOps dashboard).

These cover the PRESENTATION layer only: that the surfaces render honestly from a
canonical report, HTML-autoescape tool-controlled text, never fabricate telemetry, keep
the four axes labelled, and show the reserved regression placeholders. They deliberately
do NOT test (or re-implement) any scorer, gate, diff or lifecycle logic — the dashboard
reads report["gate"]/report["summary"] as-is, so the assertions check that the rendered
values match the report rather than recomputing them.
"""
import glob
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.gate import evaluate_gate  # noqa: E402
from engine.scorer import score_all  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402
from reports import dashboard, landing  # noqa: E402
from reports.build_ui import load_report_for_ui  # noqa: E402
from reports.json_report import build_report  # noqa: E402
from reports.ui_theme import LABEL_PLACEHOLDER  # noqa: E402

SCAN = {"timestamp": "2026-09-28T11:10:09Z", "target": "http://localhost:3000",
        "repository": "repo", "commit": "abc", "branch": "main"}

_ENV = {"assessment_id": "run-20260928T111009Z", "timestamp": "2026-09-28T11:11:00Z",
        "target": "http://localhost:3000", "repository": "repo", "commit": "abc",
        "branch": "main", "watchtower_version": "0.1.0", "python_version": "3.14.0",
        "platform": "TestPlatform-1.0", "probe_versions": {"cors": "1"},
        "scanner_versions": {"semgrep": None}, "scanner_version_note": "not collected"}

_EXEC = [{"tool": "npm-audit", "status": "success", "duration_seconds": 0.1,
          "exit_code": 0, "finding_count": 1, "error": None},
         {"tool": "semgrep", "status": "skipped", "duration_seconds": 0.0,
          "exit_code": None, "finding_count": 0, "error": "not installed"}]

# Fabricated claims the spec forbids (§2). Checked case-insensitively; none of these
# may appear in either rendered surface. Distinctive phrases only — no bare numbers,
# which could legitimately occur in scores, counts, fingerprints or timestamps.
FORBIDDEN = ["99.99", "ed25519", "us-east", "live monitoring", "checks/sec",
             "100% verification", "zero false positive", "12/12 verified",
             "82% coverage", "sast", "dast"]


def _findings():
    """Three findings spanning the lifecycle axis; the false positive carries an XSS
    payload as its title and has no endpoint/file (its surface must fall back to NA)."""
    verified = Finding(tool="cors", title="CORS reflects credentialed wildcard origin",
                       description="d", severity=Severity.HIGH, status=Status.VERIFIED,
                       endpoint="http://localhost:3000/api/data",
                       verification={"method": "active_probe", "probe": "cors",
                                     "result": "confirmed", "rationale": "origin reflected",
                                     "timestamp": "t"})
    review = Finding(tool="rate-limit", title="Rate limiting could not be confirmed",
                     description="d", severity=Severity.LOW, status=Status.NEEDS_MANUAL_REVIEW,
                     endpoint="http://localhost:3000/api/login",
                     verification={"method": "active_probe", "probe": "rate-limit",
                                   "result": "inconclusive", "rationale": "no lockout in window",
                                   "timestamp": "t"})
    evil = Finding(tool="npm-audit", title="<script>alert(1)</script>", description="d",
                   severity=Severity.INFO, status=Status.FALSE_POSITIVE,
                   verification={"method": "n/a", "result": "refuted", "rationale": "r",
                                 "timestamp": "t"})
    return score_all([verified, review, evil])


def _surface_fixture():
    return AttackSurface(
        endpoints=[Endpoint(path="/api/data", methods=["GET"], source_file="api/data.ts",
                            component="core", authentication="public",
                            risk_tags=["rpc", "rate_limit_candidate"]),
                   Endpoint(path="/api/rss-proxy", methods=["GET"], source_file="api/rss.ts",
                            component="proxy", authentication=None,
                            risk_tags=["ssrf_candidate", "external_fetch"])],
        integrations=[{"name": "Clerk", "kind": "auth", "evidence": {}}],
        env_references=["UPSTASH_REDIS_REST_URL"],
        notes=["Attack-surface discovery is static and read-only."])


def _report():
    """A schema-1.2 display report: build the canonical 1.1 report, then attach the REAL
    gate and diff=None exactly as reports.build_ui does (no re-scan, no fabrication)."""
    r = build_report(_findings(), SCAN, "0.1.0", execution=_EXEC,
                     attack_surface=_surface_fixture(), environment=_ENV,
                     assessment_id="run-20260928T111009Z")
    r["diff"] = None
    r["gate"] = evaluate_gate(r, None)
    return r


def _assert_clean(case, html):
    low = html.lower()
    for term in FORBIDDEN:
        case.assertNotIn(term, low, f"forbidden fabricated claim rendered: {term!r}")


class TestLanding(unittest.TestCase):
    def setUp(self):
        self.html = landing.render_landing(_report())

    def test_core_identity_and_pipeline(self):
        self.assertIn("WATCHTOWER", self.html)
        self.assertIn("Automated Security Assessment", self.html)
        for stage in ("DISCOVER", "SCAN", "NORMALIZE", "CORRELATE", "VERIFY",
                      "SCORE", "EXPLAIN", "REPORT"):
            self.assertIn(stage, self.html)

    def test_gate_is_watchtower_policy_not_cvss(self):
        self.assertIn("watchtower-gate-v1", self.html)
        self.assertIn("watchtower-risk-score-v1", self.html)
        # The score/gate must be explicitly disclaimed as not CVSS.
        self.assertIn("not CVSS", self.html)
        self.assertIn("Not a CVSS gate", self.html)

    def test_skipped_scanners_shown_as_limitation(self):
        # Integrated-but-uninstalled scanners appear, flagged skipped — never as complete.
        for scanner in landing.SCANNERS_OPTIONAL:
            self.assertIn(scanner, self.html)
        self.assertIn("skipped", self.html)

    def test_snapshot_note_and_gate_value_from_report(self):
        self.assertIn(landing.SNAPSHOT_NOTE, self.html)
        # Whatever the real gate says, that is what the snapshot shows (no contradiction).
        self.assertIn(evaluate_gate(_report(), None)["result"], self.html)

    def test_no_fabricated_claims(self):
        _assert_clean(self, self.html)


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.report = _report()
        self.html = dashboard.render_dashboard(self.report)

    def test_console_identity_and_real_run_id(self):
        self.assertIn("Security Operations Console", self.html)
        # Assessment is finished, not a live feed.
        self.assertIn("Assessment complete", self.html)
        self.assertNotIn("LIVE MONITORING", self.html)
        self.assertIn("run-20260928T111009Z", self.html)   # real run id, from the report
        self.assertIn("http://localhost:3000", self.html)
        self.assertIn("28 Sep 2026", self.html)             # formatted completion timestamp

    def test_gate_rendered_from_report_not_recomputed(self):
        gate = self.report["gate"]
        self.assertIn(gate["result"], self.html)            # the exact decision the engine made
        self.assertIn(gate["policy"], self.html)
        self.assertIn(dashboard.GATE_MESSAGE, self.html)

    def test_posture_and_manual_review_counts(self):
        for label in ("Critical", "High", "Medium", "Manual Review"):
            self.assertIn(label, self.html)
        review = self.report["summary"]["needs_manual_review"]
        self.assertIn(f'<div class="num" style="color:var(--warn)">{review}</div>', self.html)

    def test_findings_table_filters_and_search(self):
        self.assertIn("Findings", self.html)
        for label in ("All", "Critical", "High", "Medium", "Low", "Info",
                      "Verified", "Manual Review", "False Positive"):
            self.assertIn(f">{label}</button>", self.html)
        self.assertIn("Filter by title, endpoint, tool or fingerprint...", self.html)
        # Every finding title reaches the table (the benign ones verbatim).
        self.assertIn("CORS reflects credentialed wildcard origin", self.html)
        self.assertIn("Rate limiting could not be confirmed", self.html)

    def test_finding_titles_are_autoescaped(self):
        # The XSS payload title must never reach the DOM as live markup.
        self.assertNotIn("<script>alert(1)</script>", self.html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", self.html)

    def test_inlined_findings_json_cannot_break_out_of_script(self):
        # The client-side FINDINGS island escapes <, > and & so no </script> can appear
        # and the payload is inert even inside the <script> block.
        self.assertIn("var FINDINGS =", self.html)
        self.assertIn("\\u003cscript\\u003ealert(1)", self.html)
        self.assertNotIn("</script>alert", self.html)

    def test_missing_surface_shows_na_placeholder(self):
        # The npm-audit false positive has no endpoint and no file.
        self.assertIn(LABEL_PLACEHOLDER, self.html)

    def test_regression_placeholders_when_no_baseline(self):
        self.assertIsNone(self.report["diff"])
        self.assertIn("No baseline available for regression comparison.", self.html)
        self.assertIn("Historical run comparison unavailable.", self.html)

    def test_skipped_scanner_surfaced_in_coverage(self):
        self.assertIn("Engine Coverage", self.html)
        self.assertIn("semgrep", self.html)      # the skipped scanner is listed
        self.assertIn("skipped", self.html)
        self.assertIn("not installed", self.html)

    def test_risk_tags_not_labelled_vulnerabilities(self):
        self.assertIn("Risk tag assignments", self.html)
        self.assertIn("ssrf_candidate", self.html)
        # The spec-mandated disclaimer keeps risk tags distinct from vulnerabilities.
        self.assertIn("not", self.html.lower())
        self.assertIn("vulnerability findings", self.html)

    def test_no_fabricated_claims(self):
        _assert_clean(self, self.html)


class TestBuildUiAgainstCanonicalReport(unittest.TestCase):
    """Render both surfaces from the real report.json artifacts on disk and assert the UI
    never contradicts the report (§6). Values are read back from the loaded report rather
    than hard-coded, so the check enforces consistency for whatever the run actually holds."""

    def setUp(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.paths = sorted(glob.glob(os.path.join(root, "output", "run-*", "report.json")))
        if not self.paths:
            self.skipTest("no output/run-*/report.json present")

        def richness(path):
            r = load_report_for_ui(path)
            asf = (r.get("attack_surface") or {}).get("summary", {})
            return (asf.get("endpoint_count") or 0, (r.get("summary") or {}).get("total_findings") or 0)

        # The canonical assessment is the richest real run (most endpoints, then findings),
        # not merely the lexicographically-newest directory (which may be a degenerate run).
        self.report = load_report_for_ui(max(self.paths, key=richness))

    def test_display_report_upgraded_to_schema_1_2(self):
        self.assertIsInstance(self.report.get("gate"), dict)
        self.assertIn(self.report["gate"]["result"], ("PASS", "WARN", "FAIL"))
        self.assertIn("diff", self.report)             # present (may be None) for display
        self.assertEqual(self.report.get("schema_version"), "1.2")

    def test_surfaces_do_not_contradict_the_report(self):
        endpoints = (self.report.get("attack_surface") or {}).get("summary", {}).get("endpoint_count")
        total = (self.report.get("summary") or {}).get("total_findings")
        gate_result = self.report["gate"]["result"]
        for html in (landing.render_landing(self.report), dashboard.render_dashboard(self.report)):
            self.assertIn(str(endpoints), html)
            self.assertIn(gate_result, html)
            self.assertIn("watchtower-gate-v1", html)
            _assert_clean(self, html)
        # The findings count is a dashboard headline value.
        self.assertIn(str(total), dashboard.render_dashboard(self.report))

    def test_every_real_report_renders_without_crashing(self):
        # Regression guard: even a degenerate run (0 endpoints, all-zero risk-tag counts)
        # must render both surfaces rather than crash the presentation layer.
        for path in self.paths:
            r = load_report_for_ui(path)
            landing.render_landing(r)          # must not raise (e.g. ZeroDivisionError)
            dashboard.render_dashboard(r)


if __name__ == "__main__":
    unittest.main()
