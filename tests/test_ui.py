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
from engine.baseline import build_baseline  # noqa: E402
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
        # The headline must match the ACTUAL gate result. This fixture has a verified High
        # finding, so the engine's decision is FAIL: the dashboard must say FAIL and must NOT
        # show the WARN-specific copy — rendering GATE_MESSAGE here would contradict the
        # report (a "no verified High" sentence over a verified-High FAIL). §6/§16.
        self.assertEqual(gate["result"], "FAIL")
        self.assertIn("The gate is FAIL", self.html)
        self.assertNotIn(dashboard.GATE_MESSAGE, self.html)
        # The gate frame colour follows the result (red for FAIL), not a hardcoded amber.
        self.assertIn("gate-hero fail", self.html)

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


SCAN_OLD = {"timestamp": "2026-09-27T09:00:00Z", "target": "http://localhost:3000",
            "repository": "repo", "commit": "aaa1111", "branch": "main"}
SCAN_NEW = {"timestamp": "2026-09-28T09:00:00Z", "target": "http://localhost:3000",
            "repository": "repo", "commit": "bbb2222", "branch": "main"}


def _mk(tool, title, severity, status, result, endpoint=None, file=None, line=None):
    """A minimal Finding (scored later) carrying an explicit verification result."""
    return Finding(tool=tool, title=title, description="d", severity=severity, status=status,
                   endpoint=endpoint, file=file, line=line,
                   verification={"method": "active_probe", "probe": tool, "result": result,
                                 "rationale": "r", "timestamp": "t"})


def _surface(paths):
    """An AttackSurface over the given endpoint paths (drives the surface add/remove diff)."""
    return AttackSurface(
        endpoints=[Endpoint(path=p, methods=["GET"], source_file="api" + p.replace("/", "_") + ".ts",
                            component="core", authentication="public", risk_tags=["rpc"])
                   for p in paths],
        integrations=[], env_references=[], notes=["static, read-only"])


def _baseline_aware_report():
    """Two REAL assessments (baseline + current) whose engine-computed diff exercises the
    change axes: a new finding, a resolved finding, an unchanged finding, and severity /
    score / verification / lifecycle transitions on shared fingerprints, plus a surface
    add and remove. Built via build_report + build_baseline so field names never drift."""
    old = score_all([
        _mk("cors", "CORS wildcard", Severity.HIGH, Status.NEEDS_MANUAL_REVIEW, "inconclusive",
            endpoint="http://localhost:3000/api/a"),
        _mk("headers", "CSP header missing", Severity.HIGH, Status.VERIFIED, "confirmed",
            endpoint="http://localhost:3000/api/b"),
        _mk("rate-limit", "Rate limit unconfirmed", Severity.LOW, Status.NEEDS_MANUAL_REVIEW,
            "inconclusive", endpoint="http://localhost:3000/api/c"),
        _mk("npm-audit", "Vulnerable dependency lodash", Severity.MEDIUM, Status.NEEDS_MANUAL_REVIEW,
            None, file="package.json", line=1)])
    new = score_all([
        _mk("cors", "CORS wildcard", Severity.HIGH, Status.NEEDS_MANUAL_REVIEW, "inconclusive",
            endpoint="http://localhost:3000/api/a"),
        _mk("headers", "CSP header missing", Severity.MEDIUM, Status.VERIFIED, "confirmed",
            endpoint="http://localhost:3000/api/b"),
        _mk("rate-limit", "Rate limit unconfirmed", Severity.LOW, Status.FALSE_POSITIVE, "refuted",
            endpoint="http://localhost:3000/api/c"),
        _mk("ssrf", "SSRF candidate reachable", Severity.MEDIUM, Status.NEEDS_MANUAL_REVIEW,
            "inconclusive", endpoint="http://localhost:3000/api/d")])
    old_r = build_report(old, SCAN_OLD, "0.1.0",
                         attack_surface=_surface(["/api/a", "/api/b", "/api/c", "/api/x", "/api/y"]))
    new_r = build_report(new, SCAN_NEW, "0.1.0",
                         attack_surface=_surface(["/api/a", "/api/b", "/api/c", "/api/d", "/api/z"]),
                         baseline=build_baseline(old_r))
    return new_r


def _gate_report(findings):
    """A no-baseline report over `findings` (no execution/surface, so the gate result is
    driven purely by the findings — used to pin the PASS / WARN / FAIL states)."""
    r = build_report(score_all(findings), SCAN_NEW, "0.1.0")
    r["diff"] = None
    r["gate"] = evaluate_gate(r, None)
    return r


class TestDashboardRegression(unittest.TestCase):
    """STEP 7: the regression + gate view renders ONLY from report['diff'] / report['gate']
    (the engine is the single source of truth — the UI never recomputes a diff or a gate).
    Covers the spec's CASE A-L: no-baseline vs a real no-changes comparison, every change
    axis, the three gate colours, XSS-safety of change rows, and a degenerate/partial diff."""

    def setUp(self):
        # One real baseline-aware assessment drives CASE C-H (new/resolved/unchanged +
        # severity/score/verification/lifecycle transitions + a surface add and remove).
        self.report = _baseline_aware_report()
        self.diff = self.report["diff"]
        self.html = dashboard.render_dashboard(self.report)

    # --- CASE I/J/K: gate colour follows the ACTUAL result; message matches it ----
    def test_case_I_gate_fail_frame_is_red(self):
        r = _gate_report([_mk("cors", "CORS reflects credentialed wildcard origin", Severity.HIGH,
                              Status.VERIFIED, "confirmed", endpoint="http://localhost:3000/api/x")])
        self.assertEqual(r["gate"]["result"], "FAIL")
        html = dashboard.render_dashboard(r)
        self.assertIn("gate-hero fail", html)             # red frame follows the result
        self.assertNotIn("gate-hero warn", html)
        self.assertNotIn("gate-hero pass", html)
        self.assertIn("The gate is FAIL", html)
        self.assertNotIn(dashboard.GATE_MESSAGE, html)    # never the WARN copy on a FAIL
        _assert_clean(self, html)

    def test_case_J_gate_warn_frame_is_amber(self):
        # needs-manual-review only, no verified High/Critical -> WARN. This is the ONLY
        # state whose honest copy is GATE_MESSAGE (it preserves the coverage the rewritten
        # test_gate_rendered_from_report_not_recomputed intentionally gave up).
        r = _gate_report([_mk("rate-limit", "Rate limiting could not be confirmed", Severity.LOW,
                              Status.NEEDS_MANUAL_REVIEW, "inconclusive",
                              endpoint="http://localhost:3000/api/y")])
        self.assertEqual(r["gate"]["result"], "WARN")
        html = dashboard.render_dashboard(r)
        self.assertIn("gate-hero warn", html)
        self.assertNotIn("gate-hero fail", html)
        self.assertNotIn("gate-hero pass", html)
        self.assertIn(dashboard.GATE_MESSAGE, html)
        _assert_clean(self, html)

    def test_case_K_gate_pass_frame_is_green(self):
        r = _gate_report([_mk("headers", "Security header present", Severity.LOW,
                              Status.VERIFIED, "confirmed", endpoint="http://localhost:3000/api/z")])
        self.assertEqual(r["gate"]["result"], "PASS")
        html = dashboard.render_dashboard(r)
        self.assertIn("gate-hero pass", html)
        self.assertNotIn("gate-hero fail", html)
        self.assertNotIn("gate-hero warn", html)
        self.assertIn("The gate is PASS", html)
        self.assertIn("No gate conditions were triggered.", html)
        _assert_clean(self, html)

    # --- CASE A: no baseline -> "NO BASELINE AVAILABLE", NOT "no changes" --------
    def test_case_A_no_baseline_state(self):
        report = _report()                       # diff is None (schema upgrade, no baseline)
        self.assertIsNone(report["diff"])
        html = dashboard.render_dashboard(report)
        self.assertIn("NO BASELINE AVAILABLE", html)
        self.assertIn("Regression comparison is unavailable for this assessment.", html)
        self.assertIn("No baseline available for regression comparison.", html)
        self.assertIn(">no baseline</span>", html)          # header chip, not "no changes"
        # The no-baseline state must be visually distinct from a real "no changes" result.
        self.assertNotIn("No changes detected", html)
        _assert_clean(self, html)

    # --- CASE B: baseline present, findings + surface identical -> "No changes" ---
    def test_case_B_baseline_no_changes(self):
        old = [_mk("cors", "CORS wildcard", Severity.HIGH, Status.NEEDS_MANUAL_REVIEW,
                   "inconclusive", endpoint="http://localhost:3000/api/a")]
        new = [_mk("cors", "CORS wildcard", Severity.HIGH, Status.NEEDS_MANUAL_REVIEW,
                   "inconclusive", endpoint="http://localhost:3000/api/a")]
        old_r = build_report(score_all(old), SCAN_OLD, "0.1.0", attack_surface=_surface(["/api/a"]))
        new_r = build_report(score_all(new), SCAN_NEW, "0.1.0",
                             attack_surface=_surface(["/api/a"]), baseline=build_baseline(old_r))
        # A genuine comparison ran and found nothing changed — NOT a missing baseline.
        self.assertIsInstance(new_r["diff"], dict)
        html = dashboard.render_dashboard(new_r)
        self.assertIn("No changes detected", html)
        self.assertIn(">no changes</span>", html)
        self.assertNotIn("NO BASELINE AVAILABLE", html)
        self.assertIn("This is a real comparison result", html)
        _assert_clean(self, html)

    # --- CASE C-H: a real baseline-aware diff renders every change axis ----------
    def test_changes_detected_header_and_causality(self):
        self.assertTrue(self.diff["counts"]["new"] or self.diff["counts"]["resolved"])
        self.assertIn(">changes detected</span>", self.html)
        self.assertNotIn("NO BASELINE AVAILABLE", self.html)
        self.assertNotIn("No changes detected", self.html)
        # §13 causality disclaimer is always present on a real comparison.
        self.assertIn("They do not establish causality.", self.html)

    def test_case_C_new_finding_row(self):
        self.assertGreaterEqual(self.diff["counts"]["new"], 1)
        self.assertIn(">new</span>", self.html)
        self.assertIn("SSRF candidate reachable", self.html)      # the new finding's title

    def test_case_D_resolved_finding_row(self):
        self.assertGreaterEqual(self.diff["counts"]["resolved"], 1)
        self.assertIn(">resolved</span>", self.html)
        self.assertIn("Vulnerable dependency lodash", self.html)  # resolved finding's title

    def test_case_E_verification_change_never_conflated_with_lifecycle(self):
        self.assertGreaterEqual(self.diff["counts"]["verification_changed"], 1)
        self.assertGreaterEqual(self.diff["counts"]["status_changed"], 1)
        # Two SEPARATE panels — the verification axis and the lifecycle axis never merge.
        self.assertIn("Verification changes", self.html)
        self.assertIn("a distinct axis from lifecycle status.", self.html)
        self.assertIn("Lifecycle status changes", self.html)
        self.assertIn("Lifecycle transitions — not a verification result.", self.html)

    def test_case_F_severity_change_is_neutral(self):
        self.assertGreaterEqual(self.diff["counts"]["severity_changed"], 1)
        self.assertIn("Severity changes", self.html)
        self.assertIn("CSP header missing", self.html)            # finding whose severity moved
        low = self.html.lower()                                   # neutral wording only
        for verdict in ("improved", "worsened", "safer", "more dangerous", "regressed"):
            self.assertNotIn(verdict, low)

    def test_case_G_score_change_labelled_watchtower_not_cvss(self):
        self.assertGreaterEqual(self.diff["counts"]["score_changed"], 1)
        self.assertIn("Risk score changes", self.html)
        self.assertIn("WATCHTOWER Risk Score (not CVSS)", self.html)

    def test_case_H_attack_surface_delta_not_vulnerabilities(self):
        self.assertEqual(self.diff["counts"]["surface_added"], 2)
        self.assertEqual(self.diff["counts"]["surface_removed"], 2)
        self.assertIn("Attack surface delta", self.html)
        self.assertIn("Added endpoints", self.html)
        self.assertIn("Removed endpoints", self.html)
        for path in ("/api/d", "/api/z", "/api/x", "/api/y"):
            self.assertIn(path, self.html)
        self.assertIn("not</b> vulnerabilities", self.html)       # candidates, not vulns

    # --- CASE L: a degenerate/partial diff renders stably (no crash) -------------
    def test_case_L_partial_diff_is_stable(self):
        report = _gate_report([_mk("cors", "CORS wildcard", Severity.MEDIUM,
                                   Status.NEEDS_MANUAL_REVIEW, "inconclusive",
                                   endpoint="http://localhost:3000/api/a")])
        # Optional diff sub-sections absent; only counts + note present.
        report["diff"] = {"counts": {}, "note": "partial diff artifact"}
        report["gate"] = evaluate_gate(report, report["diff"])
        html = dashboard.render_dashboard(report)             # must not raise
        # A diff dict (even empty) IS a comparison -> "no changes", never "no baseline".
        self.assertIn("No changes detected", html)
        self.assertNotIn("NO BASELINE AVAILABLE", html)
        self.assertIn("partial diff artifact", html)          # note surfaced verbatim
        self.assertIn("Attack surface delta", html)           # structural sections still render
        _assert_clean(self, html)

    def test_regression_change_rows_are_autoescaped(self):
        # A NEW finding whose title is an XSS payload must reach the change table inert.
        old = [_mk("cors", "benign baseline finding", Severity.HIGH,
                   Status.NEEDS_MANUAL_REVIEW, "inconclusive",
                   endpoint="http://localhost:3000/api/a")]
        new = [_mk("cors", "benign baseline finding", Severity.HIGH,
                   Status.NEEDS_MANUAL_REVIEW, "inconclusive",
                   endpoint="http://localhost:3000/api/a"),
               _mk("xss", "<script>alert(1)</script>", Severity.MEDIUM,
                   Status.NEEDS_MANUAL_REVIEW, "inconclusive",
                   endpoint="http://localhost:3000/api/e")]
        old_r = build_report(score_all(old), SCAN_OLD, "0.1.0")
        new_r = build_report(score_all(new), SCAN_NEW, "0.1.0", baseline=build_baseline(old_r))
        html = dashboard.render_dashboard(new_r)
        self.assertGreaterEqual(new_r["diff"]["counts"]["new"], 1)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_gate_and_diff_are_read_from_report_not_recomputed(self):
        # The rendered gate frame + message come straight from report['gate'] (engine output);
        # the UI selects colour/copy by the engine's result and does not re-derive a decision.
        gate = self.report["gate"]
        self.assertIn(f"gate-hero {gate['result'].lower()}", self.html)
        self.assertIn(gate["policy"], self.html)              # watchtower-gate-v1
        self.assertTrue(gate["baseline_aware"])               # a real baseline was used
        self.assertIn(dashboard._gate_message(gate), self.html)


if __name__ == "__main__":
    unittest.main()
