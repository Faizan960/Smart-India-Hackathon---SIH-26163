"""Tests for the canonical assessment baseline (Phase 6, Step 2).

A baseline is a deterministic, secret-free projection of a report.json. These tests pin
its identity rules (finding = fingerprint, endpoint = path), its determinism (byte-stable
serialisation), and its secret hygiene (raw evidence dropped, secret-named keys redacted).
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.attack_surface import AttackSurface, Endpoint  # noqa: E402
from engine.baseline import (BASELINE_KIND, BASELINE_SCHEMA_VERSION,  # noqa: E402
                             build_baseline, load_baseline, render_summary, save_baseline)
from engine.scorer import score_all  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402
from reports.json_report import build_report  # noqa: E402

SCAN = {"timestamp": "2026-09-28T00:00:00Z", "target": "http://localhost:3000",
        "repository": "world-monitor", "commit": "abc123", "branch": "main"}

# A secret value buried in a finding's raw evidence blob. The allow-list projection must
# drop the whole evidence blob, so this must never reach the baseline.
_EVIDENCE_SECRET = "AKIAIOSFODNN7EXAMPLE-secretval"

# A reproducibility manifest whose `configuration` intentionally carries a secret-NAMED key,
# to prove the defensive scrub redacts it (the real manifest is already sanitized upstream).
ENVIRONMENT = {
    "watchtower_version": "0.1.0", "python_version": "3.14.0", "platform": "TestPlatform-1.0",
    "probe_versions": {"ssrf": "1", "cors": "1"}, "scanner_versions": {"semgrep": None},
    "configuration": {"log_level": "info", "SIGNING_KEY": "super-secret-signing-value"},
}


def _surface():
    # Endpoints supplied OUT of sorted order to prove the baseline sorts by path identity.
    return AttackSurface(
        endpoints=[
            Endpoint(path="/api/rss-proxy", methods=["GET"], source_file="api/rss-proxy.ts",
                     component="proxy", authentication=None,
                     risk_tags=["ssrf_candidate", "external_fetch"]),
            Endpoint(path="/api/health", methods=["GET"], source_file="api/health.ts",
                     component="core", authentication="public"),
        ],
        integrations=[{"name": "Clerk", "kind": "auth", "evidence": {"note": "x"}}],
        env_references=["UPSTASH_REDIS_REST_URL"],
        notes=["Attack-surface discovery is static and read-only."],
    )


def _findings():
    return score_all([
        Finding(tool="semgrep", title="eval injection", description="d",
                severity=Severity.HIGH, status=Status.SUSPECTED, file="api/x.ts", line=3,
                cwe="CWE-95", id="WT-SEM-0001",
                evidence={"rule": "js.eval", "raw": _EVIDENCE_SECRET}),
        Finding(tool="security-headers", title="CSP missing", description="d",
                severity=Severity.LOW, status=Status.VERIFIED, id="WT-HDR-0001",
                endpoint="http://localhost:3000/",
                verification={"method": "header_probe", "result": "confirmed",
                              "probe": "security-headers", "rationale": "absent"}),
    ])


def _report():
    return build_report(_findings(), SCAN, "0.1.0", attack_surface=_surface(),
                        environment=ENVIRONMENT, assessment_id="run-abc123")


class TestBaseline(unittest.TestCase):
    def setUp(self):
        self.report = _report()
        self.baseline = build_baseline(self.report)

    def test_baseline_created(self):
        self.assertIsInstance(self.baseline, dict)
        self.assertEqual(self.baseline["kind"], BASELINE_KIND)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            self.assertEqual(save_baseline(path, self.baseline), path)
            self.assertTrue(os.path.exists(path))

    def test_baseline_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            save_baseline(path, self.baseline)
            loaded = load_baseline(path)
        # Round-trips exactly: save then load reproduces the baseline dict.
        self.assertEqual(loaded, self.baseline)

    def test_baseline_schema_version(self):
        self.assertEqual(BASELINE_SCHEMA_VERSION, "1.0")
        self.assertEqual(self.baseline["schema_version"], "1.0")
        self.assertEqual(self.baseline["kind"], "watchtower-baseline")
        # The source report's schema is preserved for provenance (report is now 1.2).
        self.assertEqual(self.baseline["assessment"]["report_schema_version"], "1.2")

    def test_baseline_contains_attack_surface(self):
        surface = self.baseline["attack_surface"]
        self.assertEqual(len(surface["endpoints"]), 2)
        # Integrations are reduced to name/kind only (evidence dropped).
        self.assertEqual(surface["integrations"], [{"name": "Clerk", "kind": "auth"}])
        proxy = next(e for e in surface["endpoints"] if e["path"] == "/api/rss-proxy")
        self.assertEqual(proxy["risk_tags"], ["external_fetch", "ssrf_candidate"])

    def test_baseline_contains_findings(self):
        fnd = self.baseline["findings"]
        self.assertEqual(len(fnd), 2)
        csp = next(f for f in fnd if f["title"] == "CSP missing")
        # Lifecycle status, verification result, severity and risk score are all preserved.
        self.assertEqual(csp["status"], "verified")
        self.assertEqual(csp["verification"]["result"], "confirmed")
        self.assertEqual(csp["severity"], "low")
        self.assertEqual(csp["risk_score"], 3.0)
        self.assertEqual(csp["score_model"], "watchtower-risk-score-v1")  # NOT CVSS

    def test_baseline_uses_finding_fingerprint(self):
        # Identity is the stable content fingerprint, NOT the per-run WT-* id.
        expected = Finding(tool="semgrep", title="eval injection", description="d",
                           severity=Severity.HIGH, file="api/x.ts", line=3,
                           evidence={"rule": "js.eval"}).fingerprint()
        ev = next(f for f in self.baseline["findings"] if f["title"] == "eval injection")
        self.assertEqual(ev["fingerprint"], expected)
        self.assertEqual(len(ev["fingerprint"]), 16)
        # The WT-* id is retained only as a reference label, distinct from identity.
        self.assertEqual(ev["id"], "WT-SEM-0001")
        self.assertNotEqual(ev["fingerprint"], ev["id"])

    def test_baseline_uses_endpoint_path_identity(self):
        eps = self.baseline["attack_surface"]["endpoints"]
        paths = [e["path"] for e in eps]
        # Every endpoint is identified by its normalised path, and they are path-sorted.
        self.assertTrue(all("path" in e for e in eps))
        self.assertEqual(paths, ["/api/health", "/api/rss-proxy"])
        self.assertEqual(paths, sorted(paths))

    def test_baseline_is_deterministic(self):
        # Same report -> byte-identical baseline (no wall-clock, sorted, sort_keys serialisation).
        again = build_baseline(self.report)
        self.assertEqual(again, self.baseline)
        with tempfile.TemporaryDirectory() as d:
            p1, p2 = os.path.join(d, "a.json"), os.path.join(d, "b.json")
            save_baseline(p1, self.baseline)
            save_baseline(p2, again)
            with open(p1, "rb") as h1, open(p2, "rb") as h2:
                self.assertEqual(h1.read(), h2.read())

    def test_baseline_contains_no_secrets(self):
        import json as _json
        blob = _json.dumps(self.baseline, sort_keys=True)
        # The raw evidence blob (which held a secret) is dropped by the allow-list projection.
        self.assertNotIn(_EVIDENCE_SECRET, blob)
        self.assertNotIn("raw", self.baseline["findings"][0])
        # A secret-NAMED configuration key is redacted defence-in-depth.
        self.assertNotIn("super-secret-signing-value", blob)
        config = self.baseline["reproducibility"]["configuration"]
        self.assertEqual(config["SIGNING_KEY"], "[REDACTED]")
        self.assertEqual(config["log_level"], "info")   # non-secret values are untouched

    def test_baseline_excludes_ephemeral_runtime_data(self):
        # Per-run ephemera never enters a baseline (keeps it stable and diff-clean).
        for dropped in ("evidence_graph", "execution", "duplicate_groups", "scan"):
            self.assertNotIn(dropped, self.baseline)
        finding = self.baseline["findings"][0]
        for dropped in ("evidence", "explanation", "evidence_chain"):
            self.assertNotIn(dropped, finding)

    def test_render_summary_is_secret_free_lines(self):
        lines = render_summary(self.baseline)
        self.assertTrue(any("watchtower-baseline" in ln for ln in lines))
        self.assertFalse(any("super-secret-signing-value" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()

