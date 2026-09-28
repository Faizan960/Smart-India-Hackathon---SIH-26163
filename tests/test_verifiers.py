"""Tests for the verification framework (checks/verifiers.py).

Covers: security-header verdicts (confirmed / refuted / not_applicable), dependency
reachability classification (production/development, direct/transitive, imported/not),
the resulting lifecycle status transitions, verifier crash-isolation, and how the final
status feeds the WATCHTOWER Risk Score. All fixtures are temporary and local-only.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from checks.verifiers import (  # noqa: E402
    AuthVerifier, CorsVerifier, DependencyReachabilityVerifier, RateLimitVerifier,
    SecurityHeaderVerifier, SsrfVerifier, VerificationContext,
    Verifier, default_verifiers, run_verifiers,
)
from engine import scorer  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402


def _npm_finding(package, *, severity=Severity.HIGH, fixed=None):
    return Finding(tool="npm-audit", title=f"advisory for {package}", description="d",
                   severity=severity, status=Status.SUSPECTED,
                   evidence={"package": package, "identifiers": [], "fixed_version": fixed})


def _header_finding(header, *, present, value=None, scheme="http", host="localhost",
                    status_code=200, url="http://localhost:3000/"):
    return Finding(tool="security-headers", title=f"{header} header", description="d",
                   severity=Severity.LOW, status=Status.SUSPECTED, endpoint=url,
                   evidence={"header": header, "present": present, "value": value,
                             "observed_value": value, "url_tested": url,
                             "status_code": status_code, "scheme": scheme, "host": host})


class _RepoFixture(unittest.TestCase):
    """Builds throwaway package.json / package-lock.json trees under a temp dir."""

    def _repo(self, *, deps=None, dev_deps=None, lock_packages=None, src_files=None):
        tmp = tempfile.mkdtemp(prefix="wt-deps-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        pkg = {"name": "fixture", "version": "0.0.0",
               "dependencies": deps or {}, "devDependencies": dev_deps or {}}
        lock = {"name": "fixture", "lockfileVersion": 3, "packages": lock_packages or {}}
        with open(os.path.join(tmp, "package.json"), "w", encoding="utf-8") as h:
            json.dump(pkg, h)
        with open(os.path.join(tmp, "package-lock.json"), "w", encoding="utf-8") as h:
            json.dump(lock, h)
        for rel, content in (src_files or {}).items():
            full = os.path.join(tmp, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as h:
                h.write(content)
        return tmp


class TestDependencyReachability(_RepoFixture):
    def _verify(self, repo, finding):
        context = VerificationContext.build(repo_path=repo)
        DependencyReachabilityVerifier().verify(finding, context)
        return finding

    def test_production_transitive_not_imported_needs_review(self):
        repo = self._repo(lock_packages={
            "node_modules/image-size": {"version": "1.2.1", "dev": False, "optional": False}})
        f = self._verify(repo, _npm_finding("image-size"))
        self.assertEqual(f.status, Status.NEEDS_MANUAL_REVIEW)
        self.assertEqual(f.evidence["dependency_type"], "production")
        self.assertEqual(f.evidence["direct_or_transitive"], "transitive")
        self.assertEqual(f.evidence["reachable"], "not-imported")

    def test_production_imported_needs_review(self):
        repo = self._repo(
            lock_packages={"node_modules/image-size": {"version": "1.2.1", "dev": False}},
            src_files={"src/app.ts": "import sizeOf from 'image-size'\nsizeOf('x')\n"})
        f = self._verify(repo, _npm_finding("image-size"))
        # Reachability is shown, but exploitation is not demonstrated -> inconclusive,
        # which the lifecycle maps to needs_manual_review (NOT verified).
        self.assertEqual(f.status, Status.NEEDS_MANUAL_REVIEW)
        self.assertEqual(f.verification["result"], "inconclusive")
        self.assertEqual(f.evidence["reachable"], "imported")

    def test_direct_dependency_detected(self):
        repo = self._repo(
            deps={"image-size": "^1.2.1"},
            lock_packages={"node_modules/image-size": {"version": "1.2.1", "dev": False}})
        f = self._verify(repo, _npm_finding("image-size"))
        self.assertEqual(f.evidence["direct_or_transitive"], "direct")

    def test_development_only_is_false_positive(self):
        repo = self._repo(lock_packages={
            "node_modules/@vitest/mocker": {"version": "4.1.1", "dev": True}})
        f = self._verify(repo, _npm_finding("@vitest/mocker", severity=Severity.MEDIUM))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.evidence["dependency_type"], "development")
        # PART 0: a development-only dependency is not-applicable to a production target,
        # and not_applicable maps to false_positive.
        self.assertEqual(f.verification["result"], "not_applicable")

    def test_absent_from_lock_is_false_positive(self):
        repo = self._repo(lock_packages={})
        f = self._verify(repo, _npm_finding("ghost-package"))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertFalse(f.evidence["present_in_lock"])

    def test_missing_manifests_needs_review(self):
        empty = tempfile.mkdtemp(prefix="wt-empty-")
        self.addCleanup(shutil.rmtree, empty, ignore_errors=True)
        f = self._verify(empty, _npm_finding("image-size"))
        self.assertEqual(f.status, Status.NEEDS_MANUAL_REVIEW)
        self.assertIsNotNone(f.evidence["manifest_error"])

    def test_applies_only_to_dependency_tools(self):
        v = DependencyReachabilityVerifier()
        self.assertTrue(v.applies_to(_npm_finding("x")))
        self.assertFalse(v.applies_to(_header_finding("X-Frame-Options", present=False)))


class TestSecurityHeaderVerifier(unittest.TestCase):
    def test_present_header_refuted_is_false_positive(self):
        # PART 0: a "refuted" verification result maps to false_positive, NEVER verified.
        f = _header_finding("Content-Security-Policy", present=True, value="default-src 'self'")
        self.assertTrue(SecurityHeaderVerifier().verify(f))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.verification["result"], "refuted")
        self.assertEqual(f.evidence["verification_status"], "refuted")
        self.assertEqual(f.verification["method"], "active_probe")

    def test_absent_header_confirmed(self):
        f = _header_finding("X-Frame-Options", present=False)
        self.assertTrue(SecurityHeaderVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.severity, Severity.LOW)
        self.assertEqual(f.verification["result"], "confirmed")
        self.assertEqual(f.evidence["verification_status"], "confirmed")
        self.assertIn("X-Frame-Options", f.evidence["remediation"])

    def test_absent_hsts_over_http_loopback_not_applicable(self):
        # PART 0: "not_applicable" maps to false_positive, NEVER verified.
        f = _header_finding("Strict-Transport-Security", present=False, scheme="http",
                            host="localhost")
        SecurityHeaderVerifier().verify(f)
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.verification["result"], "not_applicable")
        self.assertEqual(f.evidence["verification_status"], "not_applicable")

    def test_verified_is_terminal(self):
        # A second, weaker attempt cannot reopen a verified header finding.
        f = _header_finding("X-Frame-Options", present=False)
        SecurityHeaderVerifier().verify(f)
        self.assertEqual(f.status, Status.VERIFIED)
        SecurityHeaderVerifier().verify(f)  # re-running is a no-op transition on a terminal state
        self.assertEqual(f.status, Status.VERIFIED)


class TestActiveProbeVerifiers(unittest.TestCase):
    """Each Phase-4 probe verifier routes its classifier's verdict through the lifecycle."""

    def _finding(self, tool, evidence, *, endpoint="http://localhost:3000/"):
        return Finding(tool=tool, title=f"{tool} finding", description="d",
                       severity=Severity.INFO, status=Status.SUSPECTED,
                       endpoint=endpoint, evidence=dict(evidence))

    def test_cors_confirmed_maps_to_verified(self):
        f = self._finding("cors", {
            "refused": False, "reachable": True, "origin_sent": "https://evil.example",
            "simple": {"Access-Control-Allow-Origin": "https://evil.example",
                       "Access-Control-Allow-Credentials": "true"}, "preflight": {}})
        self.assertTrue(CorsVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.verification["result"], "confirmed")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_cors_not_reflected_is_false_positive(self):
        f = self._finding("cors", {
            "refused": False, "reachable": True, "origin_sent": "https://evil.example",
            "simple": {"Access-Control-Allow-Origin": "https://app.example"}, "preflight": {}})
        self.assertTrue(CorsVerifier().verify(f))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.verification["result"], "refuted")

    def test_rate_limit_enforced_is_false_positive(self):
        f = self._finding("rate-limit", {
            "refused": False, "reachable": True, "statuses": [200, 429],
            "saw_429": True, "rate_limit_headers": {}, "request_count": 2})
        self.assertTrue(RateLimitVerifier().verify(f))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)   # enforcement present -> concern refuted
        self.assertEqual(f.verification["result"], "refuted")

    def test_rate_limit_no_signal_needs_review(self):
        f = self._finding("rate-limit", {
            "refused": False, "reachable": True, "statuses": [200, 200],
            "saw_429": False, "rate_limit_headers": {}, "request_count": 2})
        self.assertTrue(RateLimitVerifier().verify(f))
        self.assertEqual(f.status, Status.NEEDS_MANUAL_REVIEW)  # absence never "confirmed"
        self.assertEqual(f.verification["result"], "inconclusive")

    def test_auth_enforced_is_false_positive(self):
        f = self._finding("auth-mcp", {
            "refused": False, "endpoint": "http://localhost:3000/api/mcp", "kind": "mcp",
            "expected": "protected", "status_by_state": {"none": 401}})
        self.assertTrue(AuthVerifier().verify(f))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.verification["result"], "refuted")

    def test_auth_exposed_mcp_tools_confirmed(self):
        f = self._finding("auth-mcp", {
            "refused": False, "endpoint": "http://localhost:3000/api/mcp", "kind": "mcp",
            "expected": "protected", "status_by_state": {"none": 200},
            "mcp_exposed_tools": True})
        self.assertTrue(AuthVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.verification["result"], "confirmed")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_ssrf_canary_hit_confirmed(self):
        f = self._finding("ssrf", {
            "refused": False, "endpoint": "http://localhost:3000/api/rss-proxy",
            "canary_received": True, "triggering_param": "url",
            "response_status_by_param": {"url": 200}})
        self.assertTrue(SsrfVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.verification["result"], "confirmed")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_ssrf_rejected_is_false_positive(self):
        f = self._finding("ssrf", {
            "refused": False, "endpoint": "http://localhost:3000/api/rss-proxy",
            "canary_received": False, "response_status_by_param": {"url": 400}})
        self.assertTrue(SsrfVerifier().verify(f))
        self.assertEqual(f.status, Status.FALSE_POSITIVE)
        self.assertEqual(f.verification["result"], "refuted")

    def test_probe_verifiers_only_apply_to_their_tool(self):
        cors = self._finding("cors", {"refused": False, "reachable": True})
        self.assertTrue(CorsVerifier().applies_to(cors))
        self.assertFalse(RateLimitVerifier().applies_to(cors))
        self.assertFalse(AuthVerifier().applies_to(cors))
        self.assertFalse(SsrfVerifier().applies_to(cors))


class _Boom(Verifier):
    name = "boom"

    def applies_to(self, finding):
        return True

    def verify(self, finding, context=None):
        raise RuntimeError("verifier exploded")


class TestRunVerifiers(unittest.TestCase):
    def test_crashing_verifier_is_isolated(self):
        f = _npm_finding("image-size")
        counts = run_verifiers([f], context=None, verifiers=[_Boom()])
        self.assertEqual(counts["boom"], 0)
        self.assertIn("boom: verifier exploded", f.evidence["verifier_errors"][0])

    def test_counts_applied_transitions(self):
        f = _header_finding("X-Frame-Options", present=False)
        counts = run_verifiers([f], context=None, verifiers=default_verifiers())
        self.assertEqual(counts["security-header"], 1)
        self.assertEqual(counts["dependency-reachability"], 0)


class TestRiskScoreInteraction(unittest.TestCase):
    def test_false_positive_scores_zero(self):
        f = _npm_finding("x", severity=Severity.HIGH)
        f.status = Status.FALSE_POSITIVE
        scorer.score_finding(f)
        self.assertEqual(f.score["value"], 0.0)

    def test_needs_review_uses_neutral_multiplier(self):
        f = _npm_finding("x", severity=Severity.HIGH)
        f.status = Status.NEEDS_MANUAL_REVIEW
        scorer.score_finding(f)
        self.assertEqual(f.score["value"], 8.0)  # 8.0 * 1.0 * 1.0

    def test_verified_confirmed_header_scored(self):
        f = _header_finding("X-Frame-Options", present=False)
        SecurityHeaderVerifier().verify(f)
        scorer.score_finding(f)
        self.assertEqual(f.score["value"], 3.0)  # LOW(2.0) * VERIFIED(1.5) * OTHER(1.0)


if __name__ == "__main__":
    unittest.main()


