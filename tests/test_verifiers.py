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
    DependencyReachabilityVerifier, SecurityHeaderVerifier, VerificationContext,
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

    def test_production_imported_stays_suspected(self):
        repo = self._repo(
            lock_packages={"node_modules/image-size": {"version": "1.2.1", "dev": False}},
            src_files={"src/app.ts": "import sizeOf from 'image-size'\nsizeOf('x')\n"})
        f = self._verify(repo, _npm_finding("image-size"))
        self.assertEqual(f.status, Status.SUSPECTED)   # reachable, but not exploited -> not verified
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
        self.assertEqual(f.verification["result"], "refuted")

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
    def test_present_header_refuted_informational(self):
        f = _header_finding("Content-Security-Policy", present=True, value="default-src 'self'")
        self.assertTrue(SecurityHeaderVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.evidence["verification_status"], "refuted")
        self.assertEqual(f.verification["method"], "active_probe")

    def test_absent_header_confirmed(self):
        f = _header_finding("X-Frame-Options", present=False)
        self.assertTrue(SecurityHeaderVerifier().verify(f))
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.severity, Severity.LOW)
        self.assertEqual(f.evidence["verification_status"], "confirmed")
        self.assertIn("X-Frame-Options", f.evidence["remediation"])

    def test_absent_hsts_over_http_loopback_not_applicable(self):
        f = _header_finding("Strict-Transport-Security", present=False, scheme="http",
                            host="localhost")
        SecurityHeaderVerifier().verify(f)
        self.assertEqual(f.status, Status.VERIFIED)
        self.assertEqual(f.severity, Severity.INFO)
        self.assertEqual(f.evidence["verification_status"], "not_applicable")

    def test_verified_is_terminal(self):
        # A second, weaker attempt cannot reopen a verified header finding.
        f = _header_finding("X-Frame-Options", present=False)
        SecurityHeaderVerifier().verify(f)
        self.assertEqual(f.status, Status.VERIFIED)
        SecurityHeaderVerifier().verify(f)  # re-running is a no-op transition on a terminal state
        self.assertEqual(f.status, Status.VERIFIED)


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


