"""Tests for engine.correlator — cross-tool corroboration promotes to CORRELATED only.

Correlation must never move a finding to VERIFIED, and a single tool reporting the same
issue twice is a duplicate, not corroboration (so it forms no correlation group).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.correlator import correlate, correlation_groups, correlation_keys  # noqa: E402
from model.finding import Finding, Status  # noqa: E402


def _mk(tool, fid, *, ident=None, package=None, endpoint=None, cwe=None, file=None):
    ev = {}
    if ident:
        ev["identifiers"] = [ident]
    if package:
        ev["package"] = package
    f = Finding(tool=tool, title=f"{tool} finding", description="d",
                endpoint=endpoint, cwe=cwe, file=file, evidence=ev)
    f.id = fid
    return f


class TestCorrelationKeys(unittest.TestCase):
    def test_keys_are_normalized(self):
        f = _mk("npm-audit", "WT-NPM-0001", ident="ghsa-aaaa-bbbb-cccc", package="Lodash")
        keys = correlation_keys(f)
        self.assertIn("id:GHSA-AAAA-BBBB-CCCC", keys)  # identifier upper-cased
        self.assertIn("dep:lodash", keys)              # package lower-cased

    def test_endpoint_and_cwe_keys(self):
        f = _mk("zap", "WT-ZAP-0001", endpoint="http://localhost:3000/api/", cwe="CWE-79")
        keys = correlation_keys(f)
        self.assertIn("endpoint:http://localhost:3000/api", keys)  # trailing slash stripped
        self.assertIn("cwe@ep:CWE-79:http://localhost:3000/api", keys)


class TestCorrelate(unittest.TestCase):
    def test_cross_tool_shared_identifier_correlates(self):
        a = _mk("npm-audit", "WT-NPM-0001", ident="GHSA-XXXX-YYYY-ZZZZ")
        b = _mk("osv-scanner", "WT-OSV-0001", ident="GHSA-XXXX-YYYY-ZZZZ")
        groups = correlate([a, b])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["group"], "COR-0001")
        self.assertEqual(groups[0]["tools"], ["npm-audit", "osv-scanner"])
        self.assertIn("id:GHSA-XXXX-YYYY-ZZZZ", groups[0]["keys"])
        # Both members promoted to CORRELATED — never VERIFIED.
        self.assertEqual(a.status, Status.CORRELATED)
        self.assertEqual(b.status, Status.CORRELATED)
        self.assertEqual(a.evidence["correlation_group"], "COR-0001")
        self.assertEqual(a.evidence["correlated_with"], ["WT-OSV-0001"])
        self.assertEqual(a.verification["method"], "correlation")
        self.assertEqual(a.verification["result"], "corroborated")

    def test_same_tool_duplicate_is_not_correlation(self):
        a = _mk("npm-audit", "WT-NPM-0001", ident="GHSA-AAAA-BBBB-CCCC")
        b = _mk("npm-audit", "WT-NPM-0002", ident="GHSA-AAAA-BBBB-CCCC")
        groups = correlate([a, b])
        self.assertEqual(groups, [])
        self.assertEqual(a.status, Status.SUSPECTED)
        self.assertEqual(b.status, Status.SUSPECTED)
        self.assertNotIn("correlation_group", a.evidence)

    def test_no_shared_key_no_group(self):
        a = _mk("npm-audit", "WT-NPM-0001", ident="GHSA-1111-2222-3333")
        b = _mk("security-headers", "WT-HDR-0001", endpoint="http://localhost:3000/")
        self.assertEqual(correlate([a, b]), [])
        self.assertEqual(a.status, Status.SUSPECTED)
        self.assertEqual(b.status, Status.SUSPECTED)

    def test_dependency_name_correlates_across_tools(self):
        a = _mk("npm-audit", "WT-NPM-0001", package="lodash")
        b = _mk("osv-scanner", "WT-OSV-0001", package="lodash")
        groups = correlate([a, b])
        self.assertEqual(len(groups), 1)
        self.assertIn("dep:lodash", groups[0]["keys"])

    def test_endpoint_cwe_correlates_and_reads_back(self):
        a = _mk("zap", "WT-ZAP-0001", endpoint="http://localhost:3000/api", cwe="CWE-79")
        b = _mk("nuclei", "WT-NUC-0001", endpoint="http://localhost:3000/api", cwe="CWE-79")
        correlate([a, b])
        read = correlation_groups([a, b])
        self.assertEqual(len(read), 1)
        self.assertEqual(read[0]["group"], "COR-0001")
        self.assertEqual(read[0]["tools"], ["nuclei", "zap"])
        # Read-back reflects the final (correlated) status of each member.
        self.assertTrue(all(m["status"] == Status.CORRELATED for m in read[0]["members"]))

    def test_empty_input(self):
        self.assertEqual(correlate([]), [])


if __name__ == "__main__":
    unittest.main()
