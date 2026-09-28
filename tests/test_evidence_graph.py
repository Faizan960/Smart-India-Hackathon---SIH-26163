"""Tests for the evidence graph and per-finding evidence chains (Phase 5, item 4)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import evidence_graph as eg  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402


def make_findings():
    scanner = Finding(tool="semgrep", title="eval", description="d", severity=Severity.HIGH,
                      status=Status.SUSPECTED, id="WT-SEM-0001", file="api/x.ts", line=3,
                      asset={"kind": "api", "ref": "api/x.ts", "weight": 1.0})
    probe = Finding(tool="cors", title="cors", description="d", severity=Severity.HIGH,
                    status=Status.VERIFIED, id="WT-CORS-0001",
                    endpoint="http://localhost:3000/api/mcp-proxy",
                    verification={"method": "active_probe", "probe": "cors",
                                  "result": "confirmed", "rationale": "reflected"},
                    evidence={"lifecycle": [{"actor": "CorsVerifier"}]})
    return [scanner, probe]


class TestEvidenceGraph(unittest.TestCase):
    def test_finding_discovered_by_its_tool(self):
        graph = eg.build_evidence_graph(make_findings())
        chain = graph.chain_for("WT-SEM-0001")
        targets = [e["target"] for e in chain[eg.DISCOVERED_BY]]
        self.assertIn("tool:semgrep", targets)

    def test_verified_probe_has_tested_and_verified_edges(self):
        graph = eg.build_evidence_graph(make_findings())
        chain = graph.chain_for("WT-CORS-0001")
        self.assertTrue(chain[eg.TESTED_BY])
        self.assertTrue(chain[eg.VERIFIED_BY])
        self.assertEqual(chain[eg.VERIFIED_BY][0]["result"], "confirmed")
        self.assertEqual(chain[eg.VERIFIED_BY][0]["actor"], "CorsVerifier")

    def test_unverified_finding_has_no_verified_edge(self):
        graph = eg.build_evidence_graph(make_findings())
        chain = graph.chain_for("WT-SEM-0001")
        self.assertEqual(chain[eg.VERIFIED_BY], [])
        self.assertEqual(chain[eg.TESTED_BY], [])

    def test_related_to_endpoint_via_links(self):
        findings = make_findings()
        endpoint_dicts = [{"path": "/api/mcp-proxy", "component": "core",
                           "risk_tags": ["mcp"], "tested": True}]
        reverse = {"WT-CORS-0001": [{"path": "/api/mcp-proxy", "component": "core",
                                     "risk_tags": ["mcp"]}]}
        graph = eg.build_evidence_graph(findings, endpoint_dicts, reverse)
        chain = graph.chain_for("WT-CORS-0001")
        related = [e["target"] for e in chain[eg.RELATED_TO]]
        self.assertIn("endpoint:/api/mcp-proxy", related)

    def test_endpoint_discovered_by_static_analysis(self):
        endpoint_dicts = [{"path": "/api/rss-proxy", "component": "core",
                           "risk_tags": ["ssrf_candidate"], "tested": False}]
        graph = eg.build_evidence_graph(make_findings(), endpoint_dicts)
        chain = graph.chain_for("endpoint:/api/rss-proxy")
        self.assertIn("source:static-analysis",
                      [e["target"] for e in chain[eg.DISCOVERED_BY]])

    def test_correlation_produces_supported_by(self):
        findings = make_findings()
        correlation = [{"group": "COR-0001", "keys": ["cwe@ep:CWE-79:/x"],
                        "tools": ["semgrep", "cors"],
                        "members": [{"id": "WT-SEM-0001"}, {"id": "WT-CORS-0001"}]}]
        graph = eg.build_evidence_graph(findings, correlation=correlation)
        chain = graph.chain_for("WT-SEM-0001")
        self.assertTrue(chain[eg.SUPPORTED_BY])
        self.assertIn("WT-CORS-0001", chain[eg.SUPPORTED_BY][0]["corroborated_by"])

    def test_to_dict_exposes_nodes_edges_relations(self):
        graph = eg.build_evidence_graph(make_findings())
        d = graph.to_dict()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertEqual(tuple(d["relations"]), eg.RELATIONS)


if __name__ == "__main__":
    unittest.main()
