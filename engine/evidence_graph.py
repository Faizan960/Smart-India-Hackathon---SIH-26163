"""Evidence graph: typed relationships between findings, tools, endpoints and assets.

Phase 5, item 4. The graph records six relationship types —

  discovered_by : finding  -> the scanner/probe that first reported it
  tested_by     : finding  -> the probe/verifier that exercised it
  verified_by   : finding  -> the verification that reached a definitive verdict
  supported_by  : finding  -> corroborating findings (a correlation group)
  related_to    : finding  -> an attack-surface endpoint or a duplicate sibling
  affects       : finding  -> the component/asset it pertains to

so that every finding can expose its full evidence chain. The graph is built from
facts already recorded on the findings (tool, verification, correlation, dedup,
asset) and the linked attack surface — it introduces no new claims.
"""
from __future__ import annotations

from engine.lifecycle import CONFIRMED, NOT_APPLICABLE, REFUTED

DISCOVERED_BY = "discovered_by"
TESTED_BY = "tested_by"
VERIFIED_BY = "verified_by"
SUPPORTED_BY = "supported_by"
RELATED_TO = "related_to"
AFFECTS = "affects"
RELATIONS = (DISCOVERED_BY, TESTED_BY, VERIFIED_BY, SUPPORTED_BY, RELATED_TO, AFFECTS)

_DEFINITIVE = (CONFIRMED, REFUTED, NOT_APPLICABLE)


class EvidenceGraph:
    def __init__(self):
        self.nodes: dict = {}
        self.edges: list = []

    def add_node(self, node_id: str, node_type: str, label: str = "", **data):
        if node_id not in self.nodes:
            self.nodes[node_id] = {"id": node_id, "type": node_type,
                                   "label": label or node_id, **data}

    def add_edge(self, source: str, relation: str, target: str, **data):
        self.edges.append({"source": source, "relation": relation,
                           "target": target, "data": data})

    def chain_for(self, finding_id: str) -> dict:
        """Return the evidence chain for one finding, grouped by relationship."""
        chain = {rel: [] for rel in RELATIONS}
        for edge in self.edges:
            if edge["source"] == finding_id and edge["relation"] in chain:
                entry = {"target": edge["target"],
                         "label": self.nodes.get(edge["target"], {}).get("label",
                                                                          edge["target"])}
                if edge["data"]:
                    entry.update(edge["data"])
                chain[edge["relation"]].append(entry)
        return chain

    def to_dict(self) -> dict:
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges),
                "relations": list(RELATIONS)}


def build_evidence_graph(findings, endpoint_dicts=None, reverse_links=None,
                         correlation=None) -> EvidenceGraph:
    """Assemble the evidence graph from findings and the linked attack surface."""
    graph = EvidenceGraph()
    reverse_links = reverse_links or {}
    endpoint_dicts = endpoint_dicts or []

    # Attack-surface endpoints are discovered statically; record that provenance.
    graph.add_node("source:static-analysis", "source", "static analysis")
    for ep in endpoint_dicts:
        node_id = f"endpoint:{ep.get('path')}"
        graph.add_node(node_id, "endpoint", ep.get("path", ""),
                       component=ep.get("component"), risk_tags=ep.get("risk_tags", []),
                       tested=ep.get("tested", False))
        graph.add_edge(node_id, DISCOVERED_BY, "source:static-analysis")

    for finding in findings:
        fid = finding.id or finding.fingerprint()
        graph.add_node(fid, "finding", finding.title, tool=finding.tool,
                       status=finding.status, severity=finding.severity)

        tool_node = f"tool:{finding.tool}"
        graph.add_node(tool_node, "tool", finding.tool)
        graph.add_edge(fid, DISCOVERED_BY, tool_node)

        verification = finding.verification or {}
        method, result = verification.get("method"), verification.get("result")
        if method and method != "none":
            probe_node = f"probe:{verification.get('probe') or method}"
            graph.add_node(probe_node, "probe", verification.get("probe") or method,
                           method=method)
            graph.add_edge(fid, TESTED_BY, probe_node, method=method)
            if result in _DEFINITIVE:
                actor = ((finding.evidence or {}).get("lifecycle") or [{}])[-1].get("actor")
                graph.add_edge(fid, VERIFIED_BY, probe_node, result=result, actor=actor)

        # affects -> the asset/component the finding pertains to.
        asset_ref = (finding.asset or {}).get("ref")
        related = reverse_links.get(finding.id, [])
        component = related[0]["component"] if related else (finding.asset or {}).get("kind")
        if asset_ref or component:
            comp_id = f"component:{component or asset_ref}"
            graph.add_node(comp_id, "component", str(component or asset_ref))
            graph.add_edge(fid, AFFECTS, comp_id, asset_ref=asset_ref)

        # related_to -> attack-surface endpoints the finding was linked to.
        for ref in related:
            graph.add_edge(fid, RELATED_TO, f"endpoint:{ref['path']}",
                           risk_tags=ref.get("risk_tags", []))
        # related_to -> duplicate siblings (same advisory, multiple sources).
        dedup = (finding.evidence or {}).get("dedup_group")
        if dedup:
            graph.add_edge(fid, RELATED_TO, f"dedup:{dedup}", kind="duplicate")

    _add_correlation_support(graph, findings, correlation)
    return graph


def _add_correlation_support(graph: EvidenceGraph, findings, correlation):
    """supported_by edges: each correlation-group member corroborates the others."""
    if not correlation:
        return
    by_id = {f.id: f for f in findings}
    for group in correlation:
        members = [m.get("id") for m in group.get("members", []) if m.get("id")]
        group_node = f"group:{group.get('group')}"
        graph.add_node(group_node, "correlation_group", group.get("group", ""),
                       keys=group.get("keys", []), tools=group.get("tools", []))
        for mid in members:
            if mid not in by_id:
                continue
            graph.add_edge(mid, SUPPORTED_BY, group_node,
                           corroborated_by=[o for o in members if o != mid])

