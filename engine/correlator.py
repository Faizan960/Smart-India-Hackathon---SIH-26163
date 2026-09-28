"""Cross-tool correlation — raise confidence when independent sources agree.

Correlation is NOT verification. When findings from *different* tools describe the same
underlying issue (shared advisory identifier, same dependency, same endpoint, or same
file+CWE), that mutual corroboration promotes the SUSPECTED findings in the group to
CORRELATED. It never moves a finding to VERIFIED — only a probe can do that.

This is deliberately broader than :mod:`engine.dedup` (which only groups the *same*
advisory by shared GHSA/CVE id). A correlation group must span at least two distinct
tools; a single tool reporting something twice is a duplicate, not corroboration.
"""
from __future__ import annotations

from engine import lifecycle
from model.finding import Status


def _norm_ep(ep: str) -> str:
    return (ep or "").rstrip("/").lower()


def correlation_keys(finding) -> set:
    """The correlation keys a finding participates in; a shared key links two findings."""
    keys = set()
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    for ident in ev.get("identifiers", []) or []:
        keys.add(f"id:{str(ident).upper()}")
    pkg = ev.get("package")
    if pkg:
        keys.add(f"dep:{str(pkg).lower()}")
    if finding.endpoint:
        keys.add(f"endpoint:{_norm_ep(finding.endpoint)}")
    if finding.cwe and finding.endpoint:
        keys.add(f"cwe@ep:{finding.cwe}:{_norm_ep(finding.endpoint)}")
    if finding.cwe and finding.file:
        keys.add(f"cwe@file:{finding.cwe}:{finding.file}")
    return keys


def _union_find(findings):
    parent = list(range(len(findings)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    finding_keys = [correlation_keys(f) for f in findings]
    owner = {}
    for idx, keys in enumerate(finding_keys):
        for key in keys:
            if key in owner:
                union(owner[key], idx)
            else:
                owner[key] = idx
    groups = {}
    for idx in range(len(findings)):
        groups.setdefault(find(idx), []).append(idx)
    return groups, finding_keys


def _shared_keys(finding_keys, members) -> list:
    """Keys common to the whole group, else the union (for transitively-linked groups)."""
    sets = [finding_keys[i] for i in members]
    common = set.intersection(*sets) if sets else set()
    return sorted(common) if common else sorted(set().union(*sets)) if sets else []


def correlate(findings) -> list:
    """Tag cross-tool correlation groups and promote corroborated findings to CORRELATED.

    Returns the list of correlation-group dicts. Mutates findings: sets
    ``evidence['correlation_group' | 'correlated_with' | 'correlation_keys']`` and records
    a lifecycle transition to CORRELATED for each member that is still promotable.
    """
    if not findings:
        return []
    groups, finding_keys = _union_find(findings)
    result = []
    counter = 0
    for root in sorted(groups):
        members = groups[root]
        if len(members) < 2:
            continue
        tools = sorted({findings[i].tool for i in members})
        if len(tools) < 2:
            continue  # duplicates within one tool are not cross-tool corroboration
        counter += 1
        gid = f"COR-{counter:04d}"
        shared = _shared_keys(finding_keys, members)
        ids = [findings[i].id for i in members if findings[i].id]
        member_views = []
        for i in members:
            f = findings[i]
            if isinstance(f.evidence, dict):
                f.evidence["correlation_group"] = gid
                f.evidence["correlated_with"] = [x for x in ids if x != f.id]
                f.evidence["correlation_keys"] = shared
            lifecycle.transition(
                f, Status.CORRELATED, actor="correlator", method="correlation",
                result="corroborated",
                rationale=(f"Corroborated by {len(tools)} independent tools "
                           f"({', '.join(tools)}) sharing {', '.join(shared)}. Correlation "
                           "raises confidence; it is not verification."))
            member_views.append({"id": f.id, "tool": f.tool, "title": f.title, "status": f.status})
        result.append({"group": gid, "keys": shared, "tools": tools, "members": member_views})
    return result


def correlation_groups(findings) -> list:
    """Read back correlation groups already tagged on findings (reflects final status)."""
    groups = {}
    for f in findings:
        ev = f.evidence if isinstance(f.evidence, dict) else {}
        gid = ev.get("correlation_group")
        if not gid:
            continue
        group = groups.setdefault(gid, {"group": gid, "keys": ev.get("correlation_keys", []),
                                        "tools": set(), "members": []})
        group["tools"].add(f.tool)
        group["members"].append({"id": f.id, "tool": f.tool, "title": f.title, "status": f.status})
    out = []
    for gid in sorted(groups):
        group = groups[gid]
        group["tools"] = sorted(group["tools"])
        out.append(group)
    return out
