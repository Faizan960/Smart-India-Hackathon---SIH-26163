"""Deterministic duplicate grouping — NOT correlation.

Phase 2 only groups findings that are provably the *same* vulnerability reported by
more than one source: today that means findings sharing a vulnerability identifier
(GHSA-*/CVE-*), e.g. the same advisory surfaced by both OSV-Scanner and npm audit.
Findings are never merged — each keeps its own source tool and evidence; we only tag
them with a shared group id so the report can show "one logical vuln, N sources."

This makes no cross-tool *correlation* claim (that a signal is corroborated across
independent techniques). That is deliberately deferred to a later phase.
"""
from __future__ import annotations

from typing import Optional


def _identifiers(finding) -> list:
    ev = getattr(finding, "evidence", None)
    if not isinstance(ev, dict):
        return []
    ids = ev.get("identifiers")
    return [str(x).upper() for x in ids] if isinstance(ids, list) else []


def group_duplicates(findings: list) -> list:
    """Tag findings that share a vulnerability identifier with a common group id.

    Uses union-find over shared GHSA-/CVE- identifiers. Only groups with more than one
    member are labelled (evidence['dedup_group'] = 'DUP-####'); singletons are left
    untouched. Deterministic: group order follows each group's smallest fingerprint.
    """
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    # Link any two findings that share at least one identifier.
    seen: dict[str, int] = {}
    for idx, finding in enumerate(findings):
        for token in _identifiers(finding):
            if token in seen:
                union(seen[token], idx)
            else:
                seen[token] = idx

    clusters: dict[int, list[int]] = {}
    for idx in range(len(findings)):
        clusters.setdefault(find(idx), []).append(idx)

    multi = [members for members in clusters.values() if len(members) > 1]
    # Deterministic ordering by the smallest fingerprint in each cluster.
    multi.sort(key=lambda members: min(findings[i].fingerprint() for i in members))
    for number, members in enumerate(multi, start=1):
        label = f"DUP-{number:04d}"
        for i in members:
            if isinstance(findings[i].evidence, dict):
                findings[i].evidence["dedup_group"] = label
    return findings


def duplicate_groups(findings: list) -> list:
    """Build the report-facing list of duplicate groups (called after IDs are assigned)."""
    groups: dict[str, dict] = {}
    for finding in findings:
        ev = getattr(finding, "evidence", None)
        if not isinstance(ev, dict):
            continue
        label = ev.get("dedup_group")
        if not label:
            continue
        entry = groups.setdefault(label, {"group": label, "identifiers": [], "members": [], "tools": []})
        entry["members"].append({"id": finding.id, "tool": finding.tool, "title": finding.title})
        for token in _identifiers(finding):
            if token not in entry["identifiers"]:
                entry["identifiers"].append(token)
        if finding.tool not in entry["tools"]:
            entry["tools"].append(finding.tool)
    return [groups[label] for label in sorted(groups)]
