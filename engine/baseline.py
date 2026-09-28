"""Canonical assessment baseline (Phase 6, Step 2).

A baseline is a deterministic, secret-free projection of a WATCHTOWER report
(``report.json``) capturing exactly what is needed to compare two assessments over
time: the target/commit context, the reproducibility manifest, the static attack
surface, and every finding keyed by its STABLE identity. It deliberately drops
per-run ephemeral data (evidence graph, explanations, raw tool blobs, timing, the
per-endpoint tested_by linkage) so that the same report always yields byte-identical
baseline bytes.

Identity rules — reused from the existing pipeline, NOT a parallel identity system:
  * Finding identity  = ``Finding.fingerprint()`` (already stored on every report
    finding; recomputed via the shared engine.diff helper only as a fallback).
  * Endpoint identity = the normalised ``endpoint.path`` produced by
    engine.attack_surface (``/api/..``, ``convex:module.fn``, middleware literal).

Secrets never enter a baseline: findings are projected through a strict allow-list
(the raw ``evidence`` blob is dropped), the reproducibility ``configuration`` is the
already-sanitised ``config_manifest()``, and a defensive scrub redacts any value that
lands under a secret-named key.
"""
from __future__ import annotations

import json
import re

from engine.diff import _recompute_fingerprint

BASELINE_SCHEMA_VERSION = "1.0"
BASELINE_KIND = "watchtower-baseline"

# Defence-in-depth: redact any value whose KEY looks secret-bearing. With the current
# allow-listed projection this is a no-op (no such keys are ever copied), but it protects
# the baseline if an upstream structure later starts carrying a secret-named field.
_SECRET_KEY_RE = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|HMAC|PRIVATE|CREDENTIAL|SALT|SIGNING)", re.I)
_REDACTED = "[REDACTED]"


def _scrub(value):
    """Recursively redact values stored under secret-named keys (defence-in-depth)."""
    if isinstance(value, dict):
        return {k: (_REDACTED if isinstance(k, str) and _SECRET_KEY_RE.search(k)
                    else _scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _finding_identity(fd: dict) -> str:
    """The finding's stable fingerprint — read from the report, recomputed if absent."""
    return fd.get("fingerprint") or _recompute_fingerprint(fd)


def _project_finding(fd: dict) -> dict:
    """Allow-listed, secret-free projection of one report finding."""
    verification = fd.get("verification") or {}
    score = fd.get("score") or {}
    return {
        "fingerprint": _finding_identity(fd),      # stable finding identity
        "id": fd.get("id"),                        # per-run ordering label, reference only
        "tool": fd.get("tool"),
        "title": fd.get("title"),
        "severity": fd.get("severity"),
        "status": fd.get("status"),                # lifecycle status
        "cwe": fd.get("cwe"),
        "file": fd.get("file"),
        "line": fd.get("line"),
        "endpoint": fd.get("endpoint"),
        "verification": {                          # verification RESULT preserved (not evidence)
            "method": verification.get("method"),
            "result": verification.get("result"),
            "probe": verification.get("probe"),
            "rationale": verification.get("rationale"),
        },
        "risk_score": score.get("value"),          # WATCHTOWER Risk Score (NOT CVSS)
        "score_model": score.get("model"),
        "evidence_confidence": fd.get("evidence_confidence"),
    }


def _project_endpoint(ep: dict) -> dict:
    """Allow-listed projection of one attack-surface endpoint (identity = path)."""
    return {
        "path": ep.get("path"),                    # endpoint identity
        "method": ep.get("method"),
        "methods": list(ep.get("methods") or []),
        "component": ep.get("component"),
        "authentication": ep.get("authentication"),
        "kind": ep.get("kind"),
        "risk_tags": sorted(ep.get("risk_tags") or []),
        "source_file": ep.get("source_file"),
    }


def _project_attack_surface(surface: dict) -> dict:
    """Attack-surface projection with endpoints sorted by their path identity."""
    surface = surface or {}
    endpoints = [_project_endpoint(ep) for ep in (surface.get("endpoints") or [])]
    endpoints.sort(key=lambda e: (e["path"] or "", e.get("method") or ""))
    integrations = sorted(
        ({"name": i.get("name"), "kind": i.get("kind")}
         for i in (surface.get("integrations") or [])),
        key=lambda i: (i["name"] or ""))
    return {
        "summary": surface.get("summary") or {"endpoint_count": len(endpoints)},
        "endpoints": endpoints,
        "integrations": integrations,
    }


def _project_summary(report: dict) -> dict:
    """Rollup counts reused from the report summary (no recomputation, no drift)."""
    s = report.get("summary") or {}
    surface = report.get("attack_surface") or {}
    endpoint_count = (surface.get("summary") or {}).get(
        "endpoint_count", len(surface.get("endpoints") or []))
    return {
        "total_findings": s.get("total_findings", len(report.get("findings") or [])),
        "severity": {k: s.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "lifecycle": {k: s.get(k, 0) for k in (
            "suspected", "correlated", "verified", "false_positive", "needs_manual_review")},
        "verification_results": dict(s.get("verification_results") or {}),
        "attack_surface_endpoints": endpoint_count,
    }


def build_baseline(report: dict) -> dict:
    """Build the canonical, deterministic baseline from a WATCHTOWER report dict.

    Pure and side-effect free: no wall-clock reads, all collections pre-sorted, so
    ``build_baseline(r)`` is identical across calls and ``save_baseline`` is byte-stable.
    """
    assessment = report.get("assessment") or {}
    environment = report.get("environment") or {}

    findings = [_project_finding(fd) for fd in (report.get("findings") or [])]
    findings.sort(key=lambda f: (f["fingerprint"] or "", f.get("id") or "",
                                 f.get("title") or ""))

    baseline = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": BASELINE_KIND,
        "assessment": {
            "id": assessment.get("id"),
            "timestamp": assessment.get("timestamp"),
            "watchtower_version": report.get("watchtower_version"),
            "report_schema_version": report.get("schema_version"),
        },
        "target": {
            "target": assessment.get("target"),
            "repository": assessment.get("repository"),
            "commit": assessment.get("commit"),
            "branch": assessment.get("branch"),
        },
        "reproducibility": {
            "watchtower_version": environment.get("watchtower_version"),
            "python_version": environment.get("python_version"),
            "platform": environment.get("platform"),
            "probe_versions": dict(environment.get("probe_versions") or {}),
            "scanner_versions": dict(environment.get("scanner_versions") or {}),
            "configuration": environment.get("configuration") or {},
        },
        "attack_surface": _project_attack_surface(report.get("attack_surface")),
        "findings": findings,
        "summary": _project_summary(report),
    }
    return _scrub(baseline)


def save_baseline(path: str, baseline: dict) -> str:
    """Serialise deterministically (sort_keys) so equal baselines are byte-identical."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")
    return path


def load_baseline(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def render_summary(baseline: dict) -> list:
    """Human-readable lines for `watchtower baseline show`."""
    a, t = baseline.get("assessment", {}), baseline.get("target", {})
    s = baseline.get("summary", {})
    sev, life = s.get("severity", {}), s.get("lifecycle", {})
    return [
        f"schema_version: {baseline.get('schema_version')}  ({baseline.get('kind')})",
        f"assessment:     {a.get('id')}  (watchtower {a.get('watchtower_version')})",
        f"timestamp:      {a.get('timestamp')}",
        f"target:         {t.get('target')}",
        f"repository:     {t.get('repository')}  commit={t.get('commit')}  "
        f"branch={t.get('branch')}",
        f"findings:       {s.get('total_findings', 0)}  "
        f"(critical={sev.get('critical', 0)} high={sev.get('high', 0)} "
        f"medium={sev.get('medium', 0)} low={sev.get('low', 0)} info={sev.get('info', 0)})",
        f"lifecycle:      verified={life.get('verified', 0)} "
        f"needs_review={life.get('needs_manual_review', 0)} "
        f"false_positive={life.get('false_positive', 0)} "
        f"correlated={life.get('correlated', 0)} suspected={life.get('suspected', 0)}",
        f"attack surface: {s.get('attack_surface_endpoints', 0)} endpoint(s) "
        "(assessment targets, NOT vulnerabilities)",
    ]


