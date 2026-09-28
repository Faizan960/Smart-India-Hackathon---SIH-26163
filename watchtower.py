#!/usr/bin/env python3
"""WATCHTOWER - CLI orchestrator (Phase 5: assessment intelligence & evidence).

Pipeline stages:
  [1] Init  [2] Attack-surface discovery (static, read-only)
  [3] Semgrep  [4] Gitleaks  [5] OSV-Scanner  [6] npm audit
  [7] Security headers  [8] OWASP ZAP  [9] Nuclei
  [10] CORS probe  [11] Rate-limit probe  [12] Auth/MCP probe  [13] SSRF canary probe
  [14] Normalize  [15] Correlate  [16] Verify  [17] Score
  [18] Assessment intelligence (link surface, evidence graph, explanations, confidence)
  [19] Report (JSON + HTML + SARIF)

Stage 2 discovers the target's attack surface statically (endpoints, RPC, MCP, auth
boundaries, external integrations, secret-sensitive modules). Attack-surface entries are
assessment TARGETS, not vulnerabilities. Stages 10-13 are active, controlled probes against
the LOCAL target: they gather runtime evidence that the Verify stage later classifies.
Correlation raises confidence when independent tools agree (-> correlated); it never verifies.
Verification runs safe, local-only verifiers and is the ONLY stage that may mark a finding
verified or false-positive. Scoring runs last so the WATCHTOWER Risk Score reflects each
finding's final lifecycle status. Stage 18 links the static surface to the runtime findings,
builds the evidence graph, and derives per-finding explanations and evidence confidence.

Active probes refuse a non-local target by default (loopback only); a bounded request count,
a loopback-only SSRF canary, and metadata-only response capture keep them non-abusive. Each
stage records an honest execution status: a disabled/refused stage is 'skipped', a crash is
'failed', a real run is 'success'. Only the local repository and the local target are touched.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from config import (ConfigError, PROBE_VERSIONS, SCANNER_TOOLS, WATCHTOWER_VERSION,
                    WatchtowerConfig)
from checks.security_headers import run_headers_probe
from checks.cors import run_cors_probe
from checks.rate_limit import run_rate_limit_probe
from checks.auth_mcp import run_auth_probe
from checks.ssrf import run_ssrf_probe
from checks.verifiers import VerificationContext, run_verifiers
from engine import correlator, normalizer, scorer
from engine.attack_surface import discover_attack_surface
from engine.baseline import build_baseline, load_baseline, render_summary, save_baseline
from engine.diff import diff_reports
from engine.gate import evaluate_gate, exit_code_for, render_gate
from engine.evidence import EvidenceStore
from engine.execution import ToolExecution
from engine.git_meta import get_git_metadata
from reports.html_report import write_html_report
from reports.json_report import build_report, write_json_report
from reports.sarif_report import write_sarif
from scanners.semgrep import run_semgrep
from scanners.gitleaks import run_gitleaks
from scanners.osv import run_osv
from scanners.npm_audit import run_npm_audit
from scanners.zap import run_zap
from scanners.nuclei import run_nuclei

TOTAL_STAGES = 19
_ACTIVE_PROBE_TOOLS = ("cors", "rate-limit", "auth-mcp", "ssrf")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _stage(number: int, message: str) -> None:
    print(f"[{number}/{TOTAL_STAGES}] {message}")


def _console_safe(text):
    """Make tool-provided text printable on any console (stored artefacts keep UTF-8)."""
    if text is None:
        return text
    enc = sys.stdout.encoding or "utf-8"
    return str(text).encode(enc, errors="replace").decode(enc, errors="replace")

def _report_stage(rec: ToolExecution) -> None:
    if rec.error:
        print(f"      {rec.tool}: {rec.status} - {_console_safe(rec.error)}")
    else:
        print(f"      {rec.tool}: {rec.status} ({rec.duration_seconds}s)")


def _classify(rec: ToolExecution, result) -> None:
    """Map an adapter result onto the execution record (skip / fail / success)."""
    if getattr(result, "skipped", False):
        rec.skip(getattr(result, "error", None) or "Tool unavailable.")
    elif getattr(result, "error", None):
        rec.failed(result.error, exit_code=getattr(result, "returncode", None))
    else:
        rec.success(exit_code=getattr(result, "returncode", None))


def _collector_stage(tool, skip, runner, raw_name, raw_getter, store, records):
    """Run one collector adapter, persist its raw output, and record execution."""
    rec = ToolExecution(tool)
    if skip:
        rec.skip("Disabled via --skip flag.")
        _report_stage(rec)
        records.append(rec)
        return None
    rec.start()
    result = runner()
    store.save_raw(raw_name, raw_getter(result))
    _classify(rec, result)
    _report_stage(rec)
    records.append(rec)
    return result


def _headers_stage(config, store, records):
    """Security-headers probe stage (an active HTTP probe, not an external tool)."""
    rec = ToolExecution("security-headers")
    if config.skip_headers:
        rec.skip("Disabled via --skip-headers.")
        _report_stage(rec)
        records.append(rec)
        return None
    rec.start()
    result = run_headers_probe(config.normalized_target, timeout=config.request_timeout)
    store.save_raw("headers_probe.json", {
        "url": result.url, "reachable": result.reachable, "status_code": result.status_code,
        "response_time_ms": result.response_time_ms, "headers": result.headers, "error": result.error,
    })
    if not result.reachable:
        rec.failed(result.error or "Target unreachable.")
    else:
        rec.success()
    _report_stage(rec)
    records.append(rec)
    return result


def _semgrep_raw(result):
    return result.raw_stdout or {
        "executed": result.executed, "skipped": result.skipped, "error": result.error}


def _probe_ok(tool, result) -> bool:
    """True if an active probe actually gathered runtime evidence (else it 'failed')."""
    if tool == "ssrf":
        return bool(getattr(result, "canary_bound", False))
    if tool == "auth-mcp":
        return bool(getattr(result, "reachable", False) or getattr(result, "observations", None))
    return bool(getattr(result, "reachable", False))


def _probe_stage(tool, skip, locality_ok, runner, store, records):
    """Run one active verification probe against the LOCAL target, honestly recorded.

    A disabled probe or a non-local target is 'skipped' (never disguised as clean); a probe
    that could not gather any evidence is 'failed'; a probe that ran is 'success'. The verdict
    (confirmed/refuted/inconclusive/not_applicable) is decided later, in the Verify stage.
    """
    rec = ToolExecution(tool)
    if skip:
        rec.skip(f"Disabled via --skip-{tool} flag.")
        _report_stage(rec)
        records.append(rec)
        return None
    if not locality_ok:
        rec.skip("Refused: active probe restricted to loopback targets "
                 "(use --allow-nonlocal-active to override).")
        _report_stage(rec)
        records.append(rec)
        return None
    rec.start()
    result = runner()
    store.save_raw(f"{tool}_probe.json", asdict(result))
    if getattr(result, "refused", False):
        rec.skip(getattr(result, "error", None) or "Refused: non-local target.")
    elif _probe_ok(tool, result):
        rec.success()
    else:
        rec.failed(getattr(result, "error", None) or "Probe gathered no evidence.")
    _report_stage(rec)
    records.append(rec)
    return result


def _collector_raw(result):
    return result.raw or {
        "executed": result.executed, "skipped": result.skipped, "error": result.error}


def _attack_surface_stage(config, store, records):
    """Static, read-only attack-surface discovery (Phase 5). Never modifies the target."""
    rec = ToolExecution("attack-surface")
    if config.skip_attack_surface:
        rec.skip("Disabled via --skip-attack-surface.")
        _report_stage(rec)
        records.append(rec)
        return None
    rec.start()
    try:
        surface = discover_attack_surface(config.repo_path)
        store.save_raw("attack_surface.json", surface.to_dict())
        rec.finding_count = len(surface.endpoints)
        rec.success()
        print(f"      discovered {len(surface.endpoints)} endpoint(s), "
              f"{len(surface.security_modules)} security module(s), "
              f"{len(surface.integrations)} integration(s) (targets, NOT vulnerabilities)")
    except Exception as exc:                       # discovery must never abort the run
        surface = None
        rec.failed(f"attack-surface discovery failed: {exc}")
    _report_stage(rec)
    records.append(rec)
    return surface


def _reproducibility_manifest(config, store, git_meta) -> dict:
    """Everything needed to reproduce this assessment (Phase 5, item 8)."""
    return {
        "assessment_id": store.run_id,
        "timestamp": _now_iso(),
        "target": config.normalized_target,
        "repository": config.repo_path,
        "commit": git_meta.get("commit"),
        "branch": git_meta.get("branch"),
        "git_available": git_meta.get("git_available"),
        "watchtower_version": WATCHTOWER_VERSION,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "probe_versions": dict(PROBE_VERSIONS),
        "scanner_versions": {tool: None for tool in SCANNER_TOOLS},
        "scanner_version_note": ("External scanner versions are not collected; WATCHTOWER does "
                                 "not shell out purely for --version. See execution status."),
        "configuration": config.config_manifest(),
    }


def run(config) -> int:
    records: list[ToolExecution] = []

    _stage(1, f"Initializing run (repo={config.repo_path!r}, target={config.normalized_target!r})")
    store = EvidenceStore(config.output_dir)
    git_meta = get_git_metadata(config.repo_path)
    print(f"      evidence: {store.run_dir}")

    _stage(2, "Attack-surface discovery (static, read-only)")
    attack_surface = _attack_surface_stage(config, store, records)

    _stage(3, "Semgrep static scan")
    semgrep_result = _collector_stage(
        "semgrep", config.skip_semgrep,
        lambda: run_semgrep(config.repo_path, timeout=config.semgrep_timeout),
        "semgrep.json", _semgrep_raw, store, records)

    _stage(4, "Gitleaks secret scan")
    gitleaks_result = _collector_stage(
        "gitleaks", config.skip_gitleaks,
        lambda: run_gitleaks(config.repo_path, timeout=config.gitleaks_timeout),
        "gitleaks.json", _collector_raw, store, records)

    _stage(5, "OSV-Scanner dependency scan")
    osv_result = _collector_stage(
        "osv-scanner", config.skip_osv,
        lambda: run_osv(config.repo_path, timeout=config.osv_timeout),
        "osv.json", _collector_raw, store, records)

    _stage(6, "npm audit dependency scan")
    npm_result = _collector_stage(
        "npm-audit", config.skip_npm_audit,
        lambda: run_npm_audit(config.repo_path, timeout=config.npm_audit_timeout),
        "npm_audit.json", _collector_raw, store, records)

    _stage(7, "Security-headers probe")
    headers_result = _headers_stage(config, store, records)

    _stage(8, "OWASP ZAP baseline (local target only)")
    zap_result = _collector_stage(
        "zap", config.skip_zap,
        lambda: run_zap(config.normalized_target, timeout=config.zap_timeout),
        "zap.json", _collector_raw, store, records)

    _stage(9, "Nuclei controlled scan (local target only)")
    nuclei_result = _collector_stage(
        "nuclei", config.skip_nuclei,
        lambda: run_nuclei(config.normalized_target, timeout=config.nuclei_timeout),
        "nuclei.jsonl", _collector_raw, store, records)

    local_ok = config.target_is_local or config.allow_nonlocal_active
    if not local_ok:
        print("      NOTE: target is non-local; active probes (CORS/rate-limit/auth-MCP/SSRF) "
              "are refused unless --allow-nonlocal-active is set.")

    _stage(10, "CORS probe (active, local target only)")
    cors_result = _probe_stage(
        "cors", config.skip_cors, local_ok,
        lambda: run_cors_probe(config.normalized_target, timeout=config.request_timeout,
                               allow_nonlocal=config.allow_nonlocal_active),
        store, records)

    _stage(11, "Rate-limit enforcement probe (bounded, non-abusive)")
    rate_limit_result = _probe_stage(
        "rate-limit", config.skip_rate_limit, local_ok,
        lambda: run_rate_limit_probe(config.normalized_target, count=config.rate_limit_count,
                                     timeout=config.request_timeout,
                                     allow_nonlocal=config.allow_nonlocal_active),
        store, records)

    _stage(12, "Auth/MCP access-control probe (no credential guessing)")
    auth_result = _probe_stage(
        "auth-mcp", config.skip_auth_mcp, local_ok,
        lambda: run_auth_probe(config.normalized_target, timeout=config.request_timeout,
                               allow_nonlocal=config.allow_nonlocal_active),
        store, records)

    _stage(13, "SSRF local-canary probe (loopback canary only)")
    ssrf_result = _probe_stage(
        "ssrf", config.skip_ssrf, local_ok,
        lambda: run_ssrf_probe(config.normalized_target, canary_port=config.canary_port,
                               timeout=config.request_timeout,
                               allow_nonlocal=config.allow_nonlocal_active),
        store, records)

    _stage(14, "Normalizing findings")
    findings = normalizer.normalize(
        semgrep_result=semgrep_result,
        gitleaks_result=gitleaks_result,
        osv_result=osv_result,
        npm_audit_result=npm_result,
        headers_result=headers_result,
        zap_result=zap_result,
        nuclei_result=nuclei_result,
        cors_result=cors_result,
        rate_limit_result=rate_limit_result,
        auth_mcp_result=auth_result,
        ssrf_result=ssrf_result,
        repo_path=config.repo_path,
    )
    counts = Counter(f.tool for f in findings)
    for rec in records:
        rec.finding_count = counts.get(rec.tool, 0)
    print(f"      normalized {len(findings)} finding(s)")

    _stage(15, "Correlating findings across tools")
    correlation = correlator.correlate(findings)
    print(f"      {len(correlation)} correlation group(s) (cross-tool corroboration -> correlated)")

    _stage(16, "Verifying findings (safe, local-only probes)")
    context = VerificationContext.build(
        repo_path=config.repo_path, target_url=config.normalized_target)
    verify_counts = run_verifiers(findings, context)
    applied = sum(verify_counts.values())
    print(f"      {applied} verification transition(s): "
          + ", ".join(f"{name}={n}" for name, n in verify_counts.items()))

    _stage(17, "Calculating WATCHTOWER Risk Scores")
    scorer.score_all(findings)

    _stage(18, "Assessment intelligence (evidence graph, explanations, confidence)")
    environment = _reproducibility_manifest(config, store, git_meta)
    print(f"      assessment id: {environment['assessment_id']} · "
          f"python {environment['python_version']} · watchtower {WATCHTOWER_VERSION}")

    _stage(19, "Generating reports (JSON + HTML + SARIF)")
    scan = {
        "timestamp": environment["timestamp"],
        "target": config.normalized_target,
        "repository": config.repo_path,
        "commit": git_meta.get("commit"),
        "branch": git_meta.get("branch"),
    }
    execution = [rec.to_dict() for rec in records]
    # Load the prior assessment (if any) BEFORE building the report so the structured diff
    # and a baseline-aware gate can be embedded directly into report.json (schema 1.2).
    baseline = _load_baseline_for_diff(config.diff_against) if config.diff_against else None
    report = build_report(findings, scan, WATCHTOWER_VERSION, execution=execution,
                          attack_surface=attack_surface, environment=environment,
                          assessment_id=store.run_id, baseline=baseline)
    store.save_findings(findings)
    store.save_metadata({
        "scan": scan,
        "execution": execution,
        "git": git_meta,
        "watchtower_version": WATCHTOWER_VERSION,
        "reproducibility": environment,
        "analysis": {
            "attack_surface_summary": (report["attack_surface"].get("summary")
                                       if report.get("attack_surface") else None),
            "correlation_groups": correlation,
            "verification_transitions": verify_counts,
            "assessment_limitations": report.get("assessment_limitations"),
        },
    })
    json_path = write_json_report(store.path("report.json"), report)
    html_path = write_html_report(store.path("report.html"), report)
    sarif_path = write_sarif(store.path("report.sarif"), report)
    print(f"      json:  {json_path}")
    print(f"      html:  {html_path}")
    print(f"      sarif: {sarif_path}")

    if report.get("diff") is not None:
        _write_diff_artifact(report["diff"], store)
    _print_gate(report["gate"])

    _print_summary(report, records, store)
    return 0


def _load_baseline_for_diff(baseline_path: str):
    """Load a prior report.json / baseline.json to diff against, or None on failure.

    File I/O (CLI-only concern) lives here; the structured diff itself is produced inside
    build_report via engine.diff, so this never duplicates diff logic.
    """
    try:
        with open(baseline_path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"      diff: SKIPPED - could not read baseline {baseline_path!r}: {exc}")
        return None


def _write_diff_artifact(diff: dict, store) -> None:
    """Persist the already-computed structured diff (from report['diff']) to report.diff.json.

    The diff is NOT recomputed here — it is the exact object embedded in report.json, so the
    standalone artefact and the in-report section can never disagree.
    """
    path = store.path("report.diff.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(diff, handle, indent=2, ensure_ascii=False)
    c = diff["counts"]
    print(f"      diff:  {path}")
    print(f"      diff vs baseline: new={c['new']} resolved={c['resolved']} "
          f"status_changed={c['status_changed']} surface_added={c['surface_added']} "
          f"surface_removed={c['surface_removed']} (causality NOT inferred)")


def _print_gate(gate: dict) -> None:
    """Print the embedded structured gate result (report['gate']) for console visibility."""
    for line in render_gate(gate):
        print(f"      {line.strip()}" if line.startswith("gate result") else f"        {line.strip()}")


def _print_summary(report, records, store) -> None:
    summary = report["summary"]
    print("\n" + "=" * 60)
    print("WATCHTOWER assessment summary")
    print("=" * 60)
    print(
        f"  findings: {summary['total_findings']}  "
        f"(critical={summary['critical']} high={summary['high']} "
        f"medium={summary['medium']} low={summary['low']} info={summary['info']})"
    )
    print(
        f"  lifecycle: suspected={summary['suspected']} correlated={summary['correlated']} "
        f"verified={summary['verified']} needs_review={summary['needs_manual_review']} "
        f"false_positive={summary['false_positive']}"
    )
    vr = summary.get("verification_results") or {}
    if vr:
        print(
            f"  verification results: confirmed={vr.get('confirmed', 0)} "
            f"refuted={vr.get('refuted', 0)} inconclusive={vr.get('inconclusive', 0)} "
            f"not_applicable={vr.get('not_applicable', 0)}"
        )
    conf = summary.get("evidence_confidence") or {}
    if conf:
        print(f"  evidence confidence: high={conf.get('high', 0)} "
              f"medium={conf.get('medium', 0)} low={conf.get('low', 0)} "
              "(evidence completeness - NOT severity, score, or lifecycle status)")
    asf = report.get("attack_surface") or {}
    asf_summary = asf.get("summary") or {}
    if asf_summary.get("endpoint_count"):
        print(f"  attack surface: {asf_summary.get('endpoint_count', 0)} endpoint(s), "
              f"{asf_summary.get('security_module_count', 0)} security module(s), "
              f"{asf_summary.get('integration_count', 0)} integration(s) "
              "(assessment targets, NOT vulnerabilities)")
    active_recs = [rec for rec in records if rec.tool in _ACTIVE_PROBE_TOOLS]
    if active_recs:
        ran = sum(1 for rec in active_recs if rec.status == "success")
        print(
            f"  active probes: {ran}/{len(active_recs)} ran "
            f"({summary.get('active_probe_findings', 0)} finding(s)) - "
            + ", ".join(f"{rec.tool}={rec.status}" for rec in active_recs)
        )
    for rec in records:
        line = f"  {rec.tool}: {rec.status} ({rec.finding_count} finding(s), {rec.duration_seconds}s)"
        if rec.error:
            line += f" - {_console_safe(rec.error)}"
        print(line)
    dup = report.get("duplicate_groups") or []
    if dup:
        print(f"  duplicate groups: {len(dup)} (same vuln reported by multiple tools)")
    cor = report.get("correlation_groups") or []
    if cor:
        print(f"  correlation groups (count): {len(cor)}; "
              f"findings currently correlated: {summary.get('findings_currently_correlated', 0)} "
              "(a group is a cluster of corroborating findings; 'currently correlated' counts "
              "findings whose lifecycle status is still correlated - the two differ once verified)")
    skipped = summary.get("scanners_skipped") or []
    if skipped:
        print(f"  scanners skipped: {', '.join(skipped)}")
    limitations = report.get("assessment_limitations") or {}
    untested = limitations.get("untested_attack_paths") or []
    if untested:
        print(f"  untested attack paths: {len(untested)} tagged endpoint(s) not exercised "
              "by any probe (static candidates only)")
    unavailable = limitations.get("unavailable_runtime_surfaces") or []
    if unavailable:
        print(f"  unavailable runtime surfaces: {len(unavailable)} endpoint(s) responded only "
              "under the dev runtime; production/serverless surface not exercised")
    if any(rec.status == "failed" for rec in records):
        print("  NOTE: one or more tools failed; findings are incomplete (see above).")
    if all(rec.status != "success" for rec in records):
        print("  NOTE: no tool produced results; this is not a claim that the target is safe.")
    print("  NOTE: 'verified' means a probe demonstrated the property; correlation is not verification.")
    print("  NOTE: attack-surface entries are assessment targets, not vulnerabilities.")
    print(f"  artefacts: {store.run_dir}")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="watchtower",
        description="WATCHTOWER - automated security assessment (Phase 5: assessment intelligence).",
    )
    parser.add_argument("--repo", required=True, help="Path to the target repository (never modified).")
    parser.add_argument("--target", required=True, help="Base URL of the running target, e.g. http://localhost:3000")
    parser.add_argument("--output", default="./output", help="Directory for run artefacts (default: ./output).")
    parser.add_argument("--semgrep-timeout", type=int, default=600, help="Semgrep timeout in seconds.")
    parser.add_argument("--request-timeout", type=int, default=10, help="HTTP probe timeout in seconds.")
    parser.add_argument("--gitleaks-timeout", type=int, default=300, help="Gitleaks timeout in seconds.")
    parser.add_argument("--osv-timeout", type=int, default=300, help="OSV-Scanner timeout in seconds.")
    parser.add_argument("--npm-audit-timeout", type=int, default=300, help="npm audit timeout in seconds.")
    parser.add_argument("--zap-timeout", type=int, default=900, help="ZAP baseline timeout in seconds.")
    parser.add_argument("--nuclei-timeout", type=int, default=600, help="Nuclei timeout in seconds.")
    parser.add_argument("--skip-semgrep", action="store_true", help="Skip the Semgrep scan stage.")
    parser.add_argument("--skip-attack-surface", action="store_true",
                        help="Skip static attack-surface discovery (Phase 5).")
    parser.add_argument("--diff-against", default=None,
                        help="Path to a prior report.json to diff this run against (read-only).")
    parser.add_argument("--skip-gitleaks", action="store_true", help="Skip the Gitleaks stage.")
    parser.add_argument("--skip-osv", action="store_true", help="Skip the OSV-Scanner stage.")
    parser.add_argument("--skip-npm-audit", action="store_true", help="Skip the npm audit stage.")
    parser.add_argument("--skip-headers", action="store_true", help="Skip the security-headers probe.")
    parser.add_argument("--skip-zap", action="store_true", help="Skip the OWASP ZAP stage.")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip the Nuclei stage.")
    # Phase 4 - active verification probes (local target only by default).
    parser.add_argument("--skip-cors", action="store_true", help="Skip the CORS active probe.")
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the rate-limit enforcement probe.")
    parser.add_argument("--skip-auth-mcp", action="store_true", help="Skip the auth/MCP access-control probe.")
    parser.add_argument("--skip-ssrf", action="store_true", help="Skip the SSRF local-canary probe.")
    parser.add_argument("--rate-limit-count", type=int, default=10,
                        help="Bounded request count for the rate-limit probe (1-25, default 10).")
    parser.add_argument("--canary-port", type=int, default=9001,
                        help="Loopback port for the SSRF canary listener (default 9001).")
    parser.add_argument("--allow-nonlocal-active", action="store_true",
                        help="Explicitly permit active probes against a non-loopback target "
                             "(off by default; active probes refuse non-local targets).")
    return parser.parse_args(argv)


def _assess_main(argv) -> int:
    """The original flat assessment CLI, unchanged: `watchtower --repo ... --target ...`."""
    args = parse_args(argv)
    try:
        config = WatchtowerConfig(
            repo_path=args.repo,
            target_url=args.target,
            output_dir=args.output,
            semgrep_timeout=args.semgrep_timeout,
            request_timeout=args.request_timeout,
            gitleaks_timeout=args.gitleaks_timeout,
            osv_timeout=args.osv_timeout,
            npm_audit_timeout=args.npm_audit_timeout,
            zap_timeout=args.zap_timeout,
            nuclei_timeout=args.nuclei_timeout,
            skip_semgrep=args.skip_semgrep,
            skip_headers=args.skip_headers,
            skip_gitleaks=args.skip_gitleaks,
            skip_osv=args.skip_osv,
            skip_npm_audit=args.skip_npm_audit,
            skip_zap=args.skip_zap,
            skip_nuclei=args.skip_nuclei,
            skip_attack_surface=args.skip_attack_surface,
            skip_cors=args.skip_cors,
            skip_rate_limit=args.skip_rate_limit,
            skip_auth_mcp=args.skip_auth_mcp,
            skip_ssrf=args.skip_ssrf,
            rate_limit_count=args.rate_limit_count,
            canary_port=args.canary_port,
            allow_nonlocal_active=args.allow_nonlocal_active,
            diff_against=args.diff_against,
        ).validate()
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        return run(config)
    except Exception as exc:  # last resort: never crash without a clear message
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 1


def _baseline_main(argv) -> int:
    """`watchtower baseline save|show` — Phase-6 canonical baseline commands."""
    parser = argparse.ArgumentParser(
        prog="watchtower baseline",
        description="Canonical assessment baseline: save one from a report, or show a saved one.")
    sub = parser.add_subparsers(dest="action", required=True)
    p_save = sub.add_parser("save", help="Build a deterministic baseline from a report.json.")
    p_save.add_argument("--from-report", required=True,
                        help="Path to a WATCHTOWER report.json to derive the baseline from.")
    p_save.add_argument("--out", default=None,
                        help="Output path (default: baseline.json beside the report).")
    p_show = sub.add_parser("show", help="Print a summary of a saved baseline.")
    p_show.add_argument("path", help="Path to a saved baseline.json.")
    p_show.add_argument("--json", action="store_true", help="Print the raw baseline JSON instead.")
    args = parser.parse_args(argv)
    return _baseline_save(args) if args.action == "save" else _baseline_show(args)


def _baseline_save(args) -> int:
    try:
        with open(args.from_report, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read report {args.from_report!r}: {exc}", file=sys.stderr)
        return 2
    baseline = build_baseline(report)
    out = args.out or os.path.join(
        os.path.dirname(os.path.abspath(args.from_report)) or ".", "baseline.json")
    try:
        save_baseline(out, baseline)
    except OSError as exc:
        print(f"ERROR: cannot write baseline {out!r}: {exc}", file=sys.stderr)
        return 2
    print(f"WATCHTOWER baseline saved: {out}")
    for line in render_summary(baseline):
        print(f"  {line}")
    return 0


def _baseline_show(args) -> int:
    try:
        baseline = load_baseline(args.path)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read baseline {args.path!r}: {exc}", file=sys.stderr)
        return 2
    if getattr(args, "json", False):
        print(json.dumps(baseline, indent=2, ensure_ascii=False, sort_keys=True))
        return 0
    print("WATCHTOWER baseline")
    for line in render_summary(baseline):
        print(f"  {line}")
    return 0


def _gate_main(argv) -> int:
    """`watchtower gate --report ... [--baseline ...]` — Phase-6 security gate.

    Evaluates the deterministic ``watchtower-gate-v1`` policy over structured report data
    only. With ``--baseline`` it also detects newly verified findings via the structured
    diff. Exit: 0 = PASS or WARN, 1 = FAIL (security gate failure), 2 = read/parse error.
    """
    parser = argparse.ArgumentParser(
        prog="watchtower gate",
        description="Evaluate the deterministic security gate over a structured report.")
    parser.add_argument("--report", required=True,
                        help="Path to a WATCHTOWER report.json to evaluate.")
    parser.add_argument("--baseline", default=None,
                        help="Optional canonical baseline.json; enables newly-verified detection.")
    parser.add_argument("--json", action="store_true", help="Print the raw gate JSON result.")
    args = parser.parse_args(argv)

    try:
        with open(args.report, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read report {args.report!r}: {exc}", file=sys.stderr)
        return 2

    diff = None
    if args.baseline is not None:
        try:
            with open(args.baseline, "r", encoding="utf-8") as handle:
                baseline = json.load(handle)
        except (OSError, ValueError) as exc:
            print(f"ERROR: cannot read baseline {args.baseline!r}: {exc}", file=sys.stderr)
            return 2
        diff = diff_reports(baseline, report)

    gate = evaluate_gate(report, diff)
    if getattr(args, "json", False):
        print(json.dumps(gate, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        for line in render_gate(gate):
            print(line)
    return exit_code_for(gate["result"])


def main(argv=None) -> int:
    """Dispatch: a recognised subcommand routes to it; anything else is the assess CLI.

    Peeking at argv[0] keeps the original flat `watchtower --repo ... --target ...` invocation
    byte-for-byte unchanged (no subparser wraps it), while `watchtower baseline ...` and
    `watchtower gate ...` route to their Phase-6 commands.
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "baseline":
        return _baseline_main(argv[1:])
    if argv and argv[0] == "gate":
        return _gate_main(argv[1:])
    return _assess_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
