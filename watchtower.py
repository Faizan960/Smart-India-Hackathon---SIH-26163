#!/usr/bin/env python3
"""WATCHTOWER - CLI orchestrator (Phase 2: multi-tool integration).

Pipeline stages:
  [1] Init  [2] Semgrep  [3] Gitleaks  [4] OSV-Scanner  [5] npm audit
  [6] Security headers  [7] OWASP ZAP  [8] Nuclei  [9] Normalize
  [10] Score  [11] Report

Each collector stage is independently executable and records an honest execution
status: a missing tool is 'skipped', a crash/parse error is 'failed', a real run is
'success'. Skips and failures are reported plainly, never disguised as clean results.
Only the local repository and the local target are ever touched.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone

from config import ConfigError, WATCHTOWER_VERSION, WatchtowerConfig
from checks.security_headers import run_headers_probe
from engine import normalizer, scorer
from engine.evidence import EvidenceStore
from engine.execution import ToolExecution
from engine.git_meta import get_git_metadata
from reports.html_report import write_html_report
from reports.json_report import build_report, write_json_report
from scanners.semgrep import run_semgrep
from scanners.gitleaks import run_gitleaks
from scanners.osv import run_osv
from scanners.npm_audit import run_npm_audit
from scanners.zap import run_zap
from scanners.nuclei import run_nuclei

TOTAL_STAGES = 11


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


def _collector_raw(result):
    return result.raw or {
        "executed": result.executed, "skipped": result.skipped, "error": result.error}


def run(config) -> int:
    records: list[ToolExecution] = []

    _stage(1, f"Initializing run (repo={config.repo_path!r}, target={config.normalized_target!r})")
    store = EvidenceStore(config.output_dir)
    git_meta = get_git_metadata(config.repo_path)
    print(f"      evidence: {store.run_dir}")

    _stage(2, "Semgrep static scan")
    semgrep_result = _collector_stage(
        "semgrep", config.skip_semgrep,
        lambda: run_semgrep(config.repo_path, timeout=config.semgrep_timeout),
        "semgrep.json", _semgrep_raw, store, records)

    _stage(3, "Gitleaks secret scan")
    gitleaks_result = _collector_stage(
        "gitleaks", config.skip_gitleaks,
        lambda: run_gitleaks(config.repo_path, timeout=config.gitleaks_timeout),
        "gitleaks.json", _collector_raw, store, records)

    _stage(4, "OSV-Scanner dependency scan")
    osv_result = _collector_stage(
        "osv-scanner", config.skip_osv,
        lambda: run_osv(config.repo_path, timeout=config.osv_timeout),
        "osv.json", _collector_raw, store, records)

    _stage(5, "npm audit dependency scan")
    npm_result = _collector_stage(
        "npm-audit", config.skip_npm_audit,
        lambda: run_npm_audit(config.repo_path, timeout=config.npm_audit_timeout),
        "npm_audit.json", _collector_raw, store, records)

    _stage(6, "Security-headers probe")
    headers_result = _headers_stage(config, store, records)

    _stage(7, "OWASP ZAP baseline (local target only)")
    zap_result = _collector_stage(
        "zap", config.skip_zap,
        lambda: run_zap(config.normalized_target, timeout=config.zap_timeout),
        "zap.json", _collector_raw, store, records)

    _stage(8, "Nuclei controlled scan (local target only)")
    nuclei_result = _collector_stage(
        "nuclei", config.skip_nuclei,
        lambda: run_nuclei(config.normalized_target, timeout=config.nuclei_timeout),
        "nuclei.jsonl", _collector_raw, store, records)
    _stage(9, "Normalizing findings")
    findings = normalizer.normalize(
        semgrep_result=semgrep_result,
        gitleaks_result=gitleaks_result,
        osv_result=osv_result,
        npm_audit_result=npm_result,
        headers_result=headers_result,
        zap_result=zap_result,
        nuclei_result=nuclei_result,
        repo_path=config.repo_path,
    )
    counts = Counter(f.tool for f in findings)
    for rec in records:
        rec.finding_count = counts.get(rec.tool, 0)
    print(f"      normalized {len(findings)} finding(s)")

    _stage(10, "Calculating WATCHTOWER Risk Scores")
    scorer.score_all(findings)

    _stage(11, "Generating reports")
    scan = {
        "timestamp": _now_iso(),
        "target": config.normalized_target,
        "repository": config.repo_path,
        "commit": git_meta.get("commit"),
        "branch": git_meta.get("branch"),
    }
    execution = [rec.to_dict() for rec in records]
    report = build_report(findings, scan, WATCHTOWER_VERSION, execution=execution)
    store.save_findings(findings)
    store.save_metadata({
        "scan": scan,
        "execution": execution,
        "git": git_meta,
        "watchtower_version": WATCHTOWER_VERSION,
    })
    json_path = write_json_report(store.path("report.json"), report)
    html_path = write_html_report(store.path("report.html"), report)
    print(f"      json: {json_path}")
    print(f"      html: {html_path}")

    _print_summary(report, records, store)
    return 0


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
    for rec in records:
        line = f"  {rec.tool}: {rec.status} ({rec.finding_count} finding(s), {rec.duration_seconds}s)"
        if rec.error:
            line += f" - {_console_safe(rec.error)}"
        print(line)
    dup = report.get("duplicate_groups") or []
    if dup:
        print(f"  duplicate groups: {len(dup)} (same vuln reported by multiple tools)")
    if any(rec.status == "failed" for rec in records):
        print("  NOTE: one or more tools failed; findings are incomplete (see above).")
    if all(rec.status != "success" for rec in records):
        print("  NOTE: no tool produced results; this is not a claim that the target is safe.")
    print(f"  artefacts: {store.run_dir}")


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="watchtower",
        description="WATCHTOWER - automated security assessment (Phase 2: multi-tool).",
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
    parser.add_argument("--skip-gitleaks", action="store_true", help="Skip the Gitleaks stage.")
    parser.add_argument("--skip-osv", action="store_true", help="Skip the OSV-Scanner stage.")
    parser.add_argument("--skip-npm-audit", action="store_true", help="Skip the npm audit stage.")
    parser.add_argument("--skip-headers", action="store_true", help="Skip the security-headers probe.")
    parser.add_argument("--skip-zap", action="store_true", help="Skip the OWASP ZAP stage.")
    parser.add_argument("--skip-nuclei", action="store_true", help="Skip the Nuclei stage.")
    return parser.parse_args(argv)


def main(argv=None) -> int:
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
        ).validate()
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        return run(config)
    except Exception as exc:  # last resort: never crash without a clear message
        print(f"ERROR: unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
