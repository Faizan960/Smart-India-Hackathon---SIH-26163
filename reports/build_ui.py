"""Build the WATCHTOWER UI surfaces (landing + dashboard) from a canonical report.

PRESENTATION-LAYER build step. It reads an existing report.json artifact and, if that
artifact predates schema 1.2 (no embedded gate/diff), attaches the gate via the REAL
engine.gate.evaluate_gate — it never re-scans, re-scores or fabricates any value. The
stored artifact on disk is not modified. Output is written to ui/index.html and
ui/dashboard.html.

Usage:
    python -m reports.build_ui [REPORT_JSON] [OUTPUT_DIR]
Defaults: newest output/run-*/report.json  ->  ui/
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.gate import evaluate_gate  # noqa: E402  (canonical gate — not reimplemented)
from reports import dashboard, landing  # noqa: E402


def load_report_for_ui(path):
    """Load a report.json and guarantee schema-1.2 display fields (gate + diff).

    A pre-1.2 artifact has no embedded gate/diff. We attach them for display only:
    diff stays None (no baseline), and the gate is computed by the canonical engine.
    """
    with open(path, encoding="utf-8") as h:
        report = json.load(h)
    if report.get("diff") is None and "diff" not in report:
        report["diff"] = None
    report.setdefault("diff", None)
    if not isinstance(report.get("gate"), dict):
        report["gate"] = evaluate_gate(report, report.get("diff"))
    # The display copy now carries the schema-1.2 additions (gate + diff); label it 1.2
    # unless the artifact is already newer. The on-disk file is never rewritten.
    if report.get("schema_version") in (None, "", "1.0", "1.1"):
        report["schema_version"] = "1.2"
    return report


def _newest_report():
    candidates = sorted(glob.glob(os.path.join("output", "run-*", "report.json")))
    if not candidates:
        raise SystemExit("No output/run-*/report.json found; run an assessment first.")
    return candidates[-1]


def build(report_path=None, out_dir="ui"):
    report_path = report_path or _newest_report()
    report = load_report_for_ui(report_path)
    os.makedirs(out_dir, exist_ok=True)
    landing.write_landing(os.path.join(out_dir, "index.html"), report)
    dashboard.write_dashboard(os.path.join(out_dir, "dashboard.html"), report)
    gate = report.get("gate", {})
    print(f"source     : {report_path}")
    print(f"gate       : {gate.get('result')} ({gate.get('policy')})")
    print(f"findings   : {report.get('summary', {}).get('total_findings')}")
    print(f"endpoints  : {report.get('attack_surface', {}).get('summary', {}).get('endpoint_count')}")
    print(f"written    : {out_dir}/index.html, {out_dir}/dashboard.html")
    return out_dir


if __name__ == "__main__":
    args = sys.argv[1:]
    build(args[0] if len(args) > 0 else None, args[1] if len(args) > 1 else "ui")
