"""Render the human-readable HTML report with Jinja2 (autoescaping ON).

All finding text is rendered through Jinja2 with autoescape enabled, so tool
output embedded in the report cannot inject markup. The report also surfaces the
tool-execution status, so a skipped scan or an unreachable target is visible and
never disguised as a clean result.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from jinja2 import Environment

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLOR = {
    "critical": "#7f1d1d",
    "high": "#b91c1c",
    "medium": "#b45309",
    "low": "#2563eb",
    "info": "#4b5563",
}

# Lifecycle status -> pill colour. Verified/false-positive are terminal probe verdicts.
_STATUS_COLOR = {
    "verified": "#15803d",
    "correlated": "#7c3aed",
    "suspected": "#0e7490",
    "needs_manual_review": "#b45309",
    "false_positive": "#4b5563",
}


def render_html(report: dict) -> str:
    raw_findings = report.get("findings", []) or []
    findings = sorted(
        raw_findings,
        key=lambda d: (
            _SEVERITY_ORDER.get(d.get("severity"), 99),
            -((d.get("score") or {}).get("value") or 0),
        ),
    )
    views = []
    for d in findings:
        view = dict(d)
        view["evidence_json"] = json.dumps(d.get("evidence", {}), indent=2, ensure_ascii=False)
        view["score_value"] = (d.get("score") or {}).get("value")
        views.append(view)

    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE)
    return template.render(
        report=report,
        findings=views,
        summary=report.get("summary", {}),
        scan=report.get("scan", {}),
        execution=report.get("execution", []) or [],
        duplicate_groups=report.get("duplicate_groups", []) or [],
        correlation_groups=report.get("correlation_groups", []) or [],
        severity_color=_SEVERITY_COLOR,
        status_color=_STATUS_COLOR,
        generated=datetime.now(timezone.utc).isoformat(),
    )


def write_html_report(path: str, report: dict) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render_html(report))
    return path


_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WATCHTOWER Report</title>
<style>
  :root { --bg:#0b0f14; --card:#141b24; --ink:#e6edf3; --muted:#8b97a5; --line:#233040; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         background:var(--bg); color:var(--ink); line-height:1.5; }
  header { padding:24px 32px; border-bottom:1px solid var(--line); }
  h1 { margin:0 0 4px; font-size:22px; letter-spacing:0.5px; }
  .sub { color:var(--muted); font-size:13px; }
  main { padding:24px 32px; max-width:1100px; margin:0 auto; }
  .grid { display:flex; flex-wrap:wrap; gap:12px; margin:16px 0 28px; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:12px 16px; min-width:96px; }
  .stat .n { font-size:22px; font-weight:700; }
  .stat .l { font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:0.6px; }
  section { margin-bottom:28px; }
  h2 { font-size:15px; text-transform:uppercase; letter-spacing:0.8px; color:var(--muted);
       border-bottom:1px solid var(--line); padding-bottom:6px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  .pill { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff;
          font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:16px 18px; margin-bottom:14px; }
  .card h3 { margin:0 0 6px; font-size:15px; }
  .meta { color:var(--muted); font-size:12px; margin-bottom:8px; }
  pre { background:#0b1218; border:1px solid var(--line); border-radius:8px; padding:12px;
        overflow:auto; font-size:12px; color:#cbd5e1; }
  code { color:#93c5fd; }
  .exec .ok { color:#34d399; } .exec .warn { color:#fbbf24; } .exec .bad { color:#f87171; }
  a { color:#60a5fa; }
  .note { font-size:12px; color:var(--muted); }
</style>
</head>
<body>
<header>
  <h1>WATCHTOWER — Security Assessment Report</h1>
  <div class="sub">WATCHTOWER v{{ report.watchtower_version }} · schema {{ report.schema_version }} · generated {{ generated }}</div>
</header>
<main>
  <section>
    <h2>Scan</h2>
    <table>
      <tr><th>Target</th><td>{{ scan.target }}</td></tr>
      <tr><th>Repository</th><td>{{ scan.repository }}</td></tr>
      <tr><th>Commit</th><td><code>{{ scan.commit or "unknown" }}</code>{% if scan.branch %} ({{ scan.branch }}){% endif %}</td></tr>
      <tr><th>Timestamp</th><td>{{ scan.timestamp }}</td></tr>
    </table>
  </section>

  <section class="exec">
    <h2>Tool execution</h2>
    <table>
      <tr><th>Tool</th><th>Status</th><th>Duration</th><th>Findings</th><th>Error / detail</th></tr>
      {% for info in execution %}
      <tr>
        <td>{{ info.tool }}</td>
        <td class="{{ 'ok' if info.status == 'success' else ('warn' if info.status == 'skipped' else 'bad') }}">{{ info.status }}</td>
        <td class="note">{{ '%.3f'|format(info.duration_seconds) }}s{% if info.exit_code is not none %} · exit {{ info.exit_code }}{% endif %}</td>
        <td>{{ info.finding_count }}</td>
        <td class="note">{{ info.error }}</td>
      </tr>
      {% endfor %}
    </table>
    <p class="note">A tool that is not installed is recorded as <em>skipped</em>; a crash or
    unparseable output is <em>failed</em>. Absence of findings for a skipped/failed tool is
    not a claim that the target is clean.</p>
  </section>
  {% if duplicate_groups %}
  <section>
    <h2>Duplicate groups (same vulnerability, multiple sources)</h2>
    <table>
      <tr><th>Group</th><th>Identifier(s)</th><th>Sources</th><th>Findings</th></tr>
      {% for g in duplicate_groups %}
      <tr>
        <td><code>{{ g.group }}</code></td>
        <td class="note">{{ g.identifiers | join(', ') }}</td>
        <td class="note">{{ g.tools | join(', ') }}</td>
        <td class="note">{% for m in g.members %}<code>{{ m.id }}</code>{% if not loop.last %}, {% endif %}{% endfor %}</td>
      </tr>
      {% endfor %}
    </table>
    <p class="note">Deterministic duplicate grouping by shared advisory identifier. This is
    <strong>not</strong> cross-tool correlation — sources are preserved, not merged.</p>
  </section>
  {% endif %}
  {% if correlation_groups %}
  <section>
    <h2>Correlation groups (independent tools agree)</h2>
    <table>
      <tr><th>Group</th><th>Shared key(s)</th><th>Tools</th><th>Findings</th></tr>
      {% for g in correlation_groups %}
      <tr>
        <td><code>{{ g.group }}</code></td>
        <td class="note">{{ g.keys | join(', ') }}</td>
        <td class="note">{{ g.tools | join(', ') }}</td>
        <td class="note">{% for m in g.members %}<code>{{ m.id }}</code> ({{ m.status }}){% if not loop.last %}, {% endif %}{% endfor %}</td>
      </tr>
      {% endfor %}
    </table>
    <p class="note">Correlation raises confidence when independent tools corroborate the same
    issue. It promotes findings to <strong>correlated</strong> — never to verified.</p>
  </section>
  {% endif %}
  <section>
    <h2>Summary</h2>
    <div class="grid">
      <div class="stat"><div class="n">{{ summary.total_findings }}</div><div class="l">Total</div></div>
      <div class="stat"><div class="n">{{ summary.critical }}</div><div class="l">Critical</div></div>
      <div class="stat"><div class="n">{{ summary.high }}</div><div class="l">High</div></div>
      <div class="stat"><div class="n">{{ summary.medium }}</div><div class="l">Medium</div></div>
      <div class="stat"><div class="n">{{ summary.low }}</div><div class="l">Low</div></div>
      <div class="stat"><div class="n">{{ summary.info }}</div><div class="l">Info</div></div>
    </div>
    <div class="grid">
      <div class="stat"><div class="n">{{ summary.suspected }}</div><div class="l">Suspected</div></div>
      <div class="stat"><div class="n">{{ summary.correlated }}</div><div class="l">Correlated</div></div>
      <div class="stat"><div class="n">{{ summary.verified }}</div><div class="l">Verified</div></div>
      <div class="stat"><div class="n">{{ summary.needs_manual_review }}</div><div class="l">Needs review</div></div>
      <div class="stat"><div class="n">{{ summary.false_positive }}</div><div class="l">False positive</div></div>
      <div class="stat"><div class="n">{{ summary.skipped_count }}</div><div class="l">Scanners skipped</div></div>
    </div>
    <p class="note">Lifecycle: <strong>suspected</strong> (single scanner) &rarr;
    <strong>correlated</strong> (independent tools agree) &rarr; <strong>verified</strong>
    (a probe demonstrated the property). <strong>False positive</strong> means evidence
    disproved the issue; <strong>needs review</strong> means the evidence was inconclusive.
    Correlation raises confidence but is never verification.</p>
  </section>

  <section>
    <h2>Findings</h2>
    {% if not findings %}
      <p class="note">No findings were produced. If a stage was skipped or a probe could not
      reach the target, see the "Tool execution" table above — absence of findings is not a
      claim that the target is safe.</p>
    {% else %}
    <table>
      <tr><th>ID</th><th>Severity</th><th>WATCHTOWER Risk Score</th><th>Status</th><th>Tool</th><th>Title</th><th>Location</th></tr>
      {% for f in findings %}
      <tr>
        <td><code>{{ f.id }}</code></td>
        <td><span class="pill" style="background:{{ severity_color.get(f.severity, '#4b5563') }}">{{ f.severity }}</span></td>
        <td>{{ f.score_value }}</td>
        <td><span class="pill" style="background:{{ status_color.get(f.status, '#4b5563') }}">{{ f.status.replace('_', ' ') }}</span></td>
        <td>{{ f.tool }}</td>
        <td>{{ f.title }}</td>
        <td class="note">{% if f.file %}{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}{% elif f.endpoint %}{{ f.endpoint }}{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
    <h2 style="margin-top:28px;">Finding details</h2>
    {% for f in findings %}
    <div class="card">
      <h3>{{ f.id }} — {{ f.title }}</h3>
      <div class="meta">
        <span class="pill" style="background:{{ severity_color.get(f.severity, '#4b5563') }}">{{ f.severity }}</span>
        <span class="pill" style="background:{{ status_color.get(f.status, '#4b5563') }}">{{ f.status.replace('_', ' ') }}</span>
        · WATCHTOWER Risk Score {{ f.score_value }} · {{ f.tool }}{% if f.cwe %} · {{ f.cwe }}{% endif %}
        {%- if f.evidence and f.evidence.identifiers %} · {{ f.evidence.identifiers | join(', ') }}{% endif %}
        {%- if f.evidence and f.evidence.dedup_group %} · <code>{{ f.evidence.dedup_group }}</code>{% endif %}
        {%- if f.evidence and f.evidence.correlation_group %} · <code>{{ f.evidence.correlation_group }}</code>{% endif %}
      </div>
      <p>{{ f.description }}</p>
      {% if f.verification and f.verification.rationale %}
      <p class="note"><strong>Verification:</strong> {{ f.verification.method }}{% if f.verification.result %} &rarr; {{ f.verification.result }}{% endif %} — {{ f.verification.rationale }}</p>
      {% endif %}
      {% if f.evidence and f.evidence.dependency_type %}
      <p class="note"><strong>Dependency reachability:</strong> {{ f.evidence.dependency }} · {{ f.evidence.dependency_type }} · {{ f.evidence.direct_or_transitive }} · reachable: {{ f.evidence.reachable }} — {{ f.evidence.reachability_reason }}</p>
      {% endif %}
      {% if f.evidence and f.evidence.remediation %}
      <p class="note"><strong>Remediation:</strong> {{ f.evidence.remediation }}</p>
      {% endif %}
      <pre>{{ f.evidence_json }}</pre>
      {% if f.references %}
      <div class="note">References:
        <ul>{% for r in f.references %}<li><a href="{{ r }}">{{ r }}</a></li>{% endfor %}</ul>
      </div>
      {% endif %}
    </div>
    {% endfor %}
    {% endif %}
  </section>

  <footer class="note">
    The WATCHTOWER Risk Score is a transparent prioritisation number, explicitly not CVSS.
    Findings labelled "suspected" are single-source and not yet verified.
  </footer>
</main>
</body>
</html>"""
