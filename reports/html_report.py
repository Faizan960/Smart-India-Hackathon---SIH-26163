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

# Verification result -> pill colour (the raw probe verdict, distinct from lifecycle status).
_RESULT_COLOR = {
    "confirmed": "#15803d",
    "refuted": "#4b5563",
    "inconclusive": "#b45309",
    "not_applicable": "#4b5563",
}

_CONFIDENCE_COLOR = {"high": "#15803d", "medium": "#b45309", "low": "#4b5563"}

# Findings emitted by the Phase-4 active verification probes (kept visibly distinct from
# the passive scanners so "a scanner ran" is never conflated with "a probe verified").
ACTIVE_PROBE_TOOLS = ("cors", "rate-limit", "auth-mcp", "ssrf")


def _finding_component(d: dict) -> str:
    rel = d.get("related_endpoints") or []
    if rel and rel[0].get("component"):
        return rel[0]["component"]
    asset_kind = (d.get("asset") or {}).get("kind")
    return asset_kind or d.get("tool") or "other"


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
        view["confidence"] = d.get("evidence_confidence") or "low"
        view["component"] = _finding_component(d)
        view["probe"] = d.get("tool") if d.get("tool") in ACTIVE_PROBE_TOOLS else ""
        view["chain"] = d.get("evidence_chain") or {}
        view["explanation"] = d.get("explanation") or {}
        views.append(view)

    execution = report.get("execution", []) or []
    exec_times = {e.get("tool"): e.get("duration_seconds") for e in execution}
    probe_views = [
        {
            "tool": v.get("tool"),
            "endpoint": v.get("endpoint"),
            "result": (v.get("verification") or {}).get("result"),
            "status": v.get("status"),
            "rationale": (v.get("verification") or {}).get("rationale"),
            "duration_seconds": exec_times.get(v.get("tool")),
        }
        for v in views if v.get("tool") in ACTIVE_PROBE_TOOLS
    ]

    filter_options = {
        "severity": sorted({v["severity"] for v in views},
                           key=lambda s: _SEVERITY_ORDER.get(s, 99)),
        "status": sorted({v["status"] for v in views}),
        "confidence": [c for c in ("high", "medium", "low")
                       if any(v["confidence"] == c for v in views)],
        "component": sorted({v["component"] for v in views if v.get("component")}),
        "tool": sorted({v["tool"] for v in views}),
        "probe": sorted({v["probe"] for v in views if v.get("probe")}),
    }

    env = Environment(autoescape=True)
    template = env.from_string(_TEMPLATE)
    return template.render(
        report=report,
        findings=views,
        probe_findings=probe_views,
        summary=report.get("summary", {}),
        scan=report.get("scan", {}),
        assessment=report.get("assessment", {}),
        environment=report.get("environment", {}),
        attack_surface=report.get("attack_surface", {}) or {},
        limitations=report.get("assessment_limitations", {}) or {},
        execution=execution,
        duplicate_groups=report.get("duplicate_groups", []) or [],
        correlation_groups=report.get("correlation_groups", []) or [],
        filter_options=filter_options,
        severity_color=_SEVERITY_COLOR,
        status_color=_STATUS_COLOR,
        result_color=_RESULT_COLOR,
        confidence_color=_CONFIDENCE_COLOR,
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
  .filters { display:flex; flex-wrap:wrap; gap:10px; align-items:flex-end; margin:8px 0 16px;
             padding:12px; background:var(--card); border:1px solid var(--line); border-radius:10px; }
  .filters .fld { display:flex; flex-direction:column; gap:3px; }
  .filters label { font-size:10px; text-transform:uppercase; letter-spacing:0.6px; color:var(--muted); }
  .filters select { background:#0b1218; color:var(--ink); border:1px solid var(--line);
                    border-radius:6px; padding:5px 8px; font-size:12px; min-width:120px; }
  .filters button { background:#1f2937; color:var(--ink); border:1px solid var(--line);
                    border-radius:6px; padding:6px 12px; font-size:12px; cursor:pointer; }
  .filters .count { margin-left:auto; font-size:12px; color:var(--muted); align-self:center; }
  .badge { display:inline-block; padding:1px 7px; border-radius:6px; font-size:10px;
           border:1px solid var(--line); color:var(--muted); margin:0 4px 4px 0; }
  .conf { display:inline-block; padding:2px 8px; border-radius:999px; color:#fff; font-size:11px;
          text-transform:uppercase; letter-spacing:0.5px; }
  .chain { list-style:none; padding:0; margin:6px 0 0; font-size:12px; }
  .chain li { padding:3px 0; border-bottom:1px dashed var(--line); }
  .chain .rel { display:inline-block; min-width:120px; color:var(--muted); text-transform:uppercase;
                font-size:10px; letter-spacing:0.5px; }
  .expl p { margin:6px 0; font-size:13px; }
  .expl .k { color:var(--muted); }
  .hidden { display:none !important; }
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

  <section>
    <h2>Reproducibility &amp; environment</h2>
    <table>
      <tr><th>Assessment ID</th><td><code>{{ environment.assessment_id or assessment.id or "—" }}</code></td></tr>
      <tr><th>WATCHTOWER</th><td>v{{ environment.watchtower_version or report.watchtower_version }} · schema {{ report.schema_version }}</td></tr>
      <tr><th>Python</th><td>{{ environment.python_version or "—" }}</td></tr>
      <tr><th>Platform</th><td class="note">{{ environment.platform or "—" }}</td></tr>
      <tr><th>Repository</th><td class="note">{{ environment.repository or scan.repository }}</td></tr>
      <tr><th>Commit</th><td><code>{{ environment.commit or scan.commit or "unknown" }}</code>{% if environment.branch %} ({{ environment.branch }}){% endif %}</td></tr>
      {% if environment.probe_versions %}
      <tr><th>Probe versions</th><td class="note">{% for k, v in environment.probe_versions.items() %}<span class="badge">{{ k }}:{{ v }}</span>{% endfor %}</td></tr>
      {% endif %}
      {% if environment.scanner_versions %}
      <tr><th>Scanner versions</th><td class="note">{{ environment.scanner_version_note or "not collected" }}</td></tr>
      {% endif %}
    </table>
    <p class="note">Everything needed to reproduce this run is recorded here; external scanner
    versions are deliberately not collected (WATCHTOWER never shells out purely for
    <code>--version</code>) — the tool-execution table above records what actually ran.</p>
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
  {% if attack_surface and attack_surface.summary %}
  <section>
    <h2>Attack surface (static discovery)</h2>
    <div class="grid">
      <div class="stat"><div class="n">{{ attack_surface.summary.endpoint_count }}</div><div class="l">Endpoints</div></div>
      <div class="stat"><div class="n">{{ attack_surface.summary.security_module_count }}</div><div class="l">Security modules</div></div>
      <div class="stat"><div class="n">{{ attack_surface.summary.integration_count }}</div><div class="l">Integrations</div></div>
      <div class="stat"><div class="n">{{ attack_surface.summary.env_reference_count }}</div><div class="l">Env references</div></div>
    </div>
    {% if attack_surface.summary.risk_tag_counts %}
    <p class="note">Risk tags (static candidates):
      {% for tag, n in attack_surface.summary.risk_tag_counts.items() if n %}<span class="badge">{{ tag }} · {{ n }}</span>{% endfor %}
    </p>
    {% endif %}
    <p class="note"><strong>{{ attack_surface.disclaimer }}</strong></p>
    {% if attack_surface.endpoints %}
    <table>
      <tr><th>Path</th><th>Method</th><th>Component</th><th>Auth</th><th>Risk tags</th><th>Probed</th></tr>
      {% for ep in attack_surface.endpoints %}
      <tr>
        <td><code>{{ ep.path }}</code></td>
        <td class="note">{{ ep.method }}</td>
        <td class="note">{{ ep.component }}</td>
        <td class="note">{{ ep.authentication or "—" }}</td>
        <td class="note">{% for t in ep.risk_tags %}<span class="badge">{{ t }}</span>{% endfor %}</td>
        <td class="note">{% if ep.tested %}yes{% else %}no{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
    {% endif %}
    {% if attack_surface.integrations %}
    <p class="note">Integrations: {% for i in attack_surface.integrations %}<span class="badge">{{ i.name }} ({{ i.kind }})</span>{% endfor %}</p>
    {% endif %}
    {% if attack_surface.env_references %}
    <p class="note">Config/env references: {% for e in attack_surface.env_references %}<span class="badge">{{ e }}</span>{% endfor %}</p>
    {% endif %}
    {% if attack_surface.notes %}
    <p class="note">{% for nt in attack_surface.notes %}{{ nt }} {% endfor %}</p>
    {% endif %}
  </section>
  {% endif %}
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
    <p class="note">Correlation groups (count): <strong>{{ summary.correlation_groups_count }}</strong>
    &nbsp;·&nbsp; Findings currently correlated: <strong>{{ summary.findings_currently_correlated }}</strong>.
    These are distinct: a <em>group</em> is a cluster of corroborating findings, while
    <em>findings currently correlated</em> counts only findings whose lifecycle status is still
    <code>correlated</code> — verification later moves members to a terminal status, so the two
    numbers routinely differ.</p>
    <table>
      <tr><th>Group</th><th>Shared key(s)</th><th>Tools</th><th>Findings</th></tr>
      {% for g in correlation_groups %}
      <tr>
        <td><code>{{ g.group }}</code></td>
        <td class="note">{{ g['keys'] | join(', ') }}</td>
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
      <div class="stat"><div class="n">{{ summary.correlated }}</div><div class="l">Correlated (status now)</div></div>
      <div class="stat"><div class="n">{{ summary.verified }}</div><div class="l">Verified</div></div>
      <div class="stat"><div class="n">{{ summary.needs_manual_review }}</div><div class="l">Needs review</div></div>
      <div class="stat"><div class="n">{{ summary.false_positive }}</div><div class="l">False positive</div></div>
      <div class="stat"><div class="n">{{ summary.skipped_count }}</div><div class="l">Scanners skipped</div></div>
    </div>
    {% if summary.evidence_confidence %}
    <div class="grid">
      <div class="stat"><div class="n">{{ summary.evidence_confidence.high }}</div><div class="l">Confidence: high</div></div>
      <div class="stat"><div class="n">{{ summary.evidence_confidence.medium }}</div><div class="l">Confidence: medium</div></div>
      <div class="stat"><div class="n">{{ summary.evidence_confidence.low }}</div><div class="l">Confidence: low</div></div>
      <div class="stat"><div class="n">{{ summary.attack_surface_count or 0 }}</div><div class="l">Attack surface</div></div>
    </div>
    <p class="note">Evidence confidence reflects how <strong>complete</strong> the evidence is —
    it is not severity and not the WATCHTOWER Risk Score. High = a definitive probe/verifier
    result; medium = corroborated or reachability-analysed; low = single-source and suspected.</p>
    {% endif %}
    {% if summary.verification_results %}
    <div class="grid">
      <div class="stat"><div class="n">{{ summary.verification_results.confirmed }}</div><div class="l">Confirmed</div></div>
      <div class="stat"><div class="n">{{ summary.verification_results.refuted }}</div><div class="l">Refuted</div></div>
      <div class="stat"><div class="n">{{ summary.verification_results.inconclusive }}</div><div class="l">Inconclusive</div></div>
      <div class="stat"><div class="n">{{ summary.verification_results.not_applicable }}</div><div class="l">Not applicable</div></div>
      <div class="stat"><div class="n">{{ summary.active_probe_findings }}</div><div class="l">Active-probe findings</div></div>
    </div>
    {% endif %}
    <p class="note">Lifecycle: <strong>suspected</strong> (single scanner) &rarr;
    <strong>correlated</strong> (independent tools agree) &rarr; <strong>verified</strong>
    (a probe demonstrated the property). <strong>False positive</strong> means evidence
    disproved the issue; <strong>needs review</strong> means the evidence was inconclusive.
    Correlation raises confidence but is never verification. The verification-result counts
    are the raw probe verdicts (confirmed / refuted / inconclusive / not&nbsp;applicable),
    mapped onto those lifecycle statuses.</p>
  </section>

  {% if limitations %}
  <section>
    <h2>Assessment limitations</h2>
    <p class="note">What this assessment did <strong>not</strong> cover — recorded so the results
    are never read as more comprehensive than they actually are.</p>
    {% if limitations.notes %}
    <ul class="note">{% for n in limitations.notes %}<li>{{ n }}</li>{% endfor %}</ul>
    {% endif %}
    <table>
      <tr><th>Scanners skipped</th><td class="note">{{ limitations.scanners_skipped | join(', ') or "none" }}</td></tr>
      <tr><th>Scanners failed</th><td class="note">{{ limitations.scanners_failed | join(', ') or "none" }}</td></tr>
      <tr><th>Probes skipped</th><td class="note">{{ limitations.probes_skipped | join(', ') or "none" }}</td></tr>
      <tr><th>Dev vs production</th><td class="note">{{ limitations.development_vs_production.note }}</td></tr>
    </table>
    {% if limitations.untested_attack_paths %}
    <p class="note">Attack-surface endpoints carrying risk tags that no probe exercised
    (static candidates only, not findings):</p>
    <table>
      <tr><th>Path</th><th>Risk tags</th></tr>
      {% for u in limitations.untested_attack_paths %}
      <tr><td><code>{{ u.path }}</code></td><td class="note">{% for t in u.risk_tags %}<span class="badge">{{ t }}</span>{% endfor %}</td></tr>
      {% endfor %}
    </table>
    {% endif %}
  </section>
  {% endif %}

  {% if probe_findings %}
  <section>
    <h2>Active verification (Phase 4)</h2>
    <table>
      <tr><th>Probe</th><th>Target</th><th>Result</th><th>Lifecycle status</th><th>Execution time</th><th>Evidence</th></tr>
      {% for p in probe_findings %}
      <tr>
        <td>{{ p.tool }}</td>
        <td class="note">{{ p.endpoint }}</td>
        <td><span class="pill" style="background:{{ result_color.get(p.result, '#4b5563') }}">{{ (p.result or 'pending').replace('_', ' ') }}</span></td>
        <td><span class="pill" style="background:{{ status_color.get(p.status, '#4b5563') }}">{{ p.status.replace('_', ' ') }}</span></td>
        <td class="note">{% if p.duration_seconds is not none %}{{ '%.3f'|format(p.duration_seconds) }}s{% else %}—{% endif %}</td>
        <td class="note">{{ p.rationale }}</td>
      </tr>
      {% endfor %}
    </table>
    <p class="note">Active probes send bounded, controlled requests to the LOCAL target only
    (loopback SSRF canary, hostile-origin CORS, bounded rate-limit burst, unauthenticated
    auth/MCP request). A probe <strong>confirms</strong> a weakness only when it demonstrates
    the security property; otherwise it refutes it, marks it not-applicable, or leaves it for
    manual review. Probe execution is kept separate from the passive scanner run above.</p>
  </section>
  {% endif %}

  <section>
    <h2>Findings</h2>
    {% if not findings %}
      <p class="note">No findings were produced. If a stage was skipped or a probe could not
      reach the target, see the "Tool execution" table above — absence of findings is not a
      claim that the target is safe.</p>
    {% else %}
    <div class="filters">
      <div class="fld"><label for="f-severity">Severity</label>
        <select id="f-severity"><option value="">all</option>{% for o in filter_options.severity %}<option value="{{ o }}">{{ o }}</option>{% endfor %}</select></div>
      <div class="fld"><label for="f-status">Lifecycle</label>
        <select id="f-status"><option value="">all</option>{% for o in filter_options.status %}<option value="{{ o }}">{{ o.replace('_', ' ') }}</option>{% endfor %}</select></div>
      <div class="fld"><label for="f-confidence">Confidence</label>
        <select id="f-confidence"><option value="">all</option>{% for o in filter_options.confidence %}<option value="{{ o }}">{{ o }}</option>{% endfor %}</select></div>
      <div class="fld"><label for="f-component">Component</label>
        <select id="f-component"><option value="">all</option>{% for o in filter_options.component %}<option value="{{ o }}">{{ o }}</option>{% endfor %}</select></div>
      <div class="fld"><label for="f-tool">Tool</label>
        <select id="f-tool"><option value="">all</option>{% for o in filter_options.tool %}<option value="{{ o }}">{{ o }}</option>{% endfor %}</select></div>
      <div class="fld"><label for="f-probe">Probe</label>
        <select id="f-probe"><option value="">all</option>{% for o in filter_options.probe %}<option value="{{ o }}">{{ o }}</option>{% endfor %}</select></div>
      <button type="button" id="f-reset">Reset</button>
      <span class="count" id="f-count"></span>
    </div>
    <table>
      <tr><th>ID</th><th>Severity</th><th>Risk Score</th><th>Confidence</th><th>Status</th><th>Component</th><th>Tool</th><th>Title</th><th>Location</th></tr>
      {% for f in findings %}
      <tr class="finding-row filterable" data-severity="{{ f.severity }}" data-status="{{ f.status }}" data-confidence="{{ f.confidence }}" data-component="{{ f.component }}" data-tool="{{ f.tool }}" data-probe="{{ f.probe }}">
        <td><code>{{ f.id }}</code></td>
        <td><span class="pill" style="background:{{ severity_color.get(f.severity, '#4b5563') }}">{{ f.severity }}</span></td>
        <td>{{ f.score_value }}</td>
        <td><span class="conf" style="background:{{ confidence_color.get(f.confidence, '#4b5563') }}">{{ f.confidence }}</span></td>
        <td><span class="pill" style="background:{{ status_color.get(f.status, '#4b5563') }}">{{ f.status.replace('_', ' ') }}</span></td>
        <td class="note">{{ f.component }}</td>
        <td>{{ f.tool }}</td>
        <td>{{ f.title }}</td>
        <td class="note">{% if f.file %}{{ f.file }}{% if f.line %}:{{ f.line }}{% endif %}{% elif f.endpoint %}{{ f.endpoint }}{% endif %}</td>
      </tr>
      {% endfor %}
    </table>
    <h2 style="margin-top:28px;">Finding details</h2>
    {% for f in findings %}
    <div class="card filterable" data-severity="{{ f.severity }}" data-status="{{ f.status }}" data-confidence="{{ f.confidence }}" data-component="{{ f.component }}" data-tool="{{ f.tool }}" data-probe="{{ f.probe }}">
      <h3>{{ f.id }} — {{ f.title }}</h3>
      <div class="meta">
        <span class="pill" style="background:{{ severity_color.get(f.severity, '#4b5563') }}">{{ f.severity }}</span>
        <span class="pill" style="background:{{ status_color.get(f.status, '#4b5563') }}">{{ f.status.replace('_', ' ') }}</span>
        <span class="conf" style="background:{{ confidence_color.get(f.confidence, '#4b5563') }}">confidence: {{ f.confidence }}</span>
        · WATCHTOWER Risk Score {{ f.score_value }} · {{ f.tool }}{% if f.cwe %} · {{ f.cwe }}{% endif %} · component: {{ f.component }}
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
      {% if f.explanation %}
      <div class="expl">
        {% if f.explanation.why_it_matters %}<p><span class="k">Why it matters:</span> {{ f.explanation.why_it_matters }}</p>{% endif %}
        {% if f.explanation.what_was_not_tested %}<p><span class="k">What was not tested:</span> {{ f.explanation.what_was_not_tested }}</p>{% endif %}
        {% if f.explanation.limitation %}<p><span class="k">Limitation:</span> {{ f.explanation.limitation }}</p>{% endif %}
        {% if f.explanation.guidance %}<p><span class="k">Guidance:</span> {{ f.explanation.guidance }}</p>{% endif %}
      </div>
      {% endif %}
      {% if f.chain %}
      <ul class="chain">
        {% for rel in ['discovered_by','tested_by','verified_by','supported_by','related_to','affects'] %}
          {% for e in f.chain.get(rel, []) %}
          <li><span class="rel">{{ rel.replace('_', ' ') }}</span> {{ e.label }}{% if e.result %} &rarr; {{ e.result }}{% endif %}</li>
          {% endfor %}
        {% endfor %}
      </ul>
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
<script>
(function () {
  var ids = ['severity', 'status', 'confidence', 'component', 'tool', 'probe'];
  var sels = {};
  ids.forEach(function (k) { sels[k] = document.getElementById('f-' + k); });
  var items = Array.prototype.slice.call(document.querySelectorAll('.filterable'));
  var counter = document.getElementById('f-count');
  function apply() {
    var shown = 0, cards = 0;
    items.forEach(function (el) {
      var ok = ids.every(function (k) {
        var v = sels[k] ? sels[k].value : '';
        return !v || (el.dataset[k] || '') === v;
      });
      el.classList.toggle('hidden', !ok);
      if (el.classList.contains('card')) { cards++; if (ok) shown++; }
    });
    if (counter) counter.textContent = 'showing ' + shown + ' of ' + cards + ' findings';
  }
  ids.forEach(function (k) { if (sels[k]) sels[k].addEventListener('change', apply); });
  var reset = document.getElementById('f-reset');
  if (reset) reset.addEventListener('click', function () {
    ids.forEach(function (k) { if (sels[k]) sels[k].value = ''; });
    apply();
  });
  apply();
})();
</script>
</body>
</html>"""
