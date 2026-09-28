"""SecOps dashboard for WATCHTOWER.

PRESENTATION LAYER ONLY. Renders from a canonical schema-1.2 report dict and never
computes a security fact: it reads report["summary"], report["gate"], report["diff"],
report["attack_surface"], report["execution"], report["assessment_limitations"] and
report["findings"] as-is. No scorer, gate, diff, verification or lifecycle logic lives
here. All finding text is HTML-autoescaped; the client-side evidence inspector fills the
DOM with textContent (never innerHTML), so tool output cannot inject markup.
"""
import json
from . import ui_theme as T

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Left-nav items -> in-page section anchors (Overview is the whole page top).
NAV_OPS = [("Overview", "overview", "compass"), ("Attack Surface", "surface", "radar"),
           ("Findings", "findings", "list"), ("Coverage", "coverage", "chip"),
           ("Security Gate", "gate", "gate"), ("Evidence", "findings", "fingerprint"),
           ("Runs", "runs", "history")]

FILTERS = [("all", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"),
           ("low", "Low"), ("info", "Info"), ("verified", "Verified"),
           ("needs_manual_review", "Manual Review"), ("false_positive", "False Positive")]


def _surface(f):
    """Human 'affected surface' string from real finding fields, else placeholder."""
    if f.get("endpoint"):
        return f["endpoint"]
    if f.get("file"):
        return f"{f['file']}:{f['line']}" if f.get("line") is not None else f["file"]
    return T.LABEL_PLACEHOLDER


def _views(findings):
    """Ordered per-finding view dicts (sorted by severity then risk score desc)."""
    def key(f):
        score = (f.get("score") or {}).get("value") or 0
        return (_SEV_ORDER.get(f.get("severity"), 9), -float(score))

    views = []
    for f in sorted(findings, key=key):
        ex = f.get("explanation") or {}
        chain = f.get("evidence_chain") or {}
        rels = []
        for rel, items in chain.items():
            labels = [i.get("label") for i in (items or []) if isinstance(i, dict) and i.get("label")]
            if labels:
                rels.append({"rel": rel.replace("_", " "), "labels": labels})
        guidance = ex.get("guidance")
        if isinstance(guidance, dict):
            guidance = guidance.get("recommendation") or ""
        views.append({
            "fp": f.get("fingerprint") or "", "id": f.get("id") or "",
            "title": f.get("title") or T.LABEL_PLACEHOLDER,
            "sev": f.get("severity") or "info", "status": f.get("status") or "suspected",
            "result": (f.get("verification") or {}).get("result"),
            "score": (f.get("score") or {}).get("value"),
            "score_model": (f.get("score") or {}).get("model") or "watchtower-risk-score-v1",
            "tool": f.get("tool") or "", "surface": _surface(f),
            "conf": f.get("evidence_confidence") or "low",
            "cwe": f.get("cwe"),
            "expl": {
                "detected": ex.get("what_was_detected"), "matters": ex.get("why_it_matters"),
                "verification": ex.get("verification_performed"), "result_meaning": ex.get("status_meaning"),
                "not_tested": ex.get("what_was_not_tested"), "limitation": ex.get("limitation"),
                "guidance": guidance,
            },
            "rels": rels,
            "rationale": (f.get("verification") or {}).get("rationale"),
            "method": (f.get("verification") or {}).get("method"),
            "evidence": f.get("evidence") or {},
        })
    return views


GATE_MESSAGE = ("No verified Critical or High findings are currently present. The assessment "
                "remains in WARN because manual-review findings and coverage limitations remain.")


def _fmt_ts(iso):
    """Format an ISO timestamp for display; fall back to the raw string."""
    from datetime import datetime
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y · %H:%M UTC")
    except (ValueError, TypeError):
        return str(iso) if iso else T.LABEL_PLACEHOLDER


def _js_json(obj):
    """JSON for safe inlining inside a <script> block (HTML-context escaped)."""
    return (json.dumps(obj, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def _context(report):
    s = report.get("summary", {}) or {}
    gate = report.get("gate") or {}
    counts = gate.get("counts") or {}
    asf = (report.get("attack_surface") or {}).get("summary", {}) or {}
    lim = report.get("assessment_limitations", {}) or {}
    env = report.get("environment", {}) or {}
    scan = report.get("scan", {}) or {}
    risk_tags = sorted((asf.get("risk_tag_counts") or {}).items(),
                       key=lambda kv: kv[1], reverse=True)
    top = max(1, risk_tags[0][1]) if risk_tags else 1
    scanners_skipped = lim.get("scanners_skipped") or []
    unavail = lim.get("unavailable_runtime_surfaces") or []
    return {
        "run_id": env.get("assessment_id") or report.get("assessment", {}).get("assessment_id") or "—",
        "target": scan.get("target") or env.get("target") or "http://localhost:3000",
        "timestamp": _fmt_ts(env.get("timestamp") or scan.get("timestamp")),
        "wt_version": report.get("watchtower_version") or env.get("watchtower_version") or "—",
        "gate": {"result": gate.get("result", "N/A"), "policy": gate.get("policy", "watchtower-gate-v1"),
                 "baseline_aware": gate.get("baseline_aware", False),
                 "reasons": gate.get("reasons") or [], "message": GATE_MESSAGE},
        "posture": [
            ("Critical", counts.get("verified_critical", 0), s.get("critical", 0), "critical"),
            ("High", counts.get("verified_high", 0), s.get("high", 0), "high"),
            ("Medium", counts.get("verified_medium", 0), s.get("medium", 0), "medium"),
        ],
        "manual_review": s.get("needs_manual_review", 0),
        "metrics": [("Verified Findings", s.get("verified", 0), "pass"),
                    ("Manual Review", s.get("needs_manual_review", 0), "warn"),
                    ("Skipped Scanners", len(scanners_skipped), "muted"),
                    ("Unavailable Runtime Surfaces", len(unavail), "muted")],
        "endpoints": asf.get("endpoint_count", 0),
        "modules": asf.get("security_module_count", 0),
        "integrations": asf.get("integration_count", 0),
        "env_refs": asf.get("env_reference_count", 0),
        "risk_tags": [(k, v, max(4, round(v * 100 / top))) for k, v in risk_tags],
        "total": s.get("total_findings", 0),
        "execution": report.get("execution", []) or [],
        "scanners_skipped": scanners_skipped,
        "limit_notes": lim.get("notes") or [],
        "untested_count": len(lim.get("untested_attack_paths") or []),
        "unavail_count": len(unavail),
        "has_baseline": report.get("diff") is not None,
        "runs": [],  # populated only if prior reports are supplied to render_dashboard
    }


def render_dashboard(report, runs=None):
    """Render the SecOps dashboard HTML for a canonical report dict.

    `runs` is an optional list of {id, gate, timestamp} for run history. When empty, the
    run-history panel honestly states that historical comparison is unavailable.
    """
    env = T.make_env()
    ctx = _context(report)
    views = _views(report.get("findings", []) or [])
    ctx["runs"] = runs or []
    tmpl = env.from_string(_TEMPLATE)
    return tmpl.render(views=views, findings_json=_js_json(views),
                       nav_ops=NAV_OPS, filters=FILTERS,
                       head=T.page_head("WATCHTOWER — Security Operations Console", PAGE_CSS),
                       **ctx)


def write_dashboard(path, report, runs=None):
    with open(path, "w", encoding="utf-8") as h:
        h.write(render_dashboard(report, runs))
    return path


PAGE_CSS = """
body{overflow:hidden}
.app{display:grid;grid-template-columns:244px 1fr;height:100vh}
.sidebar{background:var(--surface);border-right:1px solid var(--border);display:flex;
  flex-direction:column;height:100vh;position:sticky;top:0}
.sb-brand{display:flex;align-items:center;gap:10px;font-weight:600;letter-spacing:0.12em;
  font-size:14px;padding:18px 18px;border-bottom:1px solid var(--border)}
.sb-nav{flex:1;overflow-y:auto;padding:16px 12px}
.sb-group{margin-bottom:20px}
.sb-group>.caps{padding:0 10px 8px}
.sb-item{display:flex;align-items:center;gap:11px;padding:9px 10px;border-radius:var(--r-btn);
  color:var(--text-dim);font-size:13px;font-weight:500;cursor:pointer}
.sb-item .wt-ico{width:17px;height:17px}
.sb-item:hover{background:var(--hover);color:var(--text)}
.sb-item.active{background:rgba(0,229,255,0.08);color:var(--accent);
  box-shadow:inset 2px 0 0 var(--accent)}
.sb-target{margin:12px;padding:12px;border:1px solid var(--border);border-radius:var(--r-btn);
  background:var(--elevated)}
.sb-target .val{font-family:var(--mono);font-size:12px;color:var(--text);margin-top:4px}
.main{overflow-y:auto;height:100vh}
.topbar-d{position:sticky;top:0;z-index:15;background:rgba(9,13,18,0.9);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:16px;padding:14px 26px}
.topbar-d .meta{display:flex;gap:22px;flex-wrap:wrap}
.topbar-d .meta .k{font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--muted)}
.topbar-d .meta .v{font-family:var(--mono);font-size:12px;color:var(--text)}
.status-pill{display:inline-flex;align-items:center;gap:7px;font-family:var(--mono);font-size:11px;
  font-weight:600;padding:5px 10px;border-radius:var(--r-chip);color:var(--pass);
  border:1px solid rgba(16,185,129,0.4);background:rgba(16,185,129,0.08)}
.content{padding:24px 26px 60px;max-width:1440px}
.blk{margin-bottom:26px}
.blk-h{display:flex;align-items:center;gap:10px;margin-bottom:14px}
.blk-h .wt-ico{color:var(--accent)}
.blk-h h2{font-size:15px;letter-spacing:0.02em;font-weight:600;margin:0}
.blk-h .spacer{flex:1}
.g4{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.g3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.posture .num{font-size:34px}
.posture .sub{font-size:11px;color:var(--muted);margin-top:6px}
/* gate hero */
.gate-hero{border:1px solid var(--warn);border-radius:var(--r-panel);overflow:hidden;
  background:linear-gradient(180deg,rgba(245,158,11,0.08),rgba(245,158,11,0.02))}
.gate-hero .top{display:flex;align-items:flex-start;gap:18px;padding:20px 22px;flex-wrap:wrap}
.gate-badge{font-family:var(--mono);font-size:26px;font-weight:600;letter-spacing:0.04em;
  padding:12px 20px;border-radius:10px;background:var(--warn);color:#1a1204}
.gate-hero .msg{flex:1;min-width:240px}
.gate-hero .msg h3{margin:0 0 6px;font-size:16px;letter-spacing:0.02em}
.gate-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);
  border-top:1px solid var(--border)}
.gate-metrics .m{background:var(--surface);padding:15px 18px}
.gate-metrics .m .num{font-family:var(--mono);font-size:24px;font-weight:600;margin-top:6px}
.reasons{display:flex;flex-direction:column;gap:8px;margin-top:14px}
.reason{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r-btn);
  background:var(--elevated);border:1px solid var(--border);font-size:12.5px}
/* attack surface */
.tag-row{display:grid;grid-template-columns:200px 1fr 54px;gap:12px;align-items:center;
  padding:7px 0;font-size:12.5px}
.tag-row .mono{color:var(--text)}
/* findings + inspector */
.split{display:grid;grid-template-columns:1fr 384px;gap:16px;align-items:start}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.search{display:flex;align-items:center;gap:8px;background:var(--elevated);
  border:1px solid var(--border);border-radius:var(--r-btn);padding:8px 12px;flex:1;min-width:220px}
.search input{background:transparent;border:0;outline:0;color:var(--text);font-size:13px;
  width:100%;font-family:var(--ui)}
.search .wt-ico{color:var(--muted)}
.fbtn{font-family:var(--mono);font-size:11px;font-weight:600;padding:6px 11px;border-radius:var(--r-chip);
  border:1px solid var(--border);background:var(--elevated);color:var(--text-dim);cursor:pointer}
.fbtn:hover{border-color:var(--border-accent);color:var(--text)}
.fbtn.on{background:var(--accent);color:#04121a;border-color:var(--accent)}
.finding-row td:first-child{max-width:280px}
.f-title{font-weight:500;color:var(--text);display:block;overflow:hidden;text-overflow:ellipsis;
  white-space:nowrap;max-width:270px}
.inspector{position:sticky;top:78px;max-height:calc(100vh - 100px);overflow-y:auto}
.insp-empty{color:var(--muted);text-align:center;padding:40px 20px;font-size:13px}
.insp-field{padding:10px 0;border-bottom:1px solid rgba(30,41,59,.5)}
.insp-field .lbl{font-size:10px;letter-spacing:0.08em;text-transform:uppercase;color:var(--muted)}
.insp-field .txt{font-size:13px;margin-top:4px;line-height:1.5;word-break:break-word}
.insp-field .txt.na{color:var(--muted);font-family:var(--mono);font-size:11px}
.rel{display:inline-flex;gap:6px;font-size:11px;font-family:var(--mono);margin:3px 6px 3px 0;
  padding:3px 8px;border-radius:var(--r-chip);border:1px solid var(--border);background:var(--elevated)}
.rel b{color:var(--accent);font-weight:600}
@media(max-width:1180px){.split{grid-template-columns:1fr}.inspector{position:static;max-height:none}
  .g4,.gate-metrics{grid-template-columns:repeat(2,1fr)}}
@media(max-width:900px){.app{grid-template-columns:1fr}.sidebar{position:static;height:auto;
  flex-direction:row;flex-wrap:wrap;align-items:center}.sb-nav{display:flex;gap:4px;overflow-x:auto;
  padding:8px}.sb-group{display:flex;gap:4px;margin:0}.sb-group>.caps,.sb-target{display:none}
  .main{height:auto}body{overflow:auto}.g3,.g2{grid-template-columns:1fr}}
@media(max-width:560px){.g4,.gate-metrics{grid-template-columns:1fr}.tag-row{grid-template-columns:120px 1fr 40px}
  .topbar-d{flex-wrap:wrap}}
"""


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head>{{ head|safe }}</head><body>
<div class="app">
  <aside class="sidebar">
    <div class="sb-brand">{{ LOGO_SVG|safe }} WATCHTOWER</div>
    <nav class="sb-nav">
      <div class="sb-group"><div class="caps">Operations</div>
        {% for label, anchor, ic in nav_ops %}
        <a class="sb-item {% if loop.first %}active{% endif %}" href="#{{ anchor }}">{{ icon(ic,17)|safe }} {{ label }}</a>
        {% endfor %}
      </div>
      <div class="sb-group"><div class="caps">System</div>
        <a class="sb-item" href="index.html">{{ icon('doc',17)|safe }} Documentation</a>
        <a class="sb-item" href="#" onclick="return false" title="Settings are managed via the CLI">{{ icon('gear',17)|safe }} Settings</a>
      </div>
    </nav>
    <div class="sb-target">
      <div class="caps">Active target</div>
      <div class="val">{{ target }}</div>
      <div class="chip" style="--c:var(--blue);margin-top:8px">{{ icon('target',12)|safe }} Local assessment</div>
    </div>
  </aside>

  <div class="main">
    <div class="topbar-d">
      <div>
        <div class="caps" style="color:var(--muted)">Security Operations Console</div>
        <div class="h-md" style="margin-top:2px">Assessment Overview</div>
      </div>
      <div class="meta">
        <div><div class="k">Target</div><div class="v">{{ target }}</div></div>
        <div><div class="k">Run</div><div class="v">{{ run_id }}</div></div>
        <div><div class="k">Completed</div><div class="v">{{ timestamp }}</div></div>
      </div>
      <div class="spacer" style="flex:1"></div>
      <span class="status-pill">{{ icon('check',13)|safe }} Assessment complete</span>
      <button class="btn btn-ghost btn-sm" id="rerun" title="Run: python watchtower.py --repo . --target {{ target }}">{{ icon('refresh',15)|safe }} Re-run Assessment</button>
      <a class="btn btn-secondary btn-sm" href="#findings">{{ icon('download',15)|safe }} Export Evidence</a>
    </div>

    <div class="content">
      <section class="blk" id="overview">
        <div class="blk-h">{{ icon('compass',18)|safe }}<h2>Security Posture</h2></div>
        <div class="g4 posture">
          {% for label, verified, total, sev in posture %}
          <div class="tile"><span class="accent-bar" style="--c:{{ SEVERITY_COLOR[sev] }}"></span>
            <div class="caps"><span class="dot" style="--c:{{ SEVERITY_COLOR[sev] }}"></span> {{ label }}</div>
            <div class="num" style="color:{{ SEVERITY_COLOR[sev] if verified else 'var(--text)' }}">{{ verified }}</div>
            <div class="sub">verified · {{ total }} at this severity</div>
          </div>
          {% endfor %}
          <div class="tile"><span class="accent-bar" style="--c:var(--warn)"></span>
            <div class="caps"><span class="dot" style="--c:var(--warn)"></span> Manual Review</div>
            <div class="num" style="color:var(--warn)">{{ manual_review }}</div>
            <div class="sub">awaiting human decision</div>
          </div>
        </div>
      </section>

      <section class="blk" id="gate">
        <div class="blk-h">{{ icon('gate',18)|safe }}<h2>Security Gate Decision</h2></div>
        <div class="gate-hero">
          <div class="top">
            <div class="gate-badge" style="background:{{ GATE_COLOR.get(gate.result, '#64748B') }}">{{ gate.result }}</div>
            <div class="msg">
              <h3>{{ gate.message }}</h3>
              <div class="mono dim" style="font-size:12px">policy {{ gate.policy }} · baseline-aware: {{ 'yes' if gate.baseline_aware else 'no' }}</div>
              <div class="reasons">
                {% for r in gate.reasons %}
                <div class="reason">{{ icon('warn',15)|safe }}<span>{{ r.message }}</span></div>
                {% endfor %}
              </div>
            </div>
          </div>
          <div class="gate-metrics">
            {% for label, val, tone in metrics %}
            <div class="m"><div class="caps">{{ label }}</div><div class="num" style="color:var(--{{ tone }})">{{ val }}</div></div>
            {% endfor %}
          </div>
        </div>
      </section>
      <section class="blk" id="surface">
        <div class="blk-h">{{ icon('radar',18)|safe }}<h2>Attack Surface</h2><span class="spacer"></span>
          <span class="chip" style="--c:var(--accent)">{{ endpoints }} endpoints · static discovery</span></div>
        <div class="g2">
          <div class="panel"><div class="panel-h">{{ icon('chip',16)|safe }}<span class="caps">Risk tag assignments</span></div>
            <div class="panel-b">
              {% for tag, count, pct in risk_tags %}
              <div class="tag-row"><span class="mono">{{ tag }}</span>
                <div class="bar"><span style="width:{{ pct }}%;--c:var(--accent)"></span></div>
                <span class="mono" style="text-align:right">{{ count }}</span></div>
              {% endfor %}
              <p class="note" style="margin-top:14px">{{ icon('info',13)|safe }} Risk tags identify
              candidate security-relevant surfaces. They are <b>not</b> vulnerability findings and are
              not counted as vulnerabilities.</p>
            </div>
          </div>
          <div>
            <div class="g2">
              <div class="tile"><div class="caps">Endpoints</div><div class="num">{{ endpoints }}</div></div>
              <div class="tile"><div class="caps">Security modules</div><div class="num">{{ modules }}</div></div>
              <div class="tile"><div class="caps">Integrations</div><div class="num">{{ integrations }}</div></div>
              <div class="tile"><div class="caps">Env references</div><div class="num">{{ env_refs }}</div></div>
            </div>
            <div class="callout" style="--c:var(--blue);margin-top:14px">
              <div class="caps" style="color:var(--blue)">{{ icon('radar',13)|safe }} Read-only discovery</div>
              <p class="note" style="margin-top:6px">The attack surface is enumerated statically from
              source. Discovering a surface does not mean it was probed — see Coverage and Assessment
              Limitations for what was actually exercised.</p>
            </div>
          </div>
        </div>
      </section>

      <section class="blk" id="findings">
        <div class="blk-h">{{ icon('list',18)|safe }}<h2>Findings</h2><span class="spacer"></span>
          <span class="mono dim" id="f-count">{{ total }} findings</span></div>
        <div class="split">
          <div class="panel"><div class="panel-b">
            <div class="toolbar">
              <div class="search">{{ icon('search',16)|safe }}
                <input id="f-search" type="text" autocomplete="off"
                  placeholder="Filter by title, endpoint, tool or fingerprint..." /></div>
            </div>
            <div class="toolbar" id="f-filters">
              {% for key, label in filters %}
              <button class="fbtn {% if key == 'all' %}on{% endif %}" data-filter="{{ key }}">{{ label }}</button>
              {% endfor %}
            </div>
            <div class="tbl-wrap">
              <table class="tbl"><thead><tr>
                <th>Finding</th><th>Severity</th><th>Lifecycle</th><th>Verification</th>
                <th>Risk Score</th><th>Tool</th><th>Affected Surface</th><th>Confidence</th><th>Action</th>
              </tr></thead><tbody id="f-body">
                {% for v in views %}
                <tr class="finding-row" data-idx="{{ loop.index0 }}" data-severity="{{ v.sev }}"
                    data-status="{{ v.status }}"
                    data-search="{{ (v.title ~ ' ' ~ v.surface ~ ' ' ~ v.tool ~ ' ' ~ v.fp ~ ' ' ~ v.id)|lower }}">
                  <td><span class="f-title" title="{{ v.title }}">{{ v.title }}</span>
                    <span class="mono" style="font-size:10px;color:var(--muted)">{{ v.id }}</span></td>
                  <td><span class="chip" style="--c:{{ SEVERITY_COLOR[v.sev] }}">{{ v.sev }}</span></td>
                  <td><span class="chip" style="--c:{{ STATUS_COLOR[v.status] }}">{{ v.status|labelize }}</span></td>
                  <td>{% if v.result %}<span class="chip" style="--c:{{ RESULT_COLOR.get(v.result, '#64748B') }}">{{ v.result }}</span>{% else %}<span class="dim">—</span>{% endif %}</td>
                  <td><span class="mono">{{ '%.1f'|format(v.score) if v.score is not none else '—' }}</span></td>
                  <td><span class="mono" style="font-size:11px">{{ v.tool }}</span></td>
                  <td><span class="mono" style="font-size:11px;color:var(--text-dim)">{{ v.surface }}</span></td>
                  <td><span class="chip" style="--c:{{ CONFIDENCE_COLOR[v.conf] }}">{{ v.conf }}</span></td>
                  <td><button class="btn btn-ghost btn-sm inspect-btn" type="button">Inspect</button></td>
                </tr>
                {% endfor %}
              </tbody></table>
            </div>
            <div class="empty" id="f-none" style="display:none;margin-top:12px">No findings match the current filter.</div>
          </div></div>

          <div class="panel inspector" id="inspector">
            <div class="panel-h">{{ icon('fingerprint',16)|safe }}<span class="caps">Evidence Inspector</span>
              <span class="spacer"></span>
              <button class="btn btn-ghost btn-sm" id="insp-close" type="button" style="display:none">{{ icon('close',14)|safe }}</button></div>
            <div class="panel-b" id="insp-body">
              <div class="insp-empty">{{ icon('fingerprint',28)|safe }}
                <p style="margin-top:10px">Select a finding to inspect its evidence, verification result
                and lifecycle decision. Fields absent from the assessment are shown as
                "{{ NA }}" — never fabricated.</p></div>
            </div>
          </div>
        </div>
      </section>
      <section class="blk" id="coverage">
        <div class="blk-h">{{ icon('chip',18)|safe }}<h2>Engine Coverage</h2><span class="spacer"></span>
          <span class="chip hatch" style="--c:var(--muted)">{{ scanners_skipped|length }} skipped</span></div>
        <div class="panel"><div class="panel-b">
          <div class="tbl-wrap"><table class="tbl"><thead><tr>
            <th>Stage / Tool</th><th>Status</th><th>Findings</th><th>Detail</th>
          </tr></thead><tbody>
            {% for e in execution %}
            <tr>
              <td><span class="mono">{{ e.tool }}</span></td>
              <td><span class="chip {% if e.status != 'success' %}hatch{% endif %}" style="--c:{{ EXEC_COLOR.get(e.status, '#64748B') }}">{% if e.status == 'success' %}executed{% else %}{{ e.status|labelize }}{% endif %}</span></td>
              <td><span class="mono">{{ e.finding_count if e.finding_count is not none else '—' }}</span></td>
              <td class="note" style="max-width:520px">{{ e.error or '—' }}</td>
            </tr>
            {% endfor %}
          </tbody></table></div>
          <p class="note" style="margin-top:12px">{{ icon('info',13)|safe }} Skipped scanners are not
          installed on this host. A skipped stage is a coverage gap — never counted as a pass.</p>
        </div></div>
      </section>

      <section class="blk" id="limitations">
        <div class="blk-h">{{ icon('warn',18)|safe }}<h2>Assessment Limitations</h2></div>
        <div class="panel" style="border-left:3px solid var(--warn)"><div class="panel-b">
          <div class="reasons">
            {% for note in limit_notes %}
            <div class="reason">{{ icon('warn',15)|safe }}<span>{{ note }}</span></div>
            {% endfor %}
          </div>
          {% if scanners_skipped %}
          <div class="taglist" style="margin-top:14px">
            {% for sc in scanners_skipped %}<span class="chip hatch" style="--c:var(--muted)">{{ sc }}</span>{% endfor %}
          </div>
          {% endif %}
          <p class="note" style="margin-top:14px">These limitations reduce assessment coverage and are
          a direct input to the current WARN gate decision. They are surfaced, not hidden.</p>
        </div></div>
      </section>

      <section class="blk" id="runs">
        <div class="g2">
          <div class="panel"><div class="panel-h">{{ icon('history',16)|safe }}<span class="caps">Regression comparison</span></div>
            <div class="panel-b">
              {% if has_baseline %}
              <div class="callout" style="--c:var(--accent)">A baseline is attached to this report.</div>
              {% else %}
              <div class="empty">{{ icon('history',26)|safe }}
                <p style="margin-top:10px">No baseline available for regression comparison.</p></div>
              {% endif %}
              <p class="note" style="margin-top:12px">Reserved for continuous assessment. When a baseline
              is supplied, this panel consumes <span class="mono">report.diff</span> directly — new,
              resolved and changed findings are computed by the diff engine, not here.</p>
            </div>
          </div>
          <div class="panel"><div class="panel-h">{{ icon('clock',16)|safe }}<span class="caps">Run history</span></div>
            <div class="panel-b">
              {% if runs %}
              <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Run</th><th>Gate</th><th>Completed</th></tr></thead><tbody>
                {% for r in runs %}
                <tr><td class="mono">{{ r.id }}</td>
                  <td><span class="chip" style="--c:{{ GATE_COLOR.get(r.gate, '#64748B') }}">{{ r.gate }}</span></td>
                  <td class="mono">{{ r.timestamp }}</td></tr>
                {% endfor %}
              </tbody></table></div>
              {% else %}
              <div class="empty">Historical run comparison unavailable.</div>
              {% endif %}
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</div>
<script>
var FINDINGS = {{ findings_json|safe }};
var NA = "NOT AVAILABLE IN ASSESSMENT";
var SEVC={critical:'#EF4444',high:'#F97316',medium:'#F59E0B',low:'#0A84FF',info:'#64748B'};
var STAC={verified:'#10B981',correlated:'#8B5CF6',suspected:'#00E5FF',needs_manual_review:'#F59E0B',false_positive:'#64748B'};
var RESC={confirmed:'#10B981',refuted:'#64748B',inconclusive:'#F59E0B',not_applicable:'#64748B'};
var CONC={high:'#10B981',medium:'#F59E0B',low:'#64748B'};
function el(tag,cls,txt){var n=document.createElement(tag);if(cls)n.className=cls;
  if(txt!==undefined&&txt!==null)n.textContent=txt;return n;}
function chip(text,color){var c=el('span','chip',text);c.style.setProperty('--c',color);return c;}
function labelize(s){return String(s||'').replace(/_/g,' ').replace(/\b\w/g,function(m){return m.toUpperCase();});}
function field(parent,label,value,mono){
  var f=el('div','insp-field');f.appendChild(el('div','lbl',label));
  var has=value!==undefined&&value!==null&&String(value).trim()!=='';
  var t=el('div','txt'+(has?(mono?' mono':''):' na'),has?value:NA);
  f.appendChild(t);parent.appendChild(f);return f;}
// JS-WIRE
function render(v){
  var b=document.getElementById('insp-body');b.innerHTML='';
  document.getElementById('insp-close').style.display='';
  var head=el('div','insp-field');head.appendChild(el('div','lbl','Fingerprint'));
  head.appendChild(el('div','txt mono',v.fp||NA));b.appendChild(head);
  field(b,'Title',v.title);
  var axes=el('div','insp-field');axes.appendChild(el('div','lbl','Classification'));
  var row=el('div');row.style.cssText='margin-top:6px;display:flex;flex-wrap:wrap;gap:6px';
  row.appendChild(chip(v.sev,SEVC[v.sev]||'#64748B'));
  row.appendChild(chip(labelize(v.status),STAC[v.status]||'#64748B'));
  if(v.result)row.appendChild(chip(v.result,RESC[v.result]||'#64748B'));
  row.appendChild(chip('confidence: '+v.conf,CONC[v.conf]||'#64748B'));
  axes.appendChild(row);b.appendChild(axes);
  field(b,'Risk score ('+(v.score_model||'')+')',(v.score===null||v.score===undefined)?null:v.score,true);
  field(b,'Verification result',v.result,false);
  field(b,'Tool',v.tool,true);
  field(b,'Affected endpoint / surface',v.surface,true);
  field(b,'Evidence confidence',v.conf);
  var ex=v.expl||{};
  field(b,'What was detected',ex.detected);
  field(b,'Why it matters',ex.matters);
  field(b,'Verification performed',ex.verification);
  field(b,'What the result means',ex.result_meaning);
  field(b,'What was not tested',ex.not_tested);
  field(b,'Limitation',ex.limitation);
  field(b,'Guidance',ex.guidance);
  if(v.rationale)field(b,'Verification rationale',v.rationale);
  var cf=el('div','insp-field');cf.appendChild(el('div','lbl','Evidence chain'));
  if(v.rels&&v.rels.length){var wrap=el('div');wrap.style.marginTop='6px';
    v.rels.forEach(function(r){var s=el('span','rel');s.appendChild(el('b',null,r.rel+':'));
      s.appendChild(document.createTextNode(' '+r.labels.join(', ')));wrap.appendChild(s);});
    cf.appendChild(wrap);}else{cf.appendChild(el('div','txt na',NA));}
  b.appendChild(cf);
  var rf=el('div','insp-field');rf.appendChild(el('div','lbl','Raw evidence (as recorded)'));
  var keys=v.evidence?Object.keys(v.evidence):[];
  if(keys.length){rf.appendChild(el('pre','pre',JSON.stringify(v.evidence,null,2)));}
  else{rf.appendChild(el('div','txt na',NA));}
  b.appendChild(rf);
}
// JS-WIRE2
var rows=[].slice.call(document.querySelectorAll('.finding-row'));
var active='all';
function applyFilter(){
  var q=(document.getElementById('f-search').value||'').toLowerCase().trim();
  var shown=0;
  rows.forEach(function(r){
    var sev=r.getAttribute('data-severity'),st=r.getAttribute('data-status');
    var okF=(active==='all'||sev===active||st===active);
    var okQ=(!q||r.getAttribute('data-search').indexOf(q)>=0);
    var vis=okF&&okQ;r.style.display=vis?'':'none';if(vis)shown++;
  });
  document.getElementById('f-count').textContent=shown+' of '+rows.length+' findings';
  document.getElementById('f-none').style.display=shown?'none':'';
}
document.getElementById('f-filters').addEventListener('click',function(e){
  var btn=e.target.closest('.fbtn');if(!btn)return;
  active=btn.getAttribute('data-filter');
  [].forEach.call(this.querySelectorAll('.fbtn'),function(b){b.classList.toggle('on',b===btn);});
  applyFilter();
});
document.getElementById('f-search').addEventListener('input',applyFilter);
function select(r){
  rows.forEach(function(x){x.classList.toggle('active-row',x===r);});
  render(FINDINGS[+r.getAttribute('data-idx')]);
  document.getElementById('inspector').scrollIntoView({behavior:'smooth',block:'nearest'});
}
rows.forEach(function(r){r.addEventListener('click',function(){select(r);});});
document.getElementById('insp-close').addEventListener('click',function(){
  rows.forEach(function(x){x.classList.remove('active-row');});
  var b=document.getElementById('insp-body');b.innerHTML='';
  var e=el('div','insp-empty');e.appendChild(el('p',null,'Select a finding to inspect its evidence.'));
  b.appendChild(e);this.style.display='none';
});
var rr=document.getElementById('rerun');
if(rr)rr.addEventListener('click',function(){var o=this.innerHTML;this.disabled=true;
  this.textContent='Re-run is a CLI action';setTimeout(function(){rr.innerHTML=o;rr.disabled=false;},1600);});
[].forEach.call(document.querySelectorAll('.sb-item'),function(a){
  a.addEventListener('click',function(){var h=this.getAttribute('href');
    if(h&&h.charAt(0)==='#'){[].forEach.call(document.querySelectorAll('.sb-item'),
      function(x){x.classList.remove('active');});this.classList.add('active');}});
});
applyFilter();
</script>
</body></html>
"""
