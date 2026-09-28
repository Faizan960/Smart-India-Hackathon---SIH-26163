"""Landing / project page for WATCHTOWER.

PRESENTATION LAYER ONLY. Renders from a canonical schema-1.2 report dict; contains no
scorer, gate, diff, verification or lifecycle logic. All security values shown here are
read from the report (or the report's embedded gate). Static product copy describes only
functionality that is actually implemented; no fabricated telemetry, CVEs or claims.
"""
from . import ui_theme as T

# 8 real pipeline stages (names fixed by spec; copy describes actual engine behaviour).
PIPELINE = [
    ("DISCOVER", "radar", "Static, read-only attack-surface discovery enumerates endpoints, "
     "integrations, environment references and risk-tagged surfaces from the target's source."),
    ("SCAN", "flask", "Configured scanners and active probes run against the local target. "
     "Uninstalled scanners are skipped and recorded as coverage limitations — never silently."),
    ("NORMALIZE", "layers", "Heterogeneous tool output is normalized into one finding model, "
     "each with a stable content fingerprint used as its identity."),
    ("CORRELATE", "hub", "Findings describing the same weakness across tools are grouped so "
     "corroborating evidence is visible and duplicates collapse."),
    ("VERIFY", "check", "Active probes attempt to confirm or refute suspected weaknesses. "
     "Results are recorded as confirmed, refuted, inconclusive or not applicable."),
    ("SCORE", "scale", "Each finding receives a WATCHTOWER Risk Score (watchtower-risk-score-v1) "
     "from severity, verification and asset factors. This is not CVSS."),
    ("EXPLAIN", "compass", "Every finding carries a plain-language explanation, an evidence "
     "chain and an evidence-confidence rating (high / medium / low)."),
    ("REPORT", "doc", "A reproducible report.json / report.html / report.sarif is produced and "
     "a security gate renders a PASS / WARN / FAIL decision."),
]

CAPABILITIES = [
    ("Attack Surface Discovery", "radar",
     "Static, read-only enumeration of endpoints, integrations and environment references. "
     "Risk tags mark candidate security-relevant surfaces — they are not vulnerability findings."),
    ("Evidence-Based Verification", "check",
     "Active probes exercise suspected weaknesses and record confirmed / refuted / inconclusive "
     "/ not-applicable results. Inconclusive is never promoted to verified."),
    ("Multi-Scanner Correlation", "hub",
     "Normalized findings are fingerprinted, de-duplicated and correlated across tools so shared "
     "evidence is grouped rather than double-counted."),
    ("Security Gate", "gate",
     "A structured watchtower-gate-v1 decision (PASS / WARN / FAIL) driven by verified findings "
     "and coverage limitations, with an optional baseline for regression comparison."),
]

# Checks actually implemented and exercised vs integrated-but-skipped scanners.
CHECKS_ACTIVE = ["attack-surface discovery", "npm audit", "security headers", "CORS policy",
                 "rate-limit enforcement", "MCP / auth access control", "SSRF checks",
                 "correlation", "verification", "baseline comparison", "security gate"]
SCANNERS_OPTIONAL = ["semgrep", "gitleaks", "osv-scanner", "zap", "nuclei"]

ARCH_NODES = [
    ("TARGET APPLICATION", "target", "Local instance under assessment (http://localhost:3000)."),
    ("ATTACK-SURFACE DISCOVERY", "radar", "Static endpoint / integration / env enumeration."),
    ("SCANNER / CHECK EXECUTION", "flask", "Scanners + active probes; skips recorded honestly."),
    ("NORMALIZATION", "layers", "Unified finding model + stable fingerprints."),
    ("CORRELATION", "hub", "Cross-tool grouping and de-duplication."),
    ("VERIFICATION", "check", "Confirm / refute / inconclusive / not applicable."),
    ("RISK SCORING", "scale", "watchtower-risk-score-v1 (not CVSS)."),
    ("EXPLANATION + EVIDENCE", "compass", "Explanations, evidence chains, confidence."),
    ("REPORT", "doc", "report.json · report.html · report.sarif."),
    ("SECURITY GATE", "gate", "watchtower-gate-v1 · PASS / WARN / FAIL."),
]

SNAPSHOT_NOTE = ("Snapshot from the current local World Monitor assessment. Values are "
                 "assessment-specific and not presented as global product performance.")

PAGE_CSS = """
.wrap{max-width:1120px;margin:0 auto;padding:0 24px}
.topbar{position:sticky;top:0;z-index:20;background:rgba(9,13,18,0.82);
  backdrop-filter:blur(10px);border-bottom:1px solid var(--border)}
.topbar .wrap{display:flex;align-items:center;gap:16px;height:60px}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;letter-spacing:0.12em;font-size:14px}
.topnav{display:flex;gap:22px;margin-left:20px}
.topnav a{font-size:13px;color:var(--text-dim)}
.topnav a:hover{color:var(--accent)}
.spacer{flex:1}
section{padding:76px 0}
.hero{padding:72px 0 60px;position:relative;overflow:hidden}
.hero:before{content:"";position:absolute;inset:0;background:
  radial-gradient(680px 320px at 22% -8%,rgba(0,229,255,0.10),transparent 70%);pointer-events:none}
.eyebrow{display:inline-flex;align-items:center;gap:8px;border:1px solid var(--border-accent);
  border-radius:var(--r-chip);padding:5px 11px;color:var(--accent);font-family:var(--mono);
  font-size:11px;letter-spacing:0.08em}
.hero h1{font-size:clamp(40px,7vw,66px);line-height:1;letter-spacing:-0.03em;font-weight:600;
  margin:22px 0 12px}
.hero .tag{font-size:clamp(17px,2.4vw,22px);color:var(--text);font-weight:500;margin:0 0 16px}
.hero .desc{max-width:640px;color:var(--text-dim);font-size:15px;line-height:1.6}
.cta-row{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px}
.flow{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:40px}
.flow .node{display:inline-flex;align-items:center;gap:7px;background:var(--elevated);
  border:1px solid var(--border);border-radius:var(--r-chip);padding:7px 11px;
  font-family:var(--mono);font-size:11px;letter-spacing:0.06em}
.flow .node .wt-ico{width:14px;height:14px;color:var(--accent)}
.flow .sep{color:var(--muted)}
.sec-head{margin-bottom:30px}
.sec-head .caps{color:var(--accent)}
.sec-head h2{font-size:clamp(24px,3.4vw,32px);line-height:1.15;letter-spacing:-0.02em;
  font-weight:600;margin:8px 0 8px}
.sec-head p{color:var(--text-dim);max-width:640px;font-size:14px}
.cols-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.cols-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
.step{display:flex;gap:16px;padding:18px 0;border-top:1px solid var(--border)}
.step .n{font-family:var(--mono);font-size:13px;color:var(--accent);width:34px;flex:0 0 auto;
  border:1px solid var(--border-accent);border-radius:var(--r-chip);height:34px;
  display:flex;align-items:center;justify-content:center}
.step h3{margin:2px 0 6px;font-size:15px;letter-spacing:0.02em}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-panel);
  padding:20px;transition:.15s}
.card:hover{border-color:var(--border-accent);background:var(--elevated)}
.card .ic{width:38px;height:38px;border-radius:9px;background:rgba(0,229,255,0.08);
  border:1px solid var(--border-accent);display:flex;align-items:center;justify-content:center;
  color:var(--accent);margin-bottom:14px}
.card h3{font-size:15px;margin:0 0 8px}
.card p{color:var(--text-dim);font-size:13px;line-height:1.55;margin:0}
.taglist{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.arch{display:grid;grid-template-columns:1fr 300px;gap:22px;align-items:start}
.arch-flow{display:flex;flex-direction:column;gap:0}
.arch-node{display:flex;gap:14px;align-items:center;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--r-btn);padding:13px 15px}
.arch-node .ic{color:var(--accent);width:20px;height:20px}
.arch-node.gate{border-color:var(--warn);background:rgba(245,158,11,0.06)}
.arch-conn{height:16px;width:2px;background:var(--border-accent);margin-left:26px}
.arch-side .panel{margin-bottom:14px}
.snap{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}
.snap .tile .num{font-size:34px}
.final{text-align:center;padding:80px 0}
.final h2{font-size:clamp(26px,4vw,40px);line-height:1.12;letter-spacing:-0.025em;
  max-width:760px;margin:0 auto 26px;font-weight:600}
footer{border-top:1px solid var(--border);padding:26px 0;color:var(--muted);font-size:12px}
@media(max-width:900px){.cols-2,.cols-4,.arch{grid-template-columns:1fr}
  .snap{grid-template-columns:repeat(3,1fr)}.arch-side{margin-top:8px}}
@media(max-width:560px){.snap{grid-template-columns:repeat(2,1fr)}.topnav{display:none}
  section{padding:52px 0}}
"""


def _context(report):
    """Read display values from the canonical report — no computation of security facts."""
    s = report.get("summary", {}) or {}
    asf = (report.get("attack_surface") or {}).get("summary", {}) or {}
    gate = report.get("gate") or {}
    risk_tags = sorted((asf.get("risk_tag_counts") or {}).items(),
                       key=lambda kv: kv[1], reverse=True)
    top = max(1, risk_tags[0][1]) if risk_tags else 1
    execu = report.get("execution", []) or []
    return {
        "endpoints": asf.get("endpoint_count", 0),
        "modules": asf.get("security_module_count", 0),
        "integrations": asf.get("integration_count", 0),
        "env_refs": asf.get("env_reference_count", 0),
        "total": s.get("total_findings", 0),
        "verified": s.get("verified", 0),
        "review": s.get("needs_manual_review", 0),
        "false_positive": s.get("false_positive", 0),
        "gate_result": gate.get("result", "N/A"),
        "gate_policy": gate.get("policy", "watchtower-gate-v1"),
        "risk_tags": [(k, v, round(v * 100 / top)) for k, v in risk_tags],
        "scanners_run": [e["tool"] for e in execu if e.get("status") == "success"],
        "scanners_skipped": [e["tool"] for e in execu if e.get("status") == "skipped"],
        "dashboard_href": "dashboard.html",
    }


def render_landing(report, dashboard_href="dashboard.html"):
    """Render the landing page HTML for a canonical report dict."""
    env = T.make_env()
    ctx = _context(report)
    ctx["dashboard_href"] = dashboard_href
    tmpl = env.from_string(_TEMPLATE)
    return tmpl.render(pipeline=PIPELINE, capabilities=CAPABILITIES,
                       checks_active=CHECKS_ACTIVE, scanners_optional=SCANNERS_OPTIONAL,
                       arch=ARCH_NODES, snapshot_note=SNAPSHOT_NOTE,
                       head=T.page_head("WATCHTOWER — Security Assessment Platform", PAGE_CSS),
                       **ctx)


def write_landing(path, report, dashboard_href="dashboard.html"):
    with open(path, "w", encoding="utf-8") as h:
        h.write(render_landing(report, dashboard_href))
    return path


_TEMPLATE = r"""<!doctype html>
<html lang="en"><head>{{ head|safe }}</head><body>
<header class="topbar"><div class="wrap">
  <div class="brand">{{ LOGO_SVG|safe }} WATCHTOWER</div>
  <nav class="topnav">
    <a href="#pipeline">Pipeline</a><a href="#capabilities">Capabilities</a>
    <a href="#architecture">Architecture</a><a href="#snapshot">Snapshot</a>
    <a href="#evidence">Evidence</a>
  </nav>
  <div class="spacer"></div>
  <a class="btn btn-primary btn-sm" href="{{ dashboard_href }}">Launch Dashboard {{ icon('arrow-right',15)|safe }}</a>
</div></header>

<section class="hero"><div class="wrap">
  <span class="eyebrow">{{ icon('shield',14)|safe }} EVIDENCE-DRIVEN SECURITY ASSESSMENT</span>
  <h1>WATCHTOWER</h1>
  <p class="tag">Automated Security Assessment &amp; Evidence Verification</p>
  <p class="desc">An evidence-driven security assessment platform that discovers attack
  surfaces, correlates security findings, verifies suspected weaknesses, and produces
  reproducible security decisions.</p>
  <div class="cta-row">
    <a class="btn btn-primary" href="{{ dashboard_href }}">Launch Dashboard {{ icon('arrow-right')|safe }}</a>
    <a class="btn btn-secondary" href="#architecture">{{ icon('layers')|safe }} View Architecture</a>
  </div>
  <div class="flow">
    {% for name, ic, d in pipeline %}
    <span class="node" title="{{ d }}">{{ icon(ic,14)|safe }} {{ name }}</span>
    {% if not loop.last %}<span class="sep">{{ icon('arrow-right',13)|safe }}</span>{% endif %}
    {% endfor %}
  </div>
</div></section>

<section id="pipeline"><div class="wrap">
  <div class="sec-head">
    <div class="caps">Assessment pipeline</div>
    <h2>Eight stages, every result traceable</h2>
    <p>Each stage records what it did — including what it skipped — so a decision can be
    reproduced and audited rather than trusted on faith.</p>
  </div>
  {% for name, ic, desc in pipeline %}
  <div class="step">
    <div class="n">{{ "%02d"|format(loop.index) }}</div>
    <div><h3>{{ icon(ic,15)|safe }} {{ name }}</h3><p class="note">{{ desc }}</p></div>
  </div>
  {% endfor %}
</div></section>
<section id="capabilities" style="background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border)"><div class="wrap">
  <div class="sec-head">
    <div class="caps">Capabilities</div>
    <h2>What WATCHTOWER actually does</h2>
    <p>Only implemented checks are described. Several external scanners are integrated but
    were not installed for the current assessment — they are shown as coverage limitations,
    not completed work.</p>
  </div>
  <div class="cols-4">
    {% for title, ic, desc in capabilities %}
    <div class="card"><div class="ic">{{ icon(ic,20)|safe }}</div>
      <h3>{{ title }}</h3><p>{{ desc }}</p></div>
    {% endfor %}
  </div>
  <div class="cols-2" style="margin-top:16px">
    <div class="card">
      <div class="caps" style="color:var(--pass)">{{ icon('check',13)|safe }} Executed in this assessment</div>
      <div class="taglist" style="margin-top:12px">
        {% for c in checks_active %}<span class="chip" style="--c:var(--pass)">{{ c }}</span>{% endfor %}
      </div>
    </div>
    <div class="card">
      <div class="caps" style="color:var(--muted)">{{ icon('info',13)|safe }} Integrated but skipped (not installed)</div>
      <div class="taglist" style="margin-top:12px">
        {% for c in scanners_optional %}<span class="chip hatch" style="--c:var(--muted)">{{ c }} · skipped</span>{% endfor %}
      </div>
      <p class="note" style="margin-top:12px">Skipped scanners reduce coverage and contribute
      to the current WARN gate decision. WATCHTOWER never reports a skipped scanner as complete.</p>
    </div>
  </div>
</div></section>

<section id="architecture"><div class="wrap">
  <div class="sec-head">
    <div class="caps">Architecture</div>
    <h2>Target in, reproducible decision out</h2>
    <p>A single directional flow from the target application to a structured security-gate
    decision. Artifacts are emitted at the end; the gate is WATCHTOWER's own policy — not CVSS.</p>
  </div>
  <div class="arch">
    <div class="arch-flow">
      {% for name, ic, desc in arch %}
      <div class="arch-node {% if name == 'SECURITY GATE' %}gate{% endif %}">
        {{ icon(ic,20)|safe }}
        <div><div class="mono" style="font-size:12px;letter-spacing:0.06em">{{ name }}</div>
        <div class="note">{{ desc }}</div></div>
      </div>
      {% if not loop.last %}<div class="arch-conn"></div>{% endif %}
      {% endfor %}
    </div>
    <div class="arch-side">
      <div class="panel"><div class="panel-h">{{ icon('doc',16)|safe }}<span class="caps">Report artifacts</span></div>
        <div class="panel-b">
          <div class="kv"><span class="k">Machine-readable</span><span class="v">report.json</span></div>
          <div class="kv"><span class="k">Human dashboard</span><span class="v">report.html</span></div>
          <div class="kv"><span class="k">Tooling interchange</span><span class="v">report.sarif</span></div>
        </div></div>
      <div class="panel"><div class="panel-h">{{ icon('history',16)|safe }}<span class="caps">Continuous (Phase 6)</span></div>
        <div class="panel-b">
          <div class="kv"><span class="k">Baseline</span><span class="v">baseline.json</span></div>
          <div class="kv"><span class="k">Regression</span><span class="v">diff</span></div>
          <div class="kv"><span class="k">Decision</span><span class="v">gate</span></div>
        </div></div>
      <div class="panel" style="border-color:var(--warn)"><div class="panel-b" style="text-align:center">
        <div class="caps" style="color:var(--warn)">WATCHTOWER GATE</div>
        <div class="mono" style="font-size:16px;margin-top:6px">watchtower-gate-v1</div>
        <p class="note" style="margin-top:6px">Structured PASS / WARN / FAIL. Not a CVSS gate.</p>
      </div></div>
    </div>
  </div>
</div></section>
<section id="snapshot" style="background:var(--surface);border-top:1px solid var(--border);border-bottom:1px solid var(--border)"><div class="wrap">
  <div class="sec-head">
    <div class="caps">Real assessment snapshot</div>
    <h2>Current local World Monitor assessment</h2>
  </div>
  <div class="snap">
    <div class="tile"><span class="accent-bar" style="--c:var(--accent)"></span>
      <div class="caps">Endpoints</div><div class="num">{{ endpoints }}</div>
      <div class="note">attack surface</div></div>
    <div class="tile"><span class="accent-bar" style="--c:var(--blue)"></span>
      <div class="caps">Findings</div><div class="num">{{ total }}</div>
      <div class="note">normalized</div></div>
    <div class="tile"><span class="accent-bar" style="--c:var(--pass)"></span>
      <div class="caps">Verified</div><div class="num" style="color:var(--pass)">{{ verified }}</div>
      <div class="note">confirmed</div></div>
    <div class="tile"><span class="accent-bar" style="--c:var(--warn)"></span>
      <div class="caps">Manual review</div><div class="num" style="color:var(--warn)">{{ review }}</div>
      <div class="note">unresolved</div></div>
    <div class="tile"><span class="accent-bar" style="--c:var(--muted)"></span>
      <div class="caps">False positive</div><div class="num" style="color:var(--muted)">{{ false_positive }}</div>
      <div class="note">refuted</div></div>
    <div class="tile"><span class="accent-bar" style="--c:var(--warn)"></span>
      <div class="caps">Security gate</div><div class="num" style="color:var(--warn)">{{ gate_result }}</div>
      <div class="note mono">{{ gate_policy }}</div></div>
  </div>
  <p class="note" style="margin-top:18px;max-width:720px">{{ icon('info',13)|safe }} {{ snapshot_note }}</p>
</div></section>

<section id="evidence"><div class="wrap">
  <div class="sec-head">
    <div class="caps">Evidence &amp; lifecycle</div>
    <h2>From scanner signal to a defensible decision</h2>
    <p>Every finding moves through an explicit lifecycle. WATCHTOWER does not claim zero
    false positives or total verification — it states exactly what was confirmed, what was
    refuted, and what still needs a human.</p>
  </div>
  <div class="flow" style="margin-top:0">
    <span class="node">{{ icon('flask',14)|safe }} Scanner finding</span>
    <span class="sep">{{ icon('arrow-right',13)|safe }}</span>
    <span class="node">{{ icon('hub',14)|safe }} Correlation</span>
    <span class="sep">{{ icon('arrow-right',13)|safe }}</span>
    <span class="node">{{ icon('check',14)|safe }} Verification</span>
    <span class="sep">{{ icon('arrow-right',13)|safe }}</span>
    <span class="node">{{ icon('fingerprint',14)|safe }} Evidence</span>
    <span class="sep">{{ icon('arrow-right',13)|safe }}</span>
    <span class="node">{{ icon('gate',14)|safe }} Lifecycle decision</span>
  </div>
  <div class="cols-4" style="margin-top:22px">
    <div class="callout" style="--c:var(--accent)"><div class="caps" style="color:var(--accent)">Suspected</div>
      <p class="note" style="margin-top:6px">Reported by a scanner, not yet verified.</p></div>
    <div class="callout" style="--c:var(--violet)"><div class="caps" style="color:var(--violet)">Correlated</div>
      <p class="note" style="margin-top:6px">Corroborated across more than one tool.</p></div>
    <div class="callout" style="--c:var(--pass)"><div class="caps" style="color:var(--pass)">Verified</div>
      <p class="note" style="margin-top:6px">Confirmed by an active probe.</p></div>
    <div class="callout" style="--c:var(--warn)"><div class="caps" style="color:var(--warn)">Needs manual review</div>
      <p class="note" style="margin-top:6px">Inconclusive — a human decision is required.</p></div>
  </div>
  <div class="callout" style="--c:var(--muted);margin-top:12px"><div class="caps" style="color:var(--muted)">False positive</div>
    <p class="note" style="margin-top:6px">Refuted by evidence and recorded as such — not hidden.</p></div>
</div></section>

<section class="final"><div class="wrap">
  <h2>Know what was discovered.<br>Know what was verified.<br>Know what still needs review.</h2>
  <a class="btn btn-primary" href="{{ dashboard_href }}">Open WATCHTOWER Dashboard {{ icon('arrow-right')|safe }}</a>
</div></section>

<footer><div class="wrap" style="display:flex;gap:14px;flex-wrap:wrap;align-items:center">
  <div class="brand" style="font-size:12px">{{ LOGO_SVG|safe }} WATCHTOWER</div>
  <span class="spacer"></span>
  <span class="mono">watchtower-gate-v1</span><span>·</span>
  <span>Local assessment · not a CVSS gate · evidence over assertion</span>
</div></footer>
</body></html>
"""
