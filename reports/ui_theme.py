"""Shared visual theme for the WATCHTOWER UI surfaces (landing page + dashboard).

This module is a PRESENTATION layer only. It contains no security logic: no scorer,
no gate evaluator, no diff/verification/lifecycle engine. It exposes design tokens
(DESIGN.md obsidian/cyan palette), typography, base component CSS, inline SVG icons,
and colour maps that both reports/landing.py and reports/dashboard.py render from.

Colour authority: the obsidian/cyan palette from the task spec + DESIGN.md prose
(NOT the Material tokens embedded in the reference mock-ups).
"""

# --- Operational palette (authoritative) -----------------------------------
CANVAS = "#090D12"
SURFACE = "#0D131C"
ELEVATED = "#131B26"
HOVER = "#1A2433"
BORDER = "#1E293B"
BORDER_ACCENT = "#223249"
ACCENT = "#00E5FF"      # cyan primary
BLUE = "#0A84FF"        # secondary
PASS = "#10B981"        # verified / pass
WARN = "#F59E0B"        # warning / manual review
CRITICAL = "#EF4444"    # critical / block ONLY
MUTED = "#64748B"
TEXT = "#E2E8F0"
TEXT_DIM = "#94A3B8"
VIOLET = "#8B5CF6"      # correlated (distinct neutral hue)
ORANGE = "#F97316"      # high severity (kept distinct from amber warn / red block)

# Severity is its own axis: graded scale, red reserved strictly for CRITICAL.
SEVERITY_COLOR = {"critical": CRITICAL, "high": ORANGE, "medium": WARN,
                  "low": BLUE, "info": MUTED}
# Lifecycle status axis.
STATUS_COLOR = {"verified": PASS, "correlated": VIOLET, "suspected": ACCENT,
                "needs_manual_review": WARN, "false_positive": MUTED}
# Verification-result axis.
RESULT_COLOR = {"confirmed": PASS, "refuted": MUTED, "inconclusive": WARN,
                "not_applicable": MUTED}
# Evidence-confidence axis.
CONFIDENCE_COLOR = {"high": PASS, "medium": WARN, "low": MUTED}
# Gate decision.
GATE_COLOR = {"PASS": PASS, "WARN": WARN, "FAIL": CRITICAL}
# Tool execution status.
EXEC_COLOR = {"success": PASS, "skipped": MUTED, "failed": CRITICAL,
              "not_applicable": MUTED}

FONT_LINKS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700'
    '&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">'
)

LABEL_PLACEHOLDER = "NOT AVAILABLE IN ASSESSMENT"

# --- Inline SVG assets (trusted, author-controlled markup) ------------------
# Rendered with |safe in templates. Report-derived text is NEVER routed through
# here; it always flows through Jinja autoescaping.
LOGO_SVG = (
    '<svg class="wt-logo" viewBox="0 0 24 24" fill="none" aria-hidden="true">'
    '<path d="M12 2.2 4 5.4v6.1c0 4.7 3.2 8.3 8 10.3 4.8-2 8-5.6 8-10.3V5.4L12 2.2Z" '
    'stroke="currentColor" stroke-width="1.4" fill="rgba(0,229,255,0.06)"/>'
    '<path d="M12 7.5v5.2M12 15.6v.05" stroke="currentColor" stroke-width="1.6" '
    'stroke-linecap="round"/>'
    '<circle cx="12" cy="11" r="2.1" stroke="currentColor" stroke-width="1.2"/>'
    '</svg>'
)

_ICONS = {
    "radar": '<circle cx="12" cy="12" r="9"/><path d="M12 12 19 7"/><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/>',
    "shield": '<path d="M12 3 5 6v5c0 4 3 7 7 8.5C16 18 19 15 19 11V6l-7-3Z"/>',
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "warn": '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4M12 17v.01"/>',
    "block": '<circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/>',
    "hub": '<circle cx="12" cy="12" r="2.4"/><circle cx="5" cy="6" r="1.8"/><circle cx="19" cy="6" r="1.8"/><circle cx="6" cy="18" r="1.8"/><path d="M10.3 10.6 6.4 7.2M13.7 10.6l3.8-3.4M10.6 13.6 7.3 16.6"/>',
    "fingerprint": '<path d="M6 11a6 6 0 0 1 12 0v2M8 13v-2a4 4 0 0 1 8 0v3M10 15v-4a2 2 0 0 1 4 0v5M12 13v6"/>',
    "layers": '<path d="M12 3 3 8l9 5 9-5-9-5Z"/><path d="M3 13l9 5 9-5"/>',
    "gate": '<path d="M4 21V6l8-3 8 3v15"/><path d="M4 10h16M9 6v15M15 6v15"/>',
    "scale": '<path d="M12 4v16M6 20h12M7 4l-4 7a3 3 0 0 0 6 0L5 4M19 4l-4 7a3 3 0 0 0 6 0l-2-7"/>',
    "list": '<path d="M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    "compass": '<circle cx="12" cy="12" r="9"/><path d="m15.5 8.5-2 5-5 2 2-5 5-2Z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "doc": '<path d="M6 3h8l4 4v14H6V3Z"/><path d="M14 3v4h4M9 13h6M9 17h6"/>',
    "gear": '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>',
    "refresh": '<path d="M4 12a8 8 0 0 1 13.7-5.6L20 8M20 4v4h-4M20 12a8 8 0 0 1-13.7 5.6L4 16M4 20v-4h4"/>',
    "download": '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    "arrow-right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "arrow-down": '<path d="M12 5v14M6 13l6 6 6-6"/>',
    "target": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".6"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
    "flask": '<path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4a2 2 0 0 0 1.8-3l-5-9V3"/>',
    "chip": '<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2"/>',
    "history": '<path d="M4 12a8 8 0 1 0 3-6.2L4 8M4 4v4h4"/><path d="M12 8v4l3 2"/>',
}


def icon(name, size=18, cls="wt-ico"):
    """Return an inline SVG icon (trusted markup; use |safe in templates)."""
    body = _ICONS.get(name, "")
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" '
            f'fill="none" stroke="currentColor" stroke-width="1.6" '
            f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{body}</svg>')


# --- Shared base CSS (design tokens + primitives + components) --------------
THEME_CSS = """
:root{
  --canvas:#090D12; --surface:#0D131C; --elevated:#131B26; --hover:#1A2433;
  --border:#1E293B; --border-accent:#223249; --accent:#00E5FF; --blue:#0A84FF;
  --pass:#10B981; --warn:#F59E0B; --critical:#EF4444; --muted:#64748B;
  --text:#E2E8F0; --text-dim:#94A3B8; --violet:#8B5CF6; --orange:#F97316;
  --ui:'Geist','Segoe UI',system-ui,-apple-system,sans-serif;
  --mono:'JetBrains Mono','SFMono-Regular',ui-monospace,'Consolas',monospace;
  --sp:8px; --r-chip:6px; --r-btn:8px; --r-panel:12px;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--canvas);color:var(--text);font-family:var(--ui);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased;
  font-feature-settings:'ss01';letter-spacing:-0.006em;}
a{color:inherit;text-decoration:none}
::selection{background:rgba(0,229,255,0.22)}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-thumb{background:#263345;border-radius:6px;border:2px solid var(--canvas)}
::-webkit-scrollbar-track{background:transparent}
.mono{font-family:var(--mono);font-variant-ligatures:none}
.caps{font-size:10px;line-height:1.2;letter-spacing:0.09em;text-transform:uppercase;
  font-weight:600;color:var(--text-dim)}
.dim{color:var(--text-dim)} .muted{color:var(--muted)}
.h-xl{font-size:clamp(30px,5vw,40px);line-height:1.08;font-weight:600;letter-spacing:-0.025em}
.h-lg{font-size:23px;line-height:1.25;font-weight:600;letter-spacing:-0.02em}
.h-md{font-size:17px;line-height:1.35;font-weight:600;letter-spacing:-0.01em}
.wt-ico{flex:0 0 auto;vertical-align:middle}
.wt-logo{width:26px;height:26px;color:var(--accent)}
/* panels */
.panel{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-panel);}
.panel-h{display:flex;align-items:center;gap:10px;padding:14px 18px;
  border-bottom:1px solid var(--border);}
.panel-h .caps{color:var(--text-dim)}
.panel-h .wt-ico{color:var(--accent)}
.panel-b{padding:18px}
.elev{background:var(--elevated)}
.grid{display:grid;gap:var(--sp)}
/* chips (chiseled — never full pills) */
.chip{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);
  font-size:11px;font-weight:600;letter-spacing:0.02em;padding:3px 8px;
  border-radius:var(--r-chip);border:1px solid var(--c,#334155);
  color:var(--c,#94A3B8);background:color-mix(in srgb,var(--c,#334155) 12%,transparent);
  white-space:nowrap;text-transform:uppercase}
.chip.solid{background:var(--c);color:var(--canvas)}
.dot{width:7px;height:7px;border-radius:2px;background:var(--c,#334155);flex:0 0 auto}
/* buttons */
.btn{display:inline-flex;align-items:center;gap:8px;font-family:var(--ui);font-size:13px;
  font-weight:600;padding:9px 15px;border-radius:var(--r-btn);border:1px solid transparent;
  cursor:pointer;transition:.15s;letter-spacing:-0.01em;background:transparent;color:var(--text)}
.btn .wt-ico{width:16px;height:16px}
.btn-primary{background:var(--accent);color:#04121a;border-color:var(--accent)}
.btn-primary:hover{box-shadow:0 0 0 3px rgba(0,229,255,0.18)}
.btn-secondary{border-color:var(--border-accent);color:var(--accent)}
.btn-secondary:hover{background:var(--hover);border-color:var(--accent)}
.btn-ghost{color:var(--text-dim);border-color:var(--border)}
.btn-ghost:hover{background:var(--hover);color:var(--text)}
.btn-sm{padding:5px 10px;font-size:12px}
/* stat tiles */
.tiles{display:grid;gap:12px}
.tile{background:var(--elevated);border:1px solid var(--border);border-radius:10px;
  padding:15px 16px;position:relative;overflow:hidden}
.tile .num{font-size:30px;font-weight:600;line-height:1;font-family:var(--mono);
  letter-spacing:-0.02em;margin:8px 0 4px}
.tile .accent-bar{position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--c,var(--border))}
/* tables */
.tbl{width:100%;border-collapse:collapse;font-size:13px}
.tbl th{text-align:left;font-size:10px;letter-spacing:0.08em;text-transform:uppercase;
  font-weight:600;color:var(--muted);padding:9px 12px;border-bottom:1px solid var(--border);
  position:sticky;top:0;background:var(--surface);z-index:1}
.tbl td{padding:11px 12px;border-bottom:1px solid rgba(30,41,59,0.6);vertical-align:middle}
.tbl tbody tr{cursor:pointer;transition:background .12s}
.tbl tbody tr:hover{background:var(--hover)}
.tbl tbody tr.active-row{background:rgba(0,229,255,0.07);box-shadow:inset 3px 0 0 var(--accent)}
.tbl-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
/* bars */
.bar{height:7px;border-radius:4px;background:var(--hover);overflow:hidden}
.bar>span{display:block;height:100%;background:var(--c,var(--accent));border-radius:4px}
.hatch{background-image:repeating-linear-gradient(45deg,rgba(100,116,139,.35) 0 5px,transparent 5px 10px)}
/* misc */
.kv{display:flex;justify-content:space-between;gap:14px;padding:7px 0;
  border-bottom:1px solid rgba(30,41,59,.5);font-size:13px}
.kv:last-child{border-bottom:0}
.kv .k{color:var(--text-dim);font-size:12px}
.kv .v{font-family:var(--mono);font-size:12px;text-align:right;word-break:break-word}
.note{font-size:12px;color:var(--text-dim);line-height:1.55}
.callout{border:1px solid var(--border);border-left:3px solid var(--c,var(--muted));
  border-radius:var(--r-btn);padding:12px 14px;background:var(--elevated);font-size:12.5px}
.empty{border:1px dashed var(--border-accent);border-radius:var(--r-panel);padding:26px;
  text-align:center;color:var(--muted);background:repeating-linear-gradient(135deg,
  rgba(19,27,38,.5) 0 12px,transparent 12px 24px)}
.pre{font-family:var(--mono);font-size:11.5px;line-height:1.55;background:#060a0e;
  border:1px solid var(--border);border-radius:var(--r-btn);padding:12px;overflow:auto;
  white-space:pre-wrap;word-break:break-word;color:#b6c2d1;max-height:340px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}
"""


def make_env():
    """A shared Jinja2 environment with autoescaping ON and trusted UI globals.

    Report-derived strings are autoescaped. Only author-controlled markup
    (icons, the logo) is exposed as |safe-able globals.
    """
    from jinja2 import Environment  # local import: jinja2 is a runtime dependency

    env = Environment(autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.globals.update(
        icon=icon, LOGO_SVG=LOGO_SVG,
        SEVERITY_COLOR=SEVERITY_COLOR, STATUS_COLOR=STATUS_COLOR,
        RESULT_COLOR=RESULT_COLOR, CONFIDENCE_COLOR=CONFIDENCE_COLOR,
        GATE_COLOR=GATE_COLOR, EXEC_COLOR=EXEC_COLOR,
        NA=LABEL_PLACEHOLDER,
    )
    env.filters["labelize"] = lambda s: str(s).replace("_", " ").title() if s else ""
    return env


def page_head(title, page_css=""):
    """Return a complete <head> for a self-contained UI page."""
    return (
        f'<meta charset="utf-8"><meta name="viewport" '
        f'content="width=device-width, initial-scale=1">'
        f'<title>{title}</title>{FONT_LINKS}'
        f'<style>{THEME_CSS}{page_css}</style>'
    )
