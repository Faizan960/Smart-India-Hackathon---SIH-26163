# 13 — Roadmap

WATCHTOWER is planned in three honest tiers. Only the **Prototype** tier is being built
now; everything else is a candidate direction, not a commitment or a claim.

## 13.1 Prototype (now)

The one-day end-to-end pipeline defined in [12-prototype-scope.md](12-prototype-scope.md):

- CLI orchestrator (`watchtower.py`).
- Collectors: Semgrep, Gitleaks, OSV-Scanner, npm audit, ZAP baseline, Nuclei.
- Five custom World Monitor checks (headers/CSP, CORS, rate-limit, auth, SSRF-canary).
- Normalizer → correlation → verification → scoring.
- HTML + JSON + SARIF output with an evidence store.
- Read-only against a local target; no modification of World Monitor.

**Exit state:** a reproducible, evidence-backed assessment snapshot from one command.

## 13.2 Phase 2 (near-term, after the prototype works)

Improvements that deepen the *assessment quality* without changing the local-first,
non-destructive nature of the tool:

| Item | Value |
|------|-------|
| More custom probes | Exposed `.env`/config files, source-map exposure, dangerous content-injection paths, MCP-specific behaviour (tool auth, quota), prompt-injection-relevant application paths. |
| Richer correlation | Map static findings to dynamic routes automatically via a route/asset graph derived from `api/` + `server/`. |
| Verification coverage | More controlled probes; per-probe evidence templates. |
| Config assessment | First-class checks over `vercel.json` headers/CORS, CSP sync across the three CSP sources, and `tauri.conf.json` capabilities. |
| Baseline & diff | Compare a run against a previous run to show new/fixed/regressed findings. |
| Report polish | Executive summary, per-asset rollups, remediation guidance. |
| Suppressions | A reviewed allowlist for accepted/by-design findings, with rationale. |

## 13.3 Future (aspirational, not committed)

Larger directions that would turn the assessment tool into a platform. Each is listed
with its trade-off so none reads as a promise.

| Capability | What it adds | Trade-off / caveat |
|------------|--------------|--------------------|
| Web dashboard | Browse findings, drill into evidence, compare runs | Introduces a UI + its own attack surface; needs auth. |
| GitHub Actions integration | Assessment on push / PR / schedule | Requires CI secrets handling and runner tooling. |
| Scheduled scans | Periodic posture snapshots | Moves toward monitoring; needs storage + dedup. |
| PostgreSQL | Persist findings across runs | Adds a stateful service to operate and secure. |
| Historical finding tracking | Trend lines, mean-time-to-fix | Depends on stable finding ids + storage. |
| Authenticated testing | Assess behind-login and Pro/entitlement paths | Requires credential handling and strict scoping. |
| Tauri / Rust deep analysis | IPC/capability/sidecar-token modelling of the desktop app | Needs Rust-aware tooling beyond Semgrep. |
| Local LLM-assisted triage | Summarise/cluster findings, draft remediation | **Triage aid only** — may never promote to `verified`; local (Ollama) to keep data on-box. |
| Multi-project support | Assess targets other than World Monitor | Requires generalising the custom probes. |

## 13.4 Principles That Do Not Change Across Tiers

No matter how far the roadmap goes, these hold (see
[README](../README.md) and the design principles):

1. Evidence over assumptions.
2. Verification over scanner output.
3. Correlation over isolated findings.
4. Local-first, controlled, non-destructive testing.
5. Reproducibility and transparent scoring.
6. No invented results; no automated exploitation.

## 13.5 Non-Goals (permanent)

WATCHTOWER will not become an antivirus, firewall, WAF, EDR, real-time protection agent,
or automated exploitation framework. It is and remains a **security-assessment platform**.

