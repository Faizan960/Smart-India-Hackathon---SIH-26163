# WATCHTOWER

**Automated Security Assessment & Threat Verification Platform for World Monitor**
Smart India Hackathon 2026 · Problem statement **SIH26163**

WATCHTOWER is a **security-assessment platform** that runs multiple analysers over a target
application, normalises their output into one schema, **correlates** signals across tools,
and — crucially — **verifies** the high-value ones with controlled, evidence-producing
probes. Its whole reason to exist is the gap between *"a scanner flagged this"* and
*"this actually holds when exercised."*

> **Status:** documentation & design stage. The prototype is specified but **not yet
> built**. **Scan results will be documented after the first end-to-end assessment.** This
> repository currently contains the architecture, methodology, and scope — no findings are
> claimed.

## What it assesses

The **target** is [World Monitor](https://github.com/koala73/worldmonitor) — a large
real-time global-intelligence application (Vite SPA + Vercel Edge Functions + a proto-first
RPC gateway + Convex backend + an MCP server + a Tauri desktop app). WATCHTOWER is a
**separate** tool that points at World Monitor; it does **not** modify it and is **not**
part of it. See [docs/11-world-monitor-attack-surface.md](docs/11-world-monitor-attack-surface.md)
for the surface map (every item there is a *component to assess* or an *observed control* —
never a claimed vulnerability).

## The pipeline

```
DISCOVER → SCAN → NORMALIZE → CORRELATE → VERIFY → SCORE → REPORT
```

- **SCAN** wraps Semgrep, Gitleaks, OSV-Scanner, npm audit, OWASP ZAP baseline, and Nuclei.
- **VERIFY** runs five custom World Monitor probes: security-headers/CSP, CORS,
  rate-limit, authentication/programmatic-access, and an **SSRF check that uses a local
  canary server we control** — never cloud-metadata or third-party hosts.
- **SCORE** applies the **WATCHTOWER Risk Score** — a transparent, project-specific
  *prioritisation* number that is **explicitly not CVSS**.

Findings move through an honest lifecycle — **Suspected → Correlated → Verified** (plus
**False Positive** and **Needs Manual Review**). Correlation raises confidence; only a
controlled probe grants `verified`.

## Intended usage (prototype)

```bash
python watchtower.py --repo ../worldmonitor --target http://localhost:3000
```

One command produces an **HTML + JSON + SARIF** report backed by a per-run **evidence
store** (raw tool output + probe request/response artefacts). Any collector that is not
installed is recorded as skipped, not failed. Standing up the target is the user's job; per
World Monitor's own `SELF_HOSTING.md`, `npm install && npm run dev` serves it on
`http://localhost:3000`.

## Design principles

1. **Evidence over assumptions** — every finding traces to real output or a probe artefact.
2. **Verification over scanner output** — proven beats suspected.
3. **Correlation over isolated findings** — independent sources raise confidence.
4. **Local-first, controlled, non-destructive** — bounded probes, loopback canary, no repo
   or target modification, no fuzzing, no DoS.
5. **Reproducible & transparent** — deterministic ids and a recomputable score.
6. **No invented results, no automated exploitation.**

## Documentation

| # | Document |
|---|----------|
| 01 | [Problem statement](docs/01-problem-statement.md) |
| 02 | [Proposed solution](docs/02-proposed-solution.md) |
| 03 | [System architecture](docs/03-system-architecture.md) |
| 04 | [Technical approach](docs/04-technical-approach.md) |
| 05 | [Tech stack](docs/05-tech-stack.md) |
| 06 | [Requirements](docs/06-requirements.md) |
| 07 | [Security-assessment methodology](docs/07-security-assessment-methodology.md) |
| 08 | [Finding schema](docs/08-finding-schema.md) |
| 09 | [Risk scoring](docs/09-risk-scoring.md) |
| 10 | [Verification model](docs/10-verification-model.md) |
| 11 | [World Monitor attack surface](docs/11-world-monitor-attack-surface.md) |
| 12 | [Prototype scope](docs/12-prototype-scope.md) |
| 13 | [Roadmap](docs/13-roadmap.md) |

## Scope & honesty

WATCHTOWER does **not** claim to find every vulnerability, to prove World Monitor secure,
or to replace manual review. It produces a **repeatable, evidence-backed assessment
snapshot** and labels plainly what it could and could not verify. It never runs destructive
tests, never targets cloud-metadata or third-party infrastructure, and never modifies the
target.

## Licensing note

World Monitor is **AGPL-3.0-only** and is used here strictly as an **unmodified assessment
target**. WATCHTOWER keeps its own implementation files out of the World Monitor tree.

