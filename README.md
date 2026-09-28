# WATCHTOWER

**Automated Security Assessment & Threat Verification Platform for World Monitor**
Smart India Hackathon 2026 · Problem statement **SIH26163**

WATCHTOWER is a **security-assessment platform** that runs multiple analysers over a target
application, normalises their output into one schema, **correlates** signals across tools,
and — crucially — **verifies** the high-value ones with controlled, evidence-producing
probes. Its whole reason to exist is the gap between *"a scanner flagged this"* and
*"this actually holds when exercised."*

> **Status:** **Phase 2 (real multi-tool integration) is implemented.** The pipeline now
> runs 11 stages (CLI → Semgrep → Gitleaks → OSV-Scanner → npm audit → security-headers →
> OWASP ZAP baseline → Nuclei → normalize → WATCHTOWER Risk Score → JSON + HTML report),
> with deterministic duplicate grouping and a per-tool execution record. Every stage records
> an honest status, so a missing scanner (`skipped`), a crash/parse error (`failed`), or an
> unreachable target is reported, never disguised as a clean result. **No findings are
> fabricated and no severity is inflated.** The first real run against the World Monitor repo
> produced genuine **npm audit** dependency findings; the tools that were not installed and
> the DAST stages against the (not-running) local target were honestly recorded as
> skipped/failed rather than passed. Correlation and World Monitor-specific verification
> probes remain deferred to Phases 3–4, so nothing is yet marked `verified` by a probe.

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

## Running WATCHTOWER

```bash
pip install -r requirements.txt
python watchtower.py --repo ../worldmonitor --target http://localhost:3000
```

Flags: `--output <dir>` (default `./output`); per-stage skips `--skip-semgrep`,
`--skip-gitleaks`, `--skip-osv`, `--skip-npm-audit`, `--skip-headers`, `--skip-zap`,
`--skip-nuclei`; and per-tool timeouts `--semgrep-timeout`, `--gitleaks-timeout`,
`--osv-timeout`, `--npm-audit-timeout`, `--request-timeout`, `--zap-timeout`,
`--nuclei-timeout`. Each stage is independently executable via its skip flag. Quote any
repository path that contains spaces.

One command runs the pipeline and writes a per-run **evidence store** under
`output/run-<UTC-timestamp>/`: raw tool output (`raw/`), normalized `findings.json`, run
`metadata.json`, and the **JSON + HTML report**. A collector that is not installed is
recorded as **skipped** and an unreachable target as a **failed** stage — the run still
completes and the report reflects exactly what did and did not execute. **No findings are
invented.** Standing up the target is the user's job; per World Monitor's own
`SELF_HOSTING.md`, `npm install && npm run dev` serves it on `http://localhost:3000`.

The external scanners (Semgrep, Gitleaks, OSV-Scanner, npm, Nuclei, and either a native
`zap-baseline.py` or the `ghcr.io/zaproxy/zaproxy` Docker image) are invoked as external
tools; WATCHTOWER **never installs or pulls them for you**. Any scanner that is absent is
recorded as `skipped` with install guidance, so the run always completes honestly. **Real
scan numbers are only reported once they come from an actual run** (see the per-run report),
never asserted in advance.

### Tests

```bash
python -m unittest discover -s tests -v
```

### Implemented vs. deferred

**Implemented (Phase 1):** CLI orchestrator · configuration & validation · Semgrep
collector (safe subprocess, JSON parse) · security-headers/CSP probe (real HTTP) · finding
normalization & deterministic IDs · WATCHTOWER Risk Score · per-run evidence store · JSON
report · HTML report · unit tests.

**Implemented (Phase 2):** Gitleaks collector (with adapter-level secret **redaction** —
secret values never reach a report) · OSV-Scanner collector · npm audit collector · OWASP
ZAP baseline collector (native or Docker, passive only) · Nuclei collector (controlled,
non-destructive template set) · 11-stage orchestrator with independent per-stage skips ·
honest per-tool **execution record** (`success` / `failed` / `skipped`, duration, exit
code, finding count) · deterministic **duplicate grouping** on shared GHSA/CVE identifiers
(not correlation) · expanded HTML/JSON reporting · synthetic-output unit tests for all five
new collectors (75 tests total).

**Not yet (Phases 3–4):** correlation engine · World Monitor-specific CORS / rate-limit /
auth / SSRF-canary verification probes · SARIF output.

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

