# 06 — Requirements

What must be present to run the WATCHTOWER **prototype** end-to-end. Read alongside
[12-prototype-scope.md](12-prototype-scope.md) (what the prototype does) and
[05-tech-stack.md](05-tech-stack.md) (why these tools).

Requirements are split into **host** (the machine running WATCHTOWER), **collectors** (the
external security tools), **Python dependencies**, and **target** (the World Monitor
instance being assessed). Every collector is **optional at runtime**: if it is not
installed, WATCHTOWER records it as skipped and continues (see
[04-technical-approach.md](04-technical-approach.md) §4.3).

## 6.1 Host

| Requirement | Detail |
|-------------|--------|
| OS | Linux, macOS, or Windows. Development reference environment is Windows 11 + Node 24. |
| Python | 3.10+ (uses `argparse`, `subprocess`, `http.server`, `hashlib`, `json` from stdlib). |
| Disk | Space for a per-run evidence store (raw tool output can be tens of MB). |
| Network | Loopback access to the target and outbound access only for tool template/rule updates. |

## 6.2 External Security Tools (Collectors)

All six are invoked as subprocesses. WATCHTOWER never bundles them; it detects and calls
whatever is on `PATH`.

| Tool | Purpose | Typical install |
|------|---------|-----------------|
| **Semgrep** | Static analysis over the repo | `pip install semgrep` |
| **Gitleaks** | Secret scanning of the working tree | binary release, `brew install gitleaks`, or `scoop install gitleaks` |
| **OSV-Scanner** | Lockfile vulnerability scan | `go install github.com/google/osv-scanner/cmd/osv-scanner@latest` or a release binary |
| **npm audit** | Dependency audit of `package-lock.json` | ships with Node.js / npm (already needed for the target) |
| **OWASP ZAP** | Passive baseline dynamic scan | ZAP desktop/CLI, or the `zaproxy/zap-stable` Docker image running `zap-baseline.py` |
| **Nuclei** | Template-based dynamic scan | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` or a release binary |

Notes:
- **npm audit** and the target share the Node.js toolchain — installing Node 24 for the
  target covers `npm audit` for free.
- **ZAP** and **Nuclei** only run when `--target` is reachable; with `--skip-dynamic` they
  are not required at all.
- WATCHTOWER records each tool's **version** in the run manifest for reproducibility.

## 6.3 Python Dependencies

The prototype leans on the standard library and keeps third-party dependencies minimal:

| Package | Use | Required? |
|---------|-----|-----------|
| `jinja2` | HTML report templating | yes |
| `httpx` *(or stdlib `urllib`)* | Probe HTTP client with timeouts | recommended |

Pinned versions live in `requirements.txt` when the prototype is built. Everything else
(subprocess control, JSON, hashing, the canary server via `http.server`, SARIF assembly as
plain dicts) uses the standard library.

## 6.4 Target — World Monitor Instance

The dynamic phases and custom probes need a **locally running** World Monitor.

| Requirement | Detail |
|-------------|--------|
| Repo checkout | A local clone at `--repo` (e.g. `../worldmonitor`). WATCHTOWER reads it; it never writes to it. |
| Node.js | Node 24 (the target's `.nvmrc`). |
| Running target | `--target http://localhost:3000`. |

Per the target's own `SELF_HOSTING.md`, the simplest local bring-up needs **no environment
variables**:

```
npm install
npm run dev
```

That serves the app on `http://localhost:3000`. A Docker Compose path also exists (which
adds a Redis/Redis-REST and AIS-relay service and needs `REDIS_PASSWORD` + `REDIS_TOKEN`),
but the prototype only requires the app to answer on port 3000. Standing up the target is
the **user's** responsibility — WATCHTOWER does not clone, install, or start it.

## 6.5 Functional Requirements

| # | Requirement |
|---|-------------|
| FR-1 | Run the full pipeline from one command with `--repo` and `--target`. |
| FR-2 | Detect installed collectors; run those present; record skipped ones. |
| FR-3 | Normalise every collector's output into the common finding schema. |
| FR-4 | Correlate multi-source findings that map to the same asset/issue. |
| FR-5 | Run the five custom probes, including the local-canary SSRF verification. |
| FR-6 | Assign each finding a WATCHTOWER Risk Score and rank by it. |
| FR-7 | Emit HTML + JSON + SARIF 2.1.0 with a per-run evidence store. |
| FR-8 | Support `--skip-dynamic` / phase-and-collector selection for partial runs. |

## 6.6 Non-Functional Requirements

| # | Requirement |
|---|-------------|
| NFR-1 | **Non-destructive** — no modification of the target repo or running instance. |
| NFR-2 | **Reproducible** — same commit + tool versions + target → same ids and scores. |
| NFR-3 | **Evidence-backed** — every finding traces to raw output or a probe artefact. |
| NFR-4 | **Bounded** — probes issue small fixed request counts; no fuzzing or floods. |
| NFR-5 | **Local-first** — SSRF canary is loopback-only; never cloud-metadata or third-party hosts. |
| NFR-6 | **Graceful degradation** — a missing tool or an unreachable target is recorded, not fatal. |
| NFR-7 | **Transparent scoring** — the three score factors are shown and recomputable. |

## 6.7 What Is *Not* Required

- No database, message queue, or web server (prototype is CLI + files only).
- No cloud credentials, API keys, or World Monitor secrets — the assessment is unauthenticated
  by design in the prototype (authenticated testing is a future item, see
  [13-roadmap.md](13-roadmap.md) §13.3).
- No internet access beyond optional tool rule/template updates.

