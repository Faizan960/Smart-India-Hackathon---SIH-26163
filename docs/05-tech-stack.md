# 05 — Technology Stack

WATCHTOWER's stack is split into two clearly separated tiers. Nothing is listed for
presentation value; each prototype tool maps to a concrete pipeline stage.

## 5.1 Prototype Stack (what the one-day prototype uses)

### Orchestration & core

| Technology | Role in WATCHTOWER | Stage |
|-----------|--------------------|-------|
| **Python 3.11+** | CLI orchestrator, normaliser, correlation, verification, scoring | all |
| **Git** | pin the exact target commit being assessed (reproducibility) | Discover |
| **JSON** | canonical internal + machine-readable output format | Normalize → Report |
| **SARIF 2.1.0** | interoperable static-analysis output (GitHub code scanning, IDEs) | Report |
| **Jinja2** | HTML report templating (if a templated report is used) | Report |

### Scanners (invoked, not reimplemented)

| Tool | Purpose | Consumes | Native output |
|------|---------|----------|---------------|
| **Semgrep** | Static analysis (SAST) of TypeScript/JS/Rust/config | `--repo` | JSON / SARIF |
| **Gitleaks** | Secret detection across the working tree and (optionally) git history | `--repo` | JSON / SARIF |
| **OSV-Scanner** | Dependency vulnerability analysis via the OSV database | lockfiles | JSON |
| **npm audit** | Node dependency advisories from the npm registry | `package-lock.json` | JSON |
| **OWASP ZAP (baseline)** | Passive dynamic analysis of the running target | `--target` | JSON / XML |
| **Nuclei** | Template-based dynamic checks (misconfig, exposure) | `--target` | JSON(L) |

### Custom World Monitor probes (built in-house — Python)

Five controlled, local, non-destructive checks (detailed in
[12-prototype-scope.md](12-prototype-scope.md)):

1. Security headers / CSP
2. CORS policy
3. Rate-limit enforcement (controlled burst)
4. Authentication / programmatic access (unauthenticated access mapping)
5. SSRF verification (via a **local canary server** under our control)

### Supporting Python libraries (prototype)

Kept intentionally small and mainstream:

| Library | Use |
|---------|-----|
| `httpx` or `requests` | HTTP client for custom probes and target interaction |
| `http.server` (stdlib) | the local SSRF canary listener |
| `pydantic` or `dataclasses` | typed finding model / schema validation |
| `jinja2` | HTML report rendering |
| `pyyaml` | reading tool/probe configuration |

> Exact library choices are an implementation detail of the prototype and may be trimmed;
> the pipeline design does not depend on any specific one of them.

## 5.2 Why These Tools Fit This Target

World Monitor is a TypeScript/Rust codebase with a Node dependency tree, a public HTTP
API, and a running web target. The prototype stack maps directly onto that shape:

- **Semgrep** understands TS/JS and can be pointed at Rust and config — matching
  `src/`, `api/`, `server/`, and `src-tauri/`.
- **Gitleaks** targets the large configuration surface (`.env.example` declares 279
  keys) and guards against committed secrets.
- **OSV-Scanner + npm audit** cover the Node dependency tree (`package-lock.json` is
  ~0.9 MB) from two independent databases, which is exactly the kind of independent
  corroboration the correlation engine is designed to exploit.
- **ZAP baseline + Nuclei** exercise the running target for headers, misconfiguration,
  and exposure without destructive testing.
- **Custom probes** cover World-Monitor-specific behaviour that generic tools miss
  (CORS design, rate-limit enforcement, MCP/relay-aware SSRF verification).

## 5.3 Potential Future Stack (NOT built in the prototype)

Listed separately and honestly. None of the following is implemented in the prototype;
they are candidate evolution paths (see [13-roadmap.md](13-roadmap.md)).

| Technology | Potential future role | Status |
|-----------|----------------------|--------|
| **FastAPI** | HTTP API / web service in front of the pipeline | Future |
| **PostgreSQL** | historical finding storage, trend tracking | Future |
| **Docker** | reproducible, self-contained scan environment | Future |
| **GitHub Actions** | CI-triggered assessment on push / schedule | Future |
| **Tauri / Rust analysis** | deeper desktop-runtime (IPC / sidecar) analysis | Future |
| **Ollama / local LLM** | assisted triage & summarisation of findings (local only) | Future |

Any LLM-assisted triage, if added, would be a **triage aid only** — it would never be
allowed to promote a finding to *Verified*. Verification stays evidence-based.

## 5.4 Explicitly Out Of The Stack

- No cloud-hosted SaaS scanning dependency.
- No proprietary/closed scanners in the prototype.
- No automated exploitation frameworks.
- No agent that modifies the target.

See [06-requirements.md](06-requirements.md) for the runtime/software requirements that
follow from these choices.

