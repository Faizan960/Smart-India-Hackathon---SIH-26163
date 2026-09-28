# 12 — Prototype Scope

This document defines **exactly** what the one-day WATCHTOWER prototype builds — no more,
no less. The goal is a working end-to-end pipeline that produces an evidence-backed
report against a locally running World Monitor, not an enterprise platform.

## 12.1 In Scope

### Orchestration
- A **CLI orchestrator** (`watchtower.py`) that runs the full pipeline:
  `DISCOVER → SCAN → NORMALIZE → CORRELATE → VERIFY → SCORE → REPORT`.
- Invocation: `python watchtower.py --repo ../worldmonitor --target http://localhost:3000`.
- Configurable which stages/collectors run (e.g. `--skip-dynamic` when the target is not
  running).

### Static analysis
- **Semgrep** over the target repo.
- **Gitleaks** over the target working tree.

### Dependency analysis
- **OSV-Scanner** over lockfiles.
- **npm audit** over `package-lock.json`.

### Dynamic analysis (against the running target only)
- **OWASP ZAP baseline** (passive) scan.
- **Nuclei** template scan.

### Custom World Monitor checks (5)
1. **Security headers / CSP** — fetch the app and representative API responses; compare
   runtime headers against configured policy.
2. **CORS** — test API endpoints for unsafe wildcard/reflected-origin behaviour,
   distinguishing by-design public wildcards from credentialed exposure.
3. **Rate-limit enforcement** — controlled, bounded burst against selected endpoints;
   detect `429`/limit headers.
4. **Authentication / programmatic access** — request protected API/MCP functionality
   without credentials; record exactly what is accessible.
5. **SSRF verification** — drive the target against a **local canary server** we control;
   confirm or refute server-side request reachability. Never touches cloud metadata or
   third-party hosts.

### Pipeline engines
- **Finding normalizer** — every collector's output → the common schema
  ([08-finding-schema.md](08-finding-schema.md)).
- **Correlation engine** — group findings by asset/rule/location; promote to
  `correlated`.
- **Verification engine** — run the controlled probes; write verdicts + evidence.
- **Risk scoring** — WATCHTOWER Risk Score ([09-risk-scoring.md](09-risk-scoring.md)).

### Outputs
- **HTML report** (human-readable, grouped by status, ranked by score, evidence links).
- **JSON** (the full normalised findings).
- **SARIF 2.1.0** (interoperable static-analysis output).
- **Evidence store** — a run directory holding raw tool output and probe artefacts.

## 12.2 Out Of Scope (prototype)

The following are explicitly **not** built in the prototype:

- Enterprise dashboard / web UI.
- Production continuous monitoring or scheduled scanning.
- Authenticated multi-user platform / RBAC.
- Distributed or parallel scanning across machines.
- Destructive penetration testing or fuzzing storms.
- Cloud-wide or external-infrastructure scanning.
- Automated exploitation / weaponisation of findings.
- Production deployment of WATCHTOWER itself.
- Historical trend storage / databases (findings are per-run).

## 12.3 Prototype Success Criteria

The prototype is "done" when a single command against a locally running World Monitor:

1. Runs all collectors that are available in the environment (gracefully skipping any
   that are not installed, and recording that they were skipped).
2. Produces normalised findings in the common schema.
3. Correlates multi-source findings.
4. Runs the five custom checks, including at least the local-canary SSRF verification.
5. Assigns WATCHTOWER Risk Scores and ranks findings.
6. Emits HTML + JSON + SARIF with an evidence store.
7. Makes **no modifications** to the World Monitor repository or running instance.

## 12.4 Explicit Non-Claims

The prototype does **not** claim to find every vulnerability, to prove World Monitor
secure, or to replace manual security review. It produces a **repeatable, evidence-backed
assessment snapshot** and clearly labels what it could and could not verify.

See [13-roadmap.md](13-roadmap.md) for what comes after the prototype and
[06-requirements.md](06-requirements.md) for what must be installed to run it.

