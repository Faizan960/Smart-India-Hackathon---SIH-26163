# 04 — Technical Approach

How each pipeline phase is implemented, and the technical decisions behind them. This is
the "how" companion to [03-system-architecture.md](03-system-architecture.md)'s "what".

## 4.1 Language & Orchestration

- **Python 3** for the orchestrator, engines, and probes. Rationale: the security tooling
  ecosystem (Semgrep, the SARIF libraries, HTTP clients) is Python-friendly, and the
  standard library covers everything the prototype needs (`subprocess`, `argparse`,
  `http.server`, `json`, `hashlib`, `urllib`/`httpx`).
- **Subprocess orchestration** for external collectors. WATCHTOWER does not re-implement
  Semgrep, ZAP, etc.; it invokes them, captures their machine-readable output, and
  normalises it. This keeps WATCHTOWER a *thin, honest* layer over trusted tools.
- **JSON everywhere internally.** Every collector is asked for JSON output; the finding
  schema is JSON-serialisable; the evidence store is JSON + raw files.
- **Jinja2** for the HTML report (the one non-stdlib rendering dependency).

## 4.2 DISCOVER — Building the Asset List

Two independent sources, merged into one asset inventory:

- **Static (repo) discovery.** Walk the `--repo` tree read-only. For World Monitor
  specifically, this means enumerating the edge route groups under
  `api/<domain>/v1/[rpc].ts` (the `[rpc]` segment is a literal directory name, so
  enumeration is a path walk, not a glob char-class), the `server/worldmonitor/<domain>/`
  handlers, the shared helpers under `api/_*.js`, and config files (`vercel.json`,
  `tauri.conf.json`, `.env.example`). Each becomes a static asset with a file path.
- **Dynamic (target) discovery.** If `--target` is reachable, issue a small, bounded set
  of requests (and let the ZAP baseline spider passively) to record live endpoints and
  their response headers. Each becomes a dynamic asset with an endpoint URL.

The asset list is what later lets correlation say "this Semgrep hit and this live route are
the same thing." Assets carry an `asset.kind` (`api_endpoint`, `auth`, `mcp`, `config`,
`dependency`, `static_ui`, `desktop`) used by [scoring](09-risk-scoring.md).

## 4.3 SCAN — The Collector Adapter Pattern

Every collector implements the same small interface:

```python
class Collector:
    name: str
    def is_available(self) -> bool: ...      # tool on PATH? target up?
    def run(self, ctx) -> RawResult: ...      # subprocess → raw output file
```

- **Availability first.** `is_available()` checks the binary is installed (and, for dynamic
  tools, that the target answers). A missing tool is **recorded as skipped** in
  `manifest.json`, never silently dropped and never a hard failure. This directly satisfies
  success criterion #1 in [12-prototype-scope.md](12-prototype-scope.md).
- **Version capture.** Each adapter records the tool's version string in the manifest so a
  run is reproducible and comparable.
- **Raw output preserved.** The verbatim tool output lands in `raw/<tool>.json` before any
  parsing, so the normaliser can be re-run without re-scanning.

Prototype collectors: `semgrep`, `gitleaks` (static); `osv-scanner`, `npm audit`
(dependency); `zap` baseline, `nuclei` (dynamic).

## 4.4 NORMALIZE — One Schema To Rule Them All

Each tool has a dedicated mapper that converts its native output into the
[common finding schema](08-finding-schema.md). The mapper's jobs:

- **Severity mapping.** Translate each tool's severity vocabulary (Semgrep
  `ERROR/WARNING/INFO`, ZAP risk codes, OSV/CVSS bands) into the schema's
  `critical|high|medium|low|info` — recording the tool's raw severity in
  `evidence.sources[].raw_severity` so nothing is lost.
- **Location mapping.** File+line for static tools; endpoint URL for dynamic tools.
- **Deterministic id.** `id = WM-<year>-<hash(tool + rule + asset + location)>`. Same
  input → same id → runs are comparable and future diffing is possible.
- **Default status.** Everything starts life as `suspected`. A finding **never** enters as
  `verified` (see [08-finding-schema.md](08-finding-schema.md) §8.2).
- **CWE preservation.** Where a tool emits a CWE/CVE/GHSA identifier it is copied into
  `cwe`/`references` and **never** overwritten by the WATCHTOWER Risk Score.

## 4.5 CORRELATE — Grouping Independent Signals

Correlation raises confidence without ever claiming proof. The engine:

1. Computes a **correlation key** per finding from its normalised asset + issue class
   (e.g. `asset=/api/rss-proxy`, `class=ssrf`).
2. Groups findings sharing a key. When **≥2 independent sources** (different tools, or a
   static hit that maps to a discovered live endpoint) fall in the same group, the group is
   promoted to `correlated` and each member records the others' ids in
   `evidence.correlation[]`.
3. Leaves single-source findings as `suspected`.

Correlation is deliberately conservative: it changes *priority and confidence*, not truth.
Only the verification engine can produce `verified`
(see [10-verification-model.md](10-verification-model.md) §10.1).

## 4.6 VERIFY — Controlled Probes

The five probes exercise the *real* behaviour of the running target and write an
artefact for every verdict. All are bounded, scripted, and non-destructive.

- **headers/CSP.** Re-fetch specific routes; compare the runtime `Content-Security-Policy`
  and security headers against the *configured* policy. World Monitor has three CSP sources
  to reconcile — the `vercel.json` header rules, the `index.html` meta CSP, and the desktop
  `tauri.conf.json` CSP — so a mismatch between config and runtime is itself a signal.
- **CORS.** Replay a request with a crafted foreign `Origin` and inspect whether the origin
  is reflected **and** `Access-Control-Allow-Credentials: true` on a sensitive response.
  A wildcard on a deliberately public, unauthenticated, read-only endpoint is recorded as
  **by-design / false positive**, not a weakness — World Monitor uses public wildcard CORS
  by design on cacheable public data.
- **rate-limit.** Issue a *small fixed* burst (not a flood) at a route expected to be
  limited and check for `429` + IETF `RateLimit-*` headers. The burst size is a constant,
  chosen to observe enforcement without approximating a DoS.
- **auth / programmatic access.** Send an **unauthenticated** request (no API key, no
  session) to an API/MCP route and record exactly what returns: `401/403` (control holds),
  a documented public payload (by design), or protected data (a real finding). The evidence
  is the actual response.
- **SSRF canary.** Start a **loopback-bound canary HTTP server** WATCHTOWER owns, then
  drive the target to fetch the canary URL through a request-influenced fetch path. If the
  canary is hit → server-side reachability confirmed; if blocked by allowlist/private-IP
  rejection or never arrives → false positive or `needs_manual_review`. The canary is
  **always** local and owned; the probe **never** targets cloud-metadata addresses or
  third-party hosts.

**Fail-safe rule:** if a probe cannot run safely or its result is ambiguous, the finding
becomes `needs_manual_review` — never a silent pass or fail.

### 4.6.1 Canary Server Design

`http.server`-based, bound to `127.0.0.1` on an ephemeral port, started only for the SSRF
probe and torn down after. It logs every inbound request (path, headers, timestamp) to
`probes/ssrf-canary.log`. A unique per-run nonce in the canary path proves that a hit came
from *this* probe and not stray traffic.

## 4.7 SCORE — Applying the Model

Pure function of three factors — base severity × verification multiplier × asset weight
(full model in [09-risk-scoring.md](09-risk-scoring.md)). The engine writes the three
factors *and* the product into each finding's `score` object, tagged
`watchtower-risk-score-v1`, so the number is always recomputable and explainable. This is a
**prioritisation** score, explicitly **not CVSS**.

## 4.8 REPORT — Three Outputs From One Source

- **JSON** — the full normalised finding set (`findings.json`), the machine-readable
  ground truth.
- **SARIF 2.1.0** — produced via the mapping in
  [08-finding-schema.md](08-finding-schema.md) §8.7; WATCHTOWER-specific fields ride in
  `properties` bags so the file stays valid SARIF for other tools.
- **HTML** — a Jinja2 template that groups findings by status (Verified / Correlated /
  Suspected / Needs Manual Review), ranks by risk score, shows the three score factors, and
  links each finding to its evidence artefact.

All three are derived from the same evidence store, so they can never disagree.

## 4.9 Configuration & CLI

```
python watchtower.py --repo ../worldmonitor --target http://localhost:3000
```

- `--repo <path>` — read-only path to the target checkout.
- `--target <url>` — base URL of the locally running target.
- `--skip-dynamic` — skip target-dependent collectors/probes when nothing is running.
- `--only <phase[,phase...]>` / `--skip <collector[,collector...]>` — run a subset.
- `--out <dir>` — evidence store root (default `./evidence`).

Unknown target or missing tools degrade gracefully: the phase is skipped and the omission
is recorded in `manifest.json`.

## 4.10 Determinism & Safety Properties

- **Reproducible.** Same repo commit + same tool versions + same target → same finding ids
  and same scores.
- **Auditable.** Every finding points at raw output or a probe artefact.
- **Bounded.** No probe issues more than a small fixed number of requests; no fuzzing.
- **Isolated.** The canary is loopback-only; the repo is never written; the target is never
  mutated.

