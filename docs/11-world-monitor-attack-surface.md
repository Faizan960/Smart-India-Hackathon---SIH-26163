# 11 — World Monitor Attack Surface

## 11.1 The Distinction This Document Exists To Protect

> **Every item in this document is an "attack surface / component to assess" or an
> "existing control observed in the source." NONE of it is a confirmed vulnerability.**
> WATCHTOWER has not been run yet. This is a map of *where to look* and *what protections
> the target already ships*, compiled by reading real files — not a list of weaknesses.

Conflating "this is a place a weakness *could* live" with "this is a weakness" is the exact
failure mode WATCHTOWER is built to avoid (see [10-verification-model.md](10-verification-model.md)).
So this document uses three labels, and only three:

- **Component / attack surface to assess** — a place worth pointing tools and probes at.
- **Existing control (observed)** — a protection literally present in the target's source,
  cited by file (and line where known). Recorded so WATCHTOWER does not "rediscover" a
  defended issue as a finding.
- **Note to assess** — a consistency or design question, explicitly *not* a weakness claim.

Any actual verdict (`verified`, `false_positive`, …) is produced only by a run, per the
[finding schema](08-finding-schema.md) and [verification model](10-verification-model.md).

## 11.2 Provenance

- **Target:** World Monitor, version `2.10.0`, `main` @ commit
  `a213b425a7e86f084ff6a8581f4ab386612651c9` (repo `koala73/worldmonitor`), Node 24,
  AGPL-3.0-only.
- **Method:** read-only inspection of the checked-out source (no clone, no modification).
  File paths below are grounded in that source; line numbers are given where they were read
  directly.
- **The target ships heavy defense-in-depth.** That is the headline of this map: most named
  surfaces already have layered controls, which is why the honest expectation for many
  scanner detections is `false_positive` / by-design on verification.

## 11.3 Attack Surface Inventory

### A. HTTP API gateway & edge RPC surface

- **Component to assess.** ~37 domain route groups at `api/<domain>/v1/[rpc].ts` (aviation,
  market, conflict, maritime, news, … `leads` which has public no-auth RPCs), each a Vercel
  Edge function (`runtime: 'edge'`) dispatching a proto-first "Sebuf" RPC. Central chokepoint
  is `server/gateway.ts` (~2681 lines); generated route factories in
  `src/generated/server/.../service_server.ts`; per-domain aggregators in
  `server/worldmonitor/<domain>/handler.ts`.
- **Existing controls (observed).** The `dispatch()` pipeline in `server/gateway.ts`:
  strips client-supplied trust headers (`x-user-id`, rate-limit-principal, internal-mcp
  marker), fail-closed CORS (never wildcard for credentialed), origin 403, internal-MCP HMAC
  verify with Redis replay-nonce, Clerk resolve, API-key validation (`wm_`/`wme_`/enterprise),
  `apiAccess` entitlement gate, route match + bounded POST→GET compat
  (`POST_TO_GET_MAX_BODY_BYTES=1 MiB`), idempotency, per-account burst+daily rate limiting.
  Request validation is a custom `buf.validate` proto enforcer (`server/request-validator.ts`,
  `DEFAULT_STRING_MAX_BYTES=64 KB`, ReDoS mitigation) — no `zod` in this path. Error mapping
  (`server/error-mapper.ts`) forces 5xx to a generic message so upstream URLs / key fragments
  don't leak.
- **WATCHTOWER assesses.** Unauthenticated reachability of gated RPCs (auth probe), input
  validation edges (Semgrep + bounded probes), error-response leakage, and whether the
  POST→GET compatibility layer changes any access decision.

### B. Authentication, API-key & entitlement path *(asset weight 1.5)*

- **Component to assess.** Multiple credential classes coexist: user keys `wm_<40 hex>`
  (client-generated; only SHA-256 hash + prefix stored — `src/services/api-keys.ts`,
  `convex/apiKeys.ts`); enterprise keys `WORLDMONITOR_VALID_KEYS`; partner-embed `wme_`;
  anonymous session `wms_` (HMAC over `WM_SESSION_SECRET`, `api/_session.js`); Clerk session
  JWTs (`server/auth-session.ts`); short-lived OAuth Redis sessions; desktop `LOCAL_API_TOKEN`.
  Entitlement/Pro logic in `server/_shared/premium-check.ts`, `pro-mcp-gate.ts`,
  `pro-mcp-token.ts`; Convex tables `userApiKeys`, `embedKeys`, `mcpProTokens`, `entitlements`
  (`convex/schema.ts`).
- **Existing controls (observed).** Plaintext keys never stored/received server-side;
  `USER_API_KEY_RE = /^wm_[a-f0-9]{40}$/` rejects malformed keys *before* hashing (prevents
  hash/Redis/Convex amplification — `server/_shared/user-api-key.ts`); constant-time
  comparisons (`timingSafeIncludes`, `timingSafeEqualStrings`); 60s positive + negative
  caches; fail-closed on transient validation failure for premium; own-property guards that
  resist prototype pollution; Clerk verify pins `RS256` + issuer + audience/`azp` with a 5s
  clock tolerance.
- **Note to assess.** `users.country` is explicitly **client-reported** (warning in
  `convex/schema.ts`) and documented as *not* for compliance/geo-gating — a design fact to
  keep in mind, not a weakness.
- **WATCHTOWER assesses.** What protected functionality (if any) is reachable with **no**
  credentials (auth probe records the actual response); key-shape handling; entitlement gates
  are reasoned about statically (prototype is unauthenticated, so Pro paths aren't exercised
  end-to-end).
### C. MCP server & Pro-gated MCP proxy

- **Component to assess.** The MCP server at `api/mcp.ts` → `api/mcp/handler.ts` (~1317
  lines), Streamable HTTP transport, ~75 tools across `api/mcp/registry/`. `PUBLIC_MCP_METHODS`
  (initialize, `tools/list`, `prompts/list`, `resources/list`, …) are reachable pre-auth;
  `tools/call` is gated. Separately, the **Pro-gated MCP proxy** `api/mcp-proxy.ts` (~1047
  lines) takes a **caller-supplied `serverUrl`** and makes outbound JSON-RPC/SSE to it — the
  primary caller-controlled-URL surface.
- **Existing controls (observed).** MCP server: body parsed with a JSON-RPC byte cap, SSE
  replay buffer bounded (128 KB/response, 4 MB total, 500 sessions); `_execute` tools fetch a
  **fixed** `MCP_CANONICAL_API_ORIGIN`, *not* a caller URL (`api/mcp/downstream.ts`) — this is
  why the tool surface is not itself an open SSRF vector. MCP proxy: HTTPS-only
  (`validateServerUrl`), static `BLOCKED_HOSTNAMES`, IP-literal + DoH-resolved A/AAAA rejection
  via `server/_shared/ip-address-classification.ts`, **re-validation before every outbound
  dispatch** (DNS-rebind narrowing), cloud-metadata header stripping (`DENIED_FORWARD_HEADERS`),
  manual redirects capped at 1 hop (307/308 only), SSE endpoint pinning, Pro/enterprise/user-key
  gating, 30/min rate limit. OAuth grant path uses an HMAC-SHA-256 grant token
  (`api/_mcp-grant-hmac.ts`) + one-shot Redis nonce.
- **Note to assess.** MCP CORS is `*` with **no Origin gate** (documented by the target as
  issue #4802); the Edge runtime **cannot socket-pin**, leaving a documented residual DNS-rebind
  window (issue #5061). Both are the target's own acknowledged, tracked items.
- **WATCHTOWER assesses.** Which MCP methods answer unauthenticated (auth probe); the CORS/Origin
  posture; and the mcp-proxy's SSRF controls exercised with a **local canary only** (never
  metadata/third-party).

### D. RSS proxy & Railway relay

- **Component to assess.** `api/rss-proxy.js` (~433 lines) fetches caller-supplied feed URLs;
  the Railway relay `scripts/ais-relay.cjs` (~13,800 lines, `Dockerfile.relay`, port 3004)
  exposes a public `/rss` route and other seed/proxy sources.
- **Existing controls (observed).** Edge proxy: `assertHttpProtocol` (blocks non-http/https),
  ~429-entry domain allowlist (`api/_rss-allowed-domains.js`), and the allowlist **re-checked on
  every redirect hop** (`assertAllowedRedirect`, `MAX_DIRECT_REDIRECTS=3`), caps (5 MB / 20
  items), response CSP `sandbox; default-src 'none'`. Relay: `/rss` blocks `rsshub.app`,
  enforces the shared allowlist, and **re-checks the allowlist on every redirect hop**
  (`redirectHost` check before recursing). `/rss` is intentionally **public** (proxied data is
  public; `RELAY_SHARED_SECRET` guards non-public routes and is for abuse-prevention behind a
  WAF, not data protection); relay refuses to start without a secret unless the operator sets a
  loud dev escape hatch `I_UNDERSTAND_THIS_DISABLES_AUTH`.
- **Note to assess.** Edge→relay trust is a **static shared secret** in a header + Bearer (no
  HMAC/signature) — a design point to assess, not a claimed flaw. The relay `/rss` picks
  protocol by string prefix and relies on the host allowlist rather than an explicit scheme
  assertion.
- **WATCHTOWER assesses.** SSRF via allowlist/redirect handling exercised against the **local
  canary**; whether a foreign `Origin` or redirect can escape the allowlist; relay auth posture
  (static reasoning + observed controls).
### E. Convex backend & service-to-service boundary

- **Component to assess.** `convex/http.ts` (~2461 lines) is the service-to-service HTTP
  boundary: `/api/internal-*` and `/relay/*` routes (validate-api-key, validate-embed-key,
  entitlements, Pro-MCP token issue/validate/revoke, Dodo/Resend/Clerk webhooks, intel-history
  ingest/retract). `convex/schema.ts` (~1949 lines) holds the auth/entitlement/usage tables.
- **Existing controls (observed).** Every internal/relay route is gated by a constant-time
  secret compare (`timingSafeEqualStrings`) against `CONVEX_SERVER_SHARED_SECRET` or role-scoped
  tenant-relay secrets, with explicit cross-secret-confusion rejection; **fail-closed** when a
  secret is unset. Webhook/ingest paths cap field lengths and reject `javascript:`/`data:` URLs
  (`isHttpUrl`). Key hashes are stored, never plaintext.
- **WATCHTOWER assesses.** Largely **out of the unauthenticated prototype's reach** (these
  routes require server secrets); recorded as a component to assess and a candidate for the
  future authenticated-testing tier ([13-roadmap.md](13-roadmap.md) §13.3).

### F. External data ingestion & sanitization (XSS surface)

- **Component to assess.** Three distinct feed-parsing paths: client `DOMParser`
  (`src/services/rss.ts`), a server regex parser + custom entity decoder
  (`server/worldmonitor/news/v1/list-feed-digest.ts`), and `fast-xml-parser` at 6 server/seeder
  sites. Feed items (title/link/description) are cached **raw**, with sanitization deferred to
  render time.
- **Existing controls (observed).** Build-time `scripts/enforce-safe-html.mjs` forbids direct
  `innerHTML`/`insertAdjacentHTML` outside a single allowlisted sink (`src/utils/dom-utils.ts`),
  with an enforced-empty baseline. Escape primitives in `src/utils/sanitize.ts` (`escapeHtml`,
  `validateUrl` blocking `javascript:`/`data:`). The single DOM sink `setTrustedHtml` + a
  DOM-walk `safeHtml` sanitizer. DOMPurify is scoped to markdown/LLM/agent-generated HTML (a
  restricted config in `widget-sanitizer.ts`; the Pro interactive-widget path mounts agent HTML
  in an `iframe sandbox="allow-scripts"` **without** `allow-same-origin`, i.e. opaque origin,
  inner CSP `default-src 'none'`). Render-time escaping in `src/components/NewsPanel.ts`. XML
  parsers don't process DOCTYPE/external entities by default; `text/xml` DOMParser doesn't
  execute scripts.
- **Note to assess.** `src/components/DeductionPanel.ts` uses DOMPurify's **default** config
  (of LLM-markdown output) where other sites use a restricted allowlist — a **consistency
  difference**, not a claimed weakness (defaults are themselves a strong sanitizer).
- **WATCHTOWER assesses.** Whether hostile feed content survives to a rendered DOM sink
  unescaped (reasoned statically + confirmed at render); the agent-widget iframe boundary
  (which intentionally executes agent-authored inline script in an opaque origin).

### G. CORS posture

- **Component to assess.** `api/_cors.js` — `APP_ORIGIN_PATTERN` allowlist (worldmonitor.app +
  Vercel preview + tauri/localhost when not production); `getCorsHeaders` echoes an allowed
  origin with `Access-Control-Allow-Credentials: true` + `Vary: Origin`; `getPublicCorsHeaders`
  returns `Access-Control-Allow-Origin: *` for cacheable public data.
- **Existing control (observed).** Credentialed CORS is **fail-closed to the allowlist**;
  wildcard is used only on public, read-only data.
- **WATCHTOWER assesses.** The CORS probe must **distinguish by-design public wildcard from
  credentialed reflected-origin exposure** — a wildcard on a public endpoint is recorded
  by-design/`false_positive`, not a weakness (see [10](10-verification-model.md) §10.3.2).
### H. Rate limiting

- **Component to assess.** `api/_rate-limit.js` (Upstash sliding window, default 600/60 s,
  429 with IETF `RateLimit-*` + legacy `X-RateLimit-*` headers, edge-proof 403 for an unproven
  client IP) plus per-account burst + daily limits inside `server/gateway.ts`.
- **WATCHTOWER assesses.** The rate-limit probe issues a **small fixed** burst at a route
  expected to be limited and checks for `429`/limit headers — enforcement observed → control
  holds. The burst is intentionally tiny so the probe is non-destructive (never a DoS).

### I. Security headers / CSP (three sources)

- **Component to assess.** Runtime headers on the app and API responses, against **three**
  configured CSP sources that must stay in sync: `vercel.json` header rules, the `index.html`
  meta CSP, and the desktop `src-tauri/tauri.conf.json` CSP.
- **Existing controls (observed).** `vercel.json`: `script-src 'self'`, `object-src 'none'`,
  `form-action 'none'`, `frame-src 'none'`, HSTS (`max-age=63072000; includeSubDomains;
  preload`), `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `X-Frame-Options:
  SAMEORIGIN`, a locked-down `Permissions-Policy`, and COOP/COEP in **Report-Only** mode.
- **WATCHTOWER assesses.** The headers/CSP probe re-fetches specific routes, compares runtime
  vs configured policy, and annotates directives that are *intentionally* permissive (e.g. an
  embeddable widget route) rather than scoring them as weaknesses.

### J. SSRF surfaces (consolidated)

- **Component to assess.** Caller-influenced or webhook-driven fetch paths: `api/mcp-proxy.ts`
  (caller `serverUrl`), `api/rss-proxy.js` + relay (allowlisted feeds), notification/chokepoint
  webhook delivery (user-supplied webhook URLs). Fixed-host reverse proxies
  (`api/docs-mcp.ts`, the middleware docs-locale proxy, `api/youtube/*`, `api/skills/*`,
  `api/polymarket.js`, …) are param-influenced but resolve to **fixed** upstream hosts.
- **Existing controls (observed).** A shared classifier `server/_shared/ip-address-classification.ts`
  blocks the full private/reserved IPv4 and IPv6 ranges (incl. v4-mapped, NAT64, 6to4). Node
  delivery paths (`scripts/lib/notification-webhook-ssrf.cjs`,
  `server/worldmonitor/shipping/v2/deliver-webhook.ts`) **DNS-pin** the vetted address
  (rebind defense) and re-check post-resolution; registration validation DoH-resolves and
  re-checks all addresses. The Edge mcp-proxy documents that it **cannot** socket-pin (issue
  #5061), which the Node paths **can** and do.
- **WATCHTOWER assesses.** SSRF verification uses a **loopback-bound canary server WATCHTOWER
  owns** and confirms/refutes server-side reachability. It **never** probes cloud-metadata
  endpoints or unrelated third-party hosts (see [10](10-verification-model.md) §10.3.1).

### K. Secrets management

- **Component to assess.** `.env.example` (~279 declared keys across many providers, all
  optional for a basic local run); the working tree (for accidentally committed secrets); the
  desktop sidecar's runtime secret store.
- **Existing controls (observed).** Repo-side secret lint (`scripts/check-vite-env-secrets.mjs`
  flags non-`VITE_` secrets that would be bundled client-side; `scripts/check-local-secret-dumps.mjs`
  is a pre-push dump scanner). Notification webhooks encrypted at rest AES-256-GCM
  (`NOTIFICATION_ENCRYPTION_KEY`). Sidecar secret writes are constrained to an `ALLOWED_ENV_KEYS`
  allowlist behind the `LOCAL_API_TOKEN` gate.
- **WATCHTOWER assesses.** Gitleaks over the working tree; cross-checking that the target's own
  secret-lint intent holds. **No secrets are exercised or exfiltrated.**
### L. Tauri desktop app & Node sidecar

- **Component to assess.** `src-tauri/` (Tauri 2, Rust shell, `src/main.rs`,
  `capabilities/`) plus the Node sidecar `src-tauri/sidecar/local-api-server.mjs` (~2045
  lines). The renderer↔sidecar trust boundary and IPC command surface.
- **Existing controls (observed).** `Cargo.toml` pins `tauri >=2.11.1,<3`; devtools **not**
  enabled by default; `TRUSTED_WINDOWS`/`SECRET_MANAGEMENT_WINDOWS` allowlists; gated IPC
  commands with path allow-lists; **no** `get_secret`/`get_all_secrets`/`get_local_api_token`
  commands (asserted by the target's own tests). `LOCAL_API_TOKEN` = 32 bytes from `getrandom`,
  native-only, passed to the sidecar via env; sidecar is **default-deny** (503 on every route if
  the token is unset), with only `/api/sidecar-health`, `/api/service-status`,
  `/api/youtube-embed` exempt. Sidecar SSRF guard (`isSafeUrl`/`isPrivateIP`/`makePinnedLookup`),
  HMAC desktop-auth (`WM_DESKTOP_SHARED_SECRET`), keyring v3 consolidated vault.
  `scripts/check-rust-security-floors.mjs` enforces `tauri ≥ 2.11.1`
  (GHSA-7gmj-67g7-phm9 / CVE-2026-42184) and `openssl ≥ 0.10.80`. The target credits **Cody
  Richard (2026)** in its Security Acknowledgments for IPC/trust-boundary hardening.
- **Note to assess.** `SECURITY.md` describes a fetch-patch that "injects the sidecar token
  with a 5-minute TTL," while the shipped renderer keeps the token native-only and proxies via
  IPC — a **doc/code consistency item to reconcile**, not a weakness claim.
- **WATCHTOWER assesses.** Mostly **out of the prototype's dynamic scope** (the prototype
  targets the web instance on `localhost:3000`); covered by static Semgrep + the Rust-floor
  cross-check, and flagged for the future Tauri/Rust deep-analysis tier
  ([13-roadmap.md](13-roadmap.md) §13.3).

### M. CSP / Reporting sink & misc edge endpoints

- **Component to assess.** `api/security/report.js` — an **unauthenticated by-design** CSP /
  Reporting-API sink (browsers POST here), wildcard CORS, no persistence.
- **Existing controls (observed).** `MAX_REPORT_BYTES=32 KB`, `MAX_REPORT_ITEMS=20`,
  content-type allowlist (415 otherwise), rate-limited, reduces each report to a small
  sanitized projection and only `console.info`s it, returns 204. No storage.
- **WATCHTOWER assesses.** Confirm the sink stays a bounded, no-persistence, sanitized-logging
  endpoint (headers/auth probes); its public unauthenticated nature is **by design**.

## 11.4 Mapping Surfaces To The Five Probes

| Surface class | Primary probe(s) | Also touched by |
|---------------|------------------|-----------------|
| A. API gateway / RPC | auth | Semgrep, ZAP, Nuclei |
| B. Auth / API-key / entitlement | auth | Semgrep, Gitleaks |
| C. MCP server / proxy | auth, SSRF canary | ZAP, Nuclei |
| D. RSS proxy / relay | SSRF canary | Semgrep |
| E. Convex boundary | *(future authenticated tier)* | Semgrep |
| F. Feed ingestion / XSS | headers/CSP | Semgrep, ZAP |
| G. CORS | CORS | ZAP |
| H. Rate limiting | rate-limit | — |
| I. Headers / CSP | headers/CSP | ZAP |
| J. SSRF (all) | SSRF canary | Semgrep |
| K. Secrets | *(static)* | Gitleaks |
| L. Tauri / sidecar | *(static / future tier)* | Semgrep |
| M. Reporting sink | headers/CSP, auth | ZAP |

## 11.5 Explicit Non-Claims

- This document asserts **no** vulnerabilities, CVEs, or weaknesses in World Monitor.
- The presence of a surface here does **not** imply it is exploitable; many are heavily
  defended (see the controls under each entry).
- Verdicts exist only after a WATCHTOWER run writes evidence
  ([08-finding-schema.md](08-finding-schema.md)); until then every item is a place to look,
  a control to respect, or a consistency question to reconcile — nothing more.

