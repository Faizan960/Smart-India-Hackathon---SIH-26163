# 07 — Security Assessment Methodology

This document defines the **methodology** WATCHTOWER follows: the repeatable process, the
rules of engagement, and the epistemic discipline that turns a pile of tool output into a
ranked, evidence-backed assessment. The phase *mechanics* live in
[04-technical-approach.md](04-technical-approach.md); this is the *discipline* around them.

## 7.1 The Assessment Loop

```
DISCOVER → SCAN → NORMALIZE → CORRELATE → VERIFY → SCORE → REPORT
```

Each phase has one job and one output, and the methodology is defined by the **rules** each
phase obeys — not just the tools it runs. The loop is designed to be run repeatedly against
the same target so results are comparable over time.

## 7.2 Rules Of Engagement

These are fixed for every WATCHTOWER assessment of World Monitor:

1. **Read-only on the repository.** The target checkout is only read. WATCHTOWER writes
   nothing into World Monitor.
2. **Controlled on the running target.** Only bounded, scripted requests. No fuzzing
   storms, no destructive payloads, no denial-of-service.
3. **Local-first.** The target is the locally running instance
   (`http://localhost:3000`); the SSRF canary is a loopback server WATCHTOWER owns.
4. **Unauthenticated (prototype).** The prototype assesses what is reachable *without*
   credentials. It does not hold or exercise World Monitor secrets. Authenticated testing
   is a future item ([13-roadmap.md](13-roadmap.md) §13.3).
5. **Never cloud-metadata / third-party.** No probe ever targets link-local metadata
   addresses or unrelated external hosts.
6. **No invented results.** Every recorded finding traces to a real tool output or probe
   artefact; nothing is fabricated.

## 7.3 Epistemic Discipline

The methodology's core is refusing to conflate three different questions:

| Question | Phase | Status it can grant |
|----------|-------|---------------------|
| "Does a tool's rule match here?" | SCAN → NORMALIZE | `suspected` |
| "Do independent sources point at the same asset?" | CORRELATE | `correlated` |
| "Does the security property actually hold when exercised?" | VERIFY | `verified` / `false_positive` / `needs_manual_review` |

**Correlation is not verification.** A finding only becomes `verified` when a controlled
probe demonstrates the real behaviour. Anything that cannot be safely or conclusively
tested becomes `needs_manual_review` — never a silent pass. Full model in
[10-verification-model.md](10-verification-model.md).

## 7.4 Applying Each Phase To World Monitor

The statements below describe **what WATCHTOWER would examine** and **controls already
observed in the target's source**. They are components and attack surfaces to assess, **not
vulnerability claims** — see [11-world-monitor-attack-surface.md](11-world-monitor-attack-surface.md)
for the full inventory and the critical distinction it draws.

### DISCOVER
Enumerate the target's assets: the ~37 edge route groups at `api/<domain>/v1/[rpc].ts`, the
`server/worldmonitor/<domain>/` handlers, the MCP surface at `api/mcp`, the shared helpers
(`api/_cors.js`, `api/_rate-limit.js`, `api/_api-key.js`, `api/_session.js`), the SSRF-relevant
proxies (`api/rss-proxy.js`, `api/mcp-proxy.ts`), the config trio (`vercel.json`,
`index.html` meta CSP, `src-tauri/tauri.conf.json`), and — if running — the live endpoints
the target answers on.

### SCAN
- **Semgrep** over `api/`, `server/`, `src/`, `convex/`, `src-tauri/` for injection,
  SSRF-shaped `fetch`, auth, and unsafe-HTML patterns.
- **Gitleaks** over the working tree (the target already ships secret-lint scripts of its
  own — `check-vite-env-secrets.mjs`, `check-local-secret-dumps.mjs` — an existing control
  worth cross-checking).
- **OSV-Scanner / npm audit** over `package-lock.json` (deps include `@clerk/clerk-js`,
  `convex`, `@upstash/ratelimit`, `dompurify`, `fast-xml-parser`, `jose`, `zod`).
- **ZAP baseline + Nuclei** against the running target for headers, CORS, and generic
  exposures.

### NORMALIZE / CORRELATE
Map every hit to the common schema and group by asset. A Semgrep `fetch`-to-request-URL hit
in `api/rss-proxy.js` correlating with a discovered live `/api/rss-proxy` route is the
canonical example of promotion to `correlated`.

### VERIFY
Run the five probes (§7.5). Crucially, the target has **substantial existing controls** in
these exact areas (documented in [11](11-world-monitor-attack-surface.md)), so the honest
expected outcome for many correlated findings is `false_positive` / by-design or
`needs_manual_review` — which is precisely why verification matters and why the
methodology rewards it.

## 7.5 Coverage Map — Probes To Surfaces

| Custom probe | World Monitor surface it exercises | Existing control it must account for |
|--------------|-------------------------------------|--------------------------------------|
| headers/CSP | App + API responses; the three CSP sources | `vercel.json` CSP (`script-src 'self'`), HSTS, nosniff, COOP/COEP report-only |
| CORS | API routes, MCP endpoint | Public wildcard is **by design** on cacheable public data; credentialed CORS is fail-closed via `api/_cors.js` allowlist |
| rate-limit | Rate-limited API/MCP routes | Upstash sliding-window (`api/_rate-limit.js`), per-account burst+daily in `server/gateway.ts` |
| auth / access | Gated RPCs, MCP `tools/call`, `api/me/*` | `server/gateway.ts` key/entitlement pipeline; `PUBLIC_NO_AUTH_RPC_PATHS`; Convex-backed key validation |
| SSRF canary | Request-influenced fetch paths (e.g. RSS/MCP proxy) | Domain allowlist re-checked per redirect hop; private/reserved A/AAAA rejection; metadata-header stripping |

## 7.6 Limitations & Honesty

The methodology is explicit about what it **cannot** conclude:

- **Prototype is unauthenticated**, so behind-login and Pro/entitlement code paths are
  discovered and reasoned about but not exercised end-to-end.
- **Edge-only visibility for some flows.** The server-of-record for keys, entitlements, and
  billing lives in Convex; the prototype sees the edge contract, not the Convex internals.
- **Static tools over-report.** Scanner detections start as `suspected` for a reason; the
  target's heavy defense-in-depth means many will resolve to `false_positive` on
  verification. The report separates these clearly.
- **DNS-rebind residuals** and other timing-sensitive properties may land in
  `needs_manual_review` rather than a firm verdict.

The deliverable is a **repeatable, evidence-backed snapshot** that says plainly what it
verified, what it could not, and why — not a proof that World Monitor is secure or
insecure. See [12-prototype-scope.md](12-prototype-scope.md) §12.4 for the explicit
non-claims.

