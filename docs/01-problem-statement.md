# 01 — Problem Statement

## 1.1 SIH Problem Statement

> **Security Assessment of World Monitor**
>
> Develop a solution capable of systematically evaluating the security posture of the
> World Monitor application. The solution must go beyond running individual security
> scanners: it should combine source-code analysis, secret detection, dependency
> vulnerability analysis, runtime/API security testing, security-configuration checks,
> and custom application-specific checks; correlate findings across those sources;
> verify suspected vulnerabilities; prioritise risk; and produce evidence-backed reports.

Target repository: <https://github.com/koala73/worldmonitor>

WATCHTOWER is our answer to this problem statement. It is a **security-assessment
platform** — not a scanner wrapper, not a firewall, not an exploitation framework.

## 1.2 What World Monitor Is

World Monitor is a real-time global-intelligence dashboard that aggregates open-source
data (geopolitics, markets, energy, climate, aviation, maritime, cyber, conflict, and
news) into a single situational-awareness interface. It is a large, actively developed,
multi-surface application. Based on inspection of the repository at commit
`a213b425a` (version `2.10.0`, branch `main`), its surfaces include:

| Surface | Description | Evidence in repo |
|---------|-------------|------------------|
| Browser SPA | Vanilla TypeScript + Vite single-page app, dual map engine (deck.gl + globe.gl), ~109 panel classes, web workers for on-device ML | `src/`, `vite.config.ts`, `index.html` |
| HTTP API | ~246 files under `api/`, deployed as Vercel Edge Functions; proto-first "sebuf" RPC gateways plus hand-written operational endpoints | `api/`, `server/gateway.ts`, `vercel.json` |
| MCP server | Model Context Protocol server at `/mcp` (Streamable HTTP) with a tool registry, resources, and a skills extension | `api/mcp/`, `mcp.json`, `server.json` |
| Backend | Convex Cloud (billing/entitlements, user state, API keys, forms, intel memory) | `convex/`, `package.json` |
| Relay / workers | Railway AIS relay + seed loops + RSS proxy; Cloudflare Workers for CORS preflight | `scripts/ais-relay*.cjs`, `workers/`, `Dockerfile.relay` |
| Desktop app | Tauri 2 (Rust) shell with a bundled Node.js sidecar, OS-keyring secret storage | `src-tauri/`, `src-tauri/sidecar/` |

This breadth is itself the core of the problem: World Monitor is not a single web app
with one attack surface. It is a browser client, a public REST/RPC API, an
agent-facing MCP server, a payments-and-identity backend, a set of relays and workers,
and a native desktop application — each with a different trust model.

## 1.3 Why Security Assessment Here Is Hard

1. **Many heterogeneous surfaces.** A browser XSS control (DOMPurify, CSP), an edge-API
   authorization control (`server/gateway.ts` API-key + entitlement checks), an SSRF
   control on an outbound proxy (`api/mcp` downstream fetch, `api/rss-proxy`), and a
   desktop IPC trust boundary (Tauri commands ↔ Node sidecar) are all *different classes
   of problem*. No single scanner reasons about all of them.
2. **Multiple runtimes and languages.** TypeScript on Vercel Edge (Web/`fetch` runtime),
   Node.js in the sidecar and relay, Rust in the Tauri shell, plus Convex functions.
   Tooling that only understands one runtime sees only part of the system.
3. **Server-side URL fetching is central to the product.** The app deliberately fetches
   hundreds of upstream hosts (the architecture notes "578+ observed upstream hosts").
   Distinguishing an *intended* outbound fetch from an *SSRF-exploitable* one requires
   understanding the allowlist and DNS-resolution controls, not just pattern matching.
4. **Auth is layered and context-dependent.** Trusted browser origins are exempt from
   API keys; non-browser origins require a `wm_…` key; premium RPCs always require a key;
   the MCP `tools/call` path authenticates separately. A finding is only meaningful in
   the context of which caller hits which path.
5. **Config is security-critical and large.** `vercel.json` (per-route CORS, CSP, and
   security headers), `.env.example` (279 declared configuration keys), and
   `src-tauri/tauri.conf.json` (desktop capabilities) each encode security decisions
   that must be assessed as configuration, not code.

## 1.4 Why Single-Tool Scanning Is Insufficient

A conventional "run Semgrep / npm audit and paste the output" approach fails on a system
like this for concrete reasons:

- **No cross-source correlation.** A static "possible SSRF" in a handler and a live
  reachable endpoint at the same path are two separate signals. Value comes from
  *linking* them, which a single tool cannot do.
- **High false-positive rate, no verification.** A dependency advisory or a Semgrep rule
  match is a *hypothesis*. Whether it is reachable and exploitable in this codebase is a
  separate question that requires a controlled test.
- **No shared vocabulary.** Semgrep, Gitleaks, OSV-Scanner, npm audit, ZAP, and Nuclei
  each emit their own schema and severity language. Without normalisation, findings
  cannot be de-duplicated, correlated, or ranked coherently.
- **No evidence trail.** A raw scanner line is not an assessment. A defensible assessment
  records *why* a finding holds its status and preserves the artefact that proves it.

## 1.5 What The Problem Actually Requires

- **Repeatability.** The same command must produce the same, comparable assessment run
  after run — a prerequisite for tracking posture over time and for anyone reproducing a
  result.
- **Correlation.** Findings from independent sources that describe the same underlying
  issue must be grouped into a single, higher-confidence observation.
- **Verification.** A suspected vulnerability must be confirmed by a controlled,
  local, non-destructive probe that demonstrates the actual security property — not
  assumed from a scanner hit.
- **Evidence-backed results.** Every finding must carry the evidence and the reasoning
  that justify its final status and score.

## 1.6 Scope Statement (Important)

This document, and the WATCHTOWER documentation set as a whole, describes a
**methodology and platform design**. It does **not** claim that World Monitor contains
any specific vulnerability. Any security property — present control or weakness — will
be asserted only after an actual assessment run produces evidence for it. Where this
documentation lists parts of World Monitor, it lists them as *components and candidate
attack surfaces to assess*, explicitly distinguished from *confirmed findings*.

See also: [02-proposed-solution.md](02-proposed-solution.md),
[11-world-monitor-attack-surface.md](11-world-monitor-attack-surface.md),
[10-verification-model.md](10-verification-model.md).

