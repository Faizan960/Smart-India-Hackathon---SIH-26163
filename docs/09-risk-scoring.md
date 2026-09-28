# 09 — Risk Scoring

## 9.1 Name And Disclaimer

The scoring model is called the **WATCHTOWER Risk Score**.

> **This is not CVSS.** It is a deliberately simple, transparent, project-specific
> **prioritisation** mechanism for ranking findings within a single WATCHTOWER assessment
> of World Monitor. It is **not** an industry-standard severity score and must not be
> reported, compared, or published as one. Where an industry identifier exists (CVE,
> GHSA, CWE), WATCHTOWER records it separately in the finding's `references`/`cwe` fields
> and does not overwrite it with this score.

The point of the score is ordering: given a list of findings, which should a human look
at first? It intentionally rewards **verification** and **sensitive assets**.

## 9.2 Inputs

### Base severity

| Band | Value |
|------|-------|
| Critical | 10 |
| High | 8 |
| Medium | 5 |
| Low | 2 |

(`info`-level findings are recorded but scored 0 — informational, not ranked as risk.)

### Verification multiplier

Confidence in the finding, driven by its lifecycle status:

| Status | Multiplier |
|--------|-----------|
| Suspected | 1.0 |
| Correlated | 1.2 |
| Verified | 1.5 |

`false_positive` findings are excluded from ranking (effective multiplier 0).
`needs_manual_review` is treated as `suspected` (1.0) for ranking until a human resolves it.

### Asset weight

How sensitive the affected asset is:

| Asset class | Weight |
|-------------|--------|
| Authentication / API keys / MCP | 1.5 |
| API endpoint | 1.2 |
| Static UI | 1.0 |

> Asset weights are mapped from the finding's `asset.kind` (see
> [08-finding-schema.md](08-finding-schema.md)). For World Monitor specifically, the
> "Authentication / API keys / MCP" class covers the API-key/entitlement path
> (`server/gateway.ts`, `api/_api-key.js`), the MCP endpoint (`api/mcp/`), and the
> desktop secret/token boundary (Tauri IPC + sidecar `LOCAL_API_TOKEN`). Dependency and
> config findings default to the API-endpoint or static-UI weight unless they clearly
> affect a higher-sensitivity asset.

## 9.3 Formula

```
Risk Score = Base Severity × Verification Multiplier × Asset Weight
```

Range: `0` to `10 × 1.5 × 1.5 = 22.5`. The score is used **only** for ranking within a
run; the absolute number carries no external meaning.

## 9.4 Worked Examples

These examples show the arithmetic. They are **illustrative** and assert nothing about
World Monitor.

| # | Base (severity) | Multiplier (status) | Weight (asset) | Risk Score |
|---|-----------------|---------------------|----------------|-----------|
| 1 | 8 (High) | 1.0 (Suspected) | 1.2 (API endpoint) | **9.6** |
| 2 | 8 (High) | 1.2 (Correlated) | 1.2 (API endpoint) | **11.52** |
| 3 | 8 (High) | 1.5 (Verified) | 1.5 (auth/MCP) | **18.0** |
| 4 | 10 (Critical) | 1.5 (Verified) | 1.5 (auth/API key) | **22.5** (max) |
| 5 | 5 (Medium) | 1.0 (Suspected) | 1.0 (static UI) | **5.0** |
| 6 | 8 (High) | 0 (False Positive) | — | **excluded** |

Example 1 → 2 → 3 shows the intended behaviour: the *same* base weakness climbs the
ranking as it gains corroboration and then verification, and climbs further when it sits
on a sensitive asset. A verified issue on an auth/MCP asset (18.0) outranks an
unverified high on a plain endpoint (9.6) — which is exactly the triage order a reviewer
wants.

## 9.5 Ranking And Presentation

- Findings are sorted by `risk_score` descending in every output.
- The report groups by status so a reader can immediately separate **Verified** findings
  (evidence-backed) from **Suspected**/**Correlated** (hypotheses) and
  **Needs Manual Review**.
- Each finding shows its three factors so the score is fully explainable — no opaque
  weighting.

## 9.6 Design Rationale

| Property | Why |
|----------|-----|
| Transparent | Three named factors, one multiplication. Anyone can recompute it. |
| Verification-weighted | Encodes WATCHTOWER's core philosophy: proven > suspected. |
| Asset-aware | A weakness on secrets/auth/MCP matters more than on static UI. |
| Deterministic | Same inputs → same score → comparable across runs. |
| Not CVSS | Avoids implying false precision or external standard compliance. |

## 9.7 Model Versioning

The active model is tagged `watchtower-risk-score-v1` and recorded in each finding's
`score.model`. If the bands, multipliers, or weights change, the tag increments so old
and new runs remain distinguishable and comparable.

