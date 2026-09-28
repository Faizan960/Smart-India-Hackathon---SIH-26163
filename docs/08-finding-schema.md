# 08 — Finding Schema

Every collector's output is converted into one **normalised finding**. This single schema
is what makes correlation, verification, scoring, and reporting tool-agnostic. It is
designed to be losslessly convertible to SARIF for the report stage.

## 8.1 Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Stable WATCHTOWER finding id (e.g. `WM-2026-000123`). Deterministic from a hash of `tool + rule + asset + location` so re-runs are comparable. |
| `tool` | string | yes | Originating collector: `semgrep`, `gitleaks`, `osv-scanner`, `npm-audit`, `zap`, `nuclei`, or a custom probe id (e.g. `wm-cors`, `wm-ssrf`). |
| `title` | string | yes | Short human-readable summary. |
| `description` | string | yes | Longer explanation of the issue and why it matters. |
| `cwe` | string \| null | no | CWE identifier where applicable (e.g. `CWE-918`). Null when not classifiable. |
| `severity` | enum | yes | Base severity band: `critical` \| `high` \| `medium` \| `low` \| `info`. |
| `file` | string \| null | no | Repo-relative file path for static findings. |
| `line` | integer \| null | no | 1-indexed line for static findings. |
| `endpoint` | string \| null | no | URL/route for dynamic findings (e.g. `/api/mcp`). |
| `evidence` | object | yes | Raw and derived evidence (see §8.3). |
| `status` | enum | yes | Lifecycle state: `suspected` \| `correlated` \| `verified` \| `false_positive` \| `needs_manual_review`. |
| `score` | object | yes | WATCHTOWER Risk Score result (see [09-risk-scoring.md](09-risk-scoring.md)). |
| `asset` | object | yes | The thing at risk + its asset class/weight (see §8.4). |
| `verification` | object | yes | How (or whether) the finding was verified (see §8.5). |
| `fix` | object \| null | no | Suggested remediation + references. |
| `references` | string[] | no | URLs: advisories, CWE, tool rule docs. |

## 8.2 Status Values (the finding lifecycle)

| Status | Meaning | How it is reached |
|--------|---------|-------------------|
| `suspected` | A single source reported it; no corroboration. | Default on normalisation. |
| `correlated` | ≥2 independent sources map to the same asset/issue. | Correlation engine. |
| `verified` | A controlled probe demonstrated the actual property. | Verification engine only. |
| `false_positive` | Evidence shows the finding does not hold. | Verification engine, or reviewer. |
| `needs_manual_review` | Cannot be safely/automatically verified. | Verification engine defers. |

> A finding **never** starts life as `verified`. Correlation raises confidence but does
> not by itself grant `verified` — see [10-verification-model.md](10-verification-model.md).

## 8.3 The `evidence` Object

```
evidence = {
  raw:            <original tool output fragment>,
  sources:        [ { tool, rule, raw_severity, location } , ... ],
  correlation:    [ <ids of findings this was correlated with> ],
  artifacts:      [ <paths in the evidence store: probe req/resp, logs> ],
  notes:          <free text: analyst/engine reasoning>
}
```

## 8.4 The `asset` Object

```
asset = {
  kind:   "auth" | "api_key" | "mcp" | "api_endpoint" | "static_ui" | "dependency" | "config" | "desktop",
  ref:    <file path or endpoint or package@version>,
  weight: <numeric asset weight used by scoring>   // see 09-risk-scoring.md
}
```

## 8.5 The `verification` Object

```
verification = {
  method:   "none" | "correlation" | "active_probe" | "manual",
  probe:    <probe id, e.g. "wm-ssrf-canary">,
  result:   "confirmed" | "refuted" | "inconclusive" | null,
  rationale:<why this status was assigned>,
  timestamp:<ISO-8601>
}
```

## 8.6 JSON Example

The example below is an **illustrative schema sample** — a fabricated record that shows
the shape of a finding. It is **not** a claim about World Monitor; note `status:
"suspected"` and `verification.result: null`.

```json
{
  "id": "WM-2026-000042",
  "tool": "semgrep",
  "title": "Server-side request to a URL derived from request input",
  "description": "A handler issues an outbound fetch to a URL influenced by caller input. Whether this is exploitable depends on the allowlist/DNS controls and must be verified.",
  "cwe": "CWE-918",
  "severity": "high",
  "file": "api/example/v1/[rpc].ts",
  "line": 128,
  "endpoint": "/api/example/v1",
  "asset": { "kind": "api_endpoint", "ref": "/api/example/v1", "weight": 1.2 },
  "evidence": {
    "raw": "semgrep rule ssrf.outbound-fetch matched fetch(userUrl)",
    "sources": [
      { "tool": "semgrep", "rule": "ssrf.outbound-fetch", "raw_severity": "WARNING", "location": "api/example/v1/[rpc].ts:128" }
    ],
    "correlation": [],
    "artifacts": [],
    "notes": "Single-source hypothesis. No runtime corroboration yet."
  },
  "status": "suspected",
  "verification": {
    "method": "none",
    "probe": null,
    "result": null,
    "rationale": "Not yet correlated or verified.",
    "timestamp": "2026-09-28T00:00:00Z"
  },
  "score": {
    "base_severity": 8,
    "verification_multiplier": 1.0,
    "asset_weight": 1.2,
    "risk_score": 9.6,
    "model": "watchtower-risk-score-v1"
  },
  "fix": null,
  "references": [
    "https://cwe.mitre.org/data/definitions/918.html"
  ]
}
```

## 8.7 SARIF Mapping (report stage)

| Finding field | SARIF location |
|---------------|----------------|
| `id` | `result.ruleId` / `result.guid` |
| `title`/`description` | `result.message.text`, `rule.shortDescription` |
| `severity` | `result.level` + `properties.severity` |
| `file`/`line` | `result.locations[].physicalLocation` |
| `endpoint` | `result.locations[].logicalLocation` or `properties.endpoint` |
| `status`,`score`,`verification`,`asset` | `result.properties` (WATCHTOWER extension keys) |

WATCHTOWER-specific fields ride in SARIF `properties` bags so the output stays valid
SARIF 2.1.0 while preserving the lifecycle and score.

