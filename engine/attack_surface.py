"""Static attack-surface discovery for the assessment target (Phase 5).

This module reads the target repository *read-only* and produces a normalised
inventory of endpoints, security-sensitive modules, external integrations and
configuration references. It performs NO network activity and modifies nothing.

IMPORTANT: attack-surface entries are NOT vulnerabilities. An endpoint appearing
here means "this is a place worth assessing", never "this is exploitable". The
only way a finding becomes verified is through the verification framework; this
module merely tells that framework (and the reader) where to look.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Risk tags (item 2 of the Phase-5 spec). A tag marks an endpoint as a CANDIDATE
# for a particular class of assessment. It is a routing hint, not a verdict.
# ---------------------------------------------------------------------------
SSRF_CANDIDATE = "ssrf_candidate"
AUTH_BOUNDARY = "auth_boundary"
CORS_CANDIDATE = "cors_candidate"
RATE_LIMIT_CANDIDATE = "rate_limit_candidate"
EXTERNAL_FETCH = "external_fetch"
MCP = "mcp"
RPC = "rpc"
SECRET_SENSITIVE = "secret_sensitive"

RISK_TAGS = (
    SSRF_CANDIDATE, AUTH_BOUNDARY, CORS_CANDIDATE, RATE_LIMIT_CANDIDATE,
    EXTERNAL_FETCH, MCP, RPC, SECRET_SENSITIVE,
)

# Endpoint "kind" — the structural family the entry was discovered from.
KIND_API_ROUTE = "api-route"
KIND_RPC = "rpc"
KIND_MIDDLEWARE = "middleware"

_MAX_FILE_BYTES = 400_000            # skip pathologically large files, read-only cap
_URL_LIKE_PARAMS = ("url", "uri", "feed", "target", "endpoint", "u", "src",
                    "link", "webhook", "callback", "dest", "redirect")
_SECRET_ENV_RE = re.compile(r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|HMAC|PRIVATE|"
                            r"CREDENTIAL|SALT|SIGNING)", re.I)
_ENV_REF_RE = re.compile(r"process\.env\.([A-Z0-9_]+)")
_ENV_REF_BRACKET_RE = re.compile(r"process\.env\[['\"]([A-Z0-9_]+)['\"]\]")


@dataclass
class Endpoint:
    """A normalised, tool-agnostic representation of one attack-surface entry."""
    path: str                                   # URL path, e.g. "/api/rss-proxy"
    methods: list = field(default_factory=list)  # ["GET","POST"] or ["ANY"]
    source_file: str = ""                       # repo-relative path
    component: str = "core"                     # domain/component grouping
    authentication: str = "unknown"             # required | public | unknown
    input_types: list = field(default_factory=list)   # query|json-body|path-param|headers
    external_requests: list = field(default_factory=list)  # outbound targets it may call
    risk_tags: list = field(default_factory=list)      # subset of RISK_TAGS
    evidence: dict = field(default_factory=dict)       # why each tag/flag was set
    kind: str = KIND_API_ROUTE

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": ",".join(self.methods) if self.methods else "ANY",
            "methods": list(self.methods) if self.methods else ["ANY"],
            "source_file": self.source_file,
            "component": self.component,
            "authentication": self.authentication,
            "input_types": list(self.input_types),
            "external_requests": list(self.external_requests),
            "risk_tags": list(self.risk_tags),
            "kind": self.kind,
            "evidence": dict(self.evidence),
        }


@dataclass
class AttackSurface:
    """The full static inventory. Endpoints, helper modules, integrations, config."""
    endpoints: list = field(default_factory=list)          # list[Endpoint]
    security_modules: list = field(default_factory=list)   # list[dict]
    integrations: list = field(default_factory=list)       # list[dict]
    env_references: list = field(default_factory=list)      # sorted unique names
    notes: list = field(default_factory=list)

    def summary(self) -> dict:
        tag_counts = {t: 0 for t in RISK_TAGS}
        components = {}
        for ep in self.endpoints:
            for tag in ep.risk_tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
            components[ep.component] = components.get(ep.component, 0) + 1
        return {
            "endpoint_count": len(self.endpoints),
            "security_module_count": len(self.security_modules),
            "integration_count": len(self.integrations),
            "env_reference_count": len(self.env_references),
            "risk_tag_counts": tag_counts,
            "component_counts": components,
        }

    def to_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "security_modules": list(self.security_modules),
            "integrations": list(self.integrations),
            "env_references": list(self.env_references),
            "notes": list(self.notes),
            "disclaimer": ("Attack-surface entries are assessment targets, NOT "
                           "vulnerabilities. Presence here is not a claim of weakness."),
        }


# ---------------------------------------------------------------------------
# Low-level filesystem + text helpers (all strictly read-only).
# ---------------------------------------------------------------------------
def _read_text(path: str) -> str:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _relativize(path: str, repo_path: str) -> str:
    try:
        return os.path.relpath(path, repo_path).replace(os.sep, "/")
    except ValueError:
        return path.replace(os.sep, "/")


def _iter_files(base: str, exts: tuple) -> list:
    out = []
    if not os.path.isdir(base):
        return out
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "dist", "build")]
        for name in files:
            if name.endswith(exts):
                out.append(os.path.join(root, name))
    return out

def _is_helper_file(name: str) -> bool:
    """`_`-prefixed files, tests and type decls are shared modules, not routes."""
    return (name.startswith("_") or ".test." in name or ".spec." in name
            or name.endswith(".d.ts"))


def _route_path_from_file(rel_from_api: str) -> str:
    """Map a Vercel-style api/ file to its URL path.

    `foo/bar.ts` -> `/api/foo/bar`; `index.ts` -> `/api`; `[id].ts` -> `/api/:id`;
    `[...slug].ts` -> `/api/*`.
    """
    no_ext = re.sub(r"\.(ts|js|mjs|cjs|tsx|jsx)$", "", rel_from_api)
    parts = [p for p in no_ext.split("/") if p]
    mapped = []
    for part in parts:
        if part == "index":
            continue
        m = re.fullmatch(r"\[\.\.\.(.+)\]", part)
        if m:
            mapped.append("*")
            continue
        m = re.fullmatch(r"\[(.+)\]", part)
        if m:
            mapped.append(":" + m.group(1))
            continue
        mapped.append(part)
    return "/api/" + "/".join(mapped) if mapped else "/api"


def _component_for(route_path: str) -> str:
    """Group by the first meaningful path segment under /api."""
    segs = [s for s in route_path.split("/") if s and s not in ("api",)]
    if not segs:
        return "core"
    first = segs[0]
    return "core" if first.startswith((":", "*")) else first


def _detect_methods(text: str) -> list:
    found = set()
    for m in re.finditer(r"req(?:uest)?\.method\s*[=!]==?\s*['\"]([A-Za-z]+)['\"]", text):
        found.add(m.group(1).upper())
    for m in re.finditer(r"\bmethods?\s*:\s*\[([^\]]+)\]", text):
        for tok in re.findall(r"['\"]([A-Za-z]+)['\"]", m.group(1)):
            found.add(tok.upper())
    for m in re.finditer(r"export\s+(?:async\s+)?function\s+"
                         r"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b", text):
        found.add(m.group(1))
    for m in re.finditer(r"export\s+const\s+"
                         r"(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s*=", text):
        found.add(m.group(1))
    valid = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
    return sorted(found & valid)


def _detect_input_types(text: str) -> list:
    types = []
    if re.search(r"\.query\b|searchParams|new URL\(|URLSearchParams", text):
        types.append("query")
    if re.search(r"\.json\(\)|readBoundedRequestBody|\.body\b|await\s+req(?:uest)?\.text\(",
                 text):
        types.append("json-body")
    if re.search(r"\.headers\b|headers\.get\(", text):
        types.append("headers")
    return types


def _detect_env_refs(text: str) -> set:
    refs = set(_ENV_REF_RE.findall(text))
    refs |= set(_ENV_REF_BRACKET_RE.findall(text))
    return refs

# Import / call markers that indicate authentication is enforced somewhere in the file.
_AUTH_MARKERS = (
    "_api-key", "_session", "validateApiKey", "requireAuth", "getSession",
    "@clerk", "clerkClient", "getAuth(", "resolvePremiumCallerIdentity",
    "assertAuth", "checkAuth", "mcpProToken", "verifyToken", "RELAY_SHARED_SECRET",
    "premium-check", "agent-auth",
)
_PUBLIC_MARKERS = ("isKnownPublicPagePath", "intentionally public", "public: true",
                   "SOCIAL_PREVIEW_PATHS")
_FETCH_MARKERS = ("fetch(", "axios", "undici", "got(", "node-fetch", "http.request",
                  "https.request")
_CORS_MARKERS = ("_cors", "getCorsHeaders", "Access-Control-Allow", "applyCors")
_RATE_MARKERS = ("_rate-limit", "checkRateLimit", "ratelimit", "Ratelimit",
                 "@upstash/ratelimit")
_MCP_MARKERS = ("modelcontextprotocol", "jsonrpc", "tools/list", "tools/call",
                "mcp", "JSON-RPC")


def _classify_endpoint(route_path: str, text: str, kind: str) -> dict:
    """Derive authentication, tags, external requests and supporting evidence.

    Every decision is recorded in `evidence` so the reader can audit *why* a tag
    was applied. No tag here asserts a vulnerability — only that the endpoint is
    a candidate worth assessing for that class.
    """
    low = text.lower()
    tags, ext, notes = set(), [], {}
    env_refs = sorted(_detect_env_refs(text))

    has_auth = any(mk.lower() in low for mk in _AUTH_MARKERS)
    is_public = any(mk.lower() in low for mk in _PUBLIC_MARKERS)
    authentication = "required" if has_auth else ("public" if is_public else "unknown")
    if has_auth or kind == KIND_MIDDLEWARE:
        tags.add(AUTH_BOUNDARY)
        notes["auth_markers"] = [mk for mk in _AUTH_MARKERS if mk.lower() in low]

    if any(mk.lower() in low for mk in _FETCH_MARKERS):
        tags.add(EXTERNAL_FETCH)
        ext.append("outbound-http")
    if "_relay" in low or "getrelaybaseurl" in low or "relay" in route_path.lower():
        ext.append("relay")

    has_url_param = any(re.search(r"['\"]" + re.escape(p) + r"['\"]", text)
                        for p in _URL_LIKE_PARAMS)
    is_proxy = "proxy" in route_path.lower()
    if (EXTERNAL_FETCH in tags) and (has_url_param or is_proxy):
        tags.add(SSRF_CANDIDATE)
        notes["ssrf_reason"] = ("outbound fetch with caller-influenced target"
                                if has_url_param else "proxy endpoint performs outbound fetch")

    has_rate_guard = any(mk.lower() in low for mk in _RATE_MARKERS)
    if any(mk.lower() in low for mk in _CORS_MARKERS):
        tags.add(CORS_CANDIDATE)
    if any(mk.lower() in low for mk in _MCP_MARKERS) or "mcp" in route_path.lower():
        tags.add(MCP)
    if kind == KIND_RPC:
        tags.add(RPC)

    # Rate-limit candidacy: state-changing / proxy / mcp / auth surfaces are worth
    # probing. Record whether a guard is already present (has, ≠ verified-safe).
    if is_proxy or (MCP in tags) or (AUTH_BOUNDARY in tags) or has_rate_guard:
        tags.add(RATE_LIMIT_CANDIDATE)
    notes["has_rate_limit_guard"] = has_rate_guard
    notes["has_cors_handling"] = CORS_CANDIDATE in tags

    secret_env = [e for e in env_refs if _SECRET_ENV_RE.search(e)]
    if secret_env or "_crypto" in low or "_oauth-token" in low or "hmac" in low:
        tags.add(SECRET_SENSITIVE)
        if secret_env:
            notes["secret_env_refs"] = secret_env

    if env_refs:
        notes["env_refs"] = env_refs
    if "edge" in low and "runtime" in low:
        notes["runtime"] = "edge"

    return {
        "authentication": authentication,
        "risk_tags": sorted(tags),
        "external_requests": ext,
        "input_types": _detect_input_types(text),
        "evidence": notes,
        "env_refs": env_refs,
    }

# Known dependency -> external integration mapping (declared deps are honest facts).
_INTEGRATION_DEPS = {
    "@clerk/clerk-js": ("Clerk", "authentication"),
    "@clerk/nextjs": ("Clerk", "authentication"),
    "@clerk/backend": ("Clerk", "authentication"),
    "convex": ("Convex", "backend-rpc"),
    "@upstash/ratelimit": ("Upstash", "rate-limiting"),
    "@upstash/redis": ("Upstash Redis", "datastore"),
    "@sentry/browser": ("Sentry", "observability"),
    "@sentry/node": ("Sentry", "observability"),
    "@anthropic-ai/sdk": ("Anthropic", "ai-provider"),
    "@aws-sdk/client-s3": ("AWS S3", "object-storage"),
    "@vercel/functions": ("Vercel", "hosting-runtime"),
    "dompurify": ("DOMPurify", "sanitisation"),
}


def discover_vercel_routes(repo_path: str) -> list:
    api_dir = os.path.join(repo_path, "api")
    endpoints = []
    for path in _iter_files(api_dir, (".ts", ".js", ".mjs", ".cjs", ".tsx", ".jsx")):
        name = os.path.basename(path)
        if _is_helper_file(name):
            continue
        rel_from_api = _relativize(path, api_dir)
        route = _route_path_from_file(rel_from_api)
        text = _read_text(path)
        info = _classify_endpoint(route, text, KIND_API_ROUTE)
        methods = _detect_methods(text) or ["ANY"]
        if route.split("/")[-1] in ("*",) or ":" in route:
            info["input_types"] = sorted(set(info["input_types"]) | {"path-param"})
        endpoints.append(Endpoint(
            path=route, methods=methods, source_file=_relativize(path, repo_path),
            component=_component_for(route), authentication=info["authentication"],
            input_types=info["input_types"], external_requests=info["external_requests"],
            risk_tags=info["risk_tags"], evidence=info["evidence"], kind=KIND_API_ROUTE))
    return endpoints


def discover_convex_rpc(repo_path: str) -> list:
    convex_dir = os.path.join(repo_path, "convex")
    endpoints = []
    rpc_re = re.compile(r"export\s+const\s+(\w+)\s*=\s*(query|mutation|action|"
                        r"internalQuery|internalMutation|internalAction|httpAction)\b")
    for path in _iter_files(convex_dir, (".ts", ".js")):
        name = os.path.basename(path)
        if name.startswith("_") or name in ("schema.ts", "auth.config.ts") \
                or ".test." in name or name.endswith(".d.ts"):
            continue
        text = _read_text(path)
        module = re.sub(r"\.(ts|js)$", "", _relativize(path, convex_dir))
        for m in rpc_re.finditer(text):
            fn_name, fn_kind = m.group(1), m.group(2)
            methods = ["GET"] if "query" in fn_kind.lower() else ["POST"]
            info = _classify_endpoint(f"convex/{module}.{fn_name}", text, KIND_RPC)
            internal = fn_kind.startswith("internal")
            auth = "required" if internal else info["authentication"]
            endpoints.append(Endpoint(
                path=f"convex:{module}.{fn_name}", methods=methods,
                source_file=_relativize(path, repo_path), component="convex-rpc",
                authentication=auth, input_types=info["input_types"] or ["json-body"],
                external_requests=info["external_requests"],
                risk_tags=sorted(set(info["risk_tags"]) | {RPC}),
                evidence={**info["evidence"], "convex_kind": fn_kind,
                          "internal": internal}, kind=KIND_RPC))
    return endpoints


def discover_middleware(repo_path: str) -> list:
    endpoints = []
    for candidate in ("middleware.ts", "middleware.js", "src/middleware.ts"):
        path = os.path.join(repo_path, candidate)
        if not os.path.isfile(path):
            continue
        text = _read_text(path)
        info = _classify_endpoint("/*", text, KIND_MIDDLEWARE)
        endpoints.append(Endpoint(
            path="/* (edge middleware)", methods=["ANY"],
            source_file=_relativize(path, repo_path), component="edge-middleware",
            authentication=info["authentication"] if info["authentication"] != "unknown"
            else "required", input_types=info["input_types"],
            external_requests=info["external_requests"],
            risk_tags=sorted(set(info["risk_tags"]) | {AUTH_BOUNDARY}),
            evidence=info["evidence"], kind=KIND_MIDDLEWARE))
    return endpoints

def discover_security_modules(repo_path: str) -> list:
    """`_`-prefixed helpers under api/ that implement a security control."""
    api_dir = os.path.join(repo_path, "api")
    modules = []
    interest = {
        "cors": "CORS handling", "rate-limit": "rate limiting", "api-key": "API-key auth",
        "session": "session handling", "crypto": "cryptographic operations",
        "oauth": "OAuth token handling", "ssrf": "SSRF mitigation",
        "relay": "outbound relay", "client-ip": "client IP resolution",
        "auth": "authentication",
    }
    for path in _iter_files(api_dir, (".ts", ".js", ".mjs", ".cjs")):
        name = os.path.basename(path)
        if not name.startswith("_"):
            continue
        stem = name.lstrip("_").lower()
        reason = next((desc for key, desc in interest.items() if key in stem), None)
        if reason is None:
            continue
        text = _read_text(path)
        info = _classify_endpoint("/" + name, text, KIND_API_ROUTE)
        modules.append({
            "file": _relativize(path, repo_path), "component": "security-helper",
            "reason": reason, "risk_tags": info["risk_tags"],
            "env_refs": info["env_refs"],
        })
    return sorted(modules, key=lambda m: m["file"])


def _load_dependencies(repo_path: str) -> dict:
    import json
    path = os.path.join(repo_path, "package.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    deps = {}
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            deps.update(section)
    return deps


def discover_integrations(repo_path: str) -> list:
    deps = _load_dependencies(repo_path)
    seen, integrations = set(), []
    for dep, (name, kind) in _INTEGRATION_DEPS.items():
        if dep in deps and name not in seen:
            seen.add(name)
            integrations.append({"name": name, "kind": kind, "evidence": {
                "declared_dependency": dep, "version": deps[dep]}})
    return integrations


def discover_attack_surface(repo_path: str) -> AttackSurface:
    """Top-level entry: build the full static inventory for `repo_path`."""
    endpoints = []
    endpoints.extend(discover_vercel_routes(repo_path))
    endpoints.extend(discover_convex_rpc(repo_path))
    endpoints.extend(discover_middleware(repo_path))
    endpoints.sort(key=lambda e: (e.component, e.path))

    security_modules = discover_security_modules(repo_path)
    integrations = discover_integrations(repo_path)

    env_refs = set()
    for ep in endpoints:
        env_refs |= set(ep.evidence.get("env_refs", []))
        ep.evidence.pop("env_refs", None)          # keep per-endpoint evidence lean
    for mod in security_modules:
        env_refs |= set(mod.get("env_refs", []))

    notes = []
    if not endpoints:
        notes.append("No api/ or convex/ endpoints were discovered under the target "
                     "repository; attack-surface discovery found nothing to inventory.")
    notes.append("Attack-surface discovery is static and read-only. Entries are "
                 "assessment targets, not vulnerabilities.")
    return AttackSurface(
        endpoints=endpoints, security_modules=security_modules,
        integrations=integrations, env_references=sorted(env_refs), notes=notes)

def _finding_path(endpoint_url: str) -> str:
    """Reduce a finding endpoint (possibly a full URL) to a comparable path."""
    if not endpoint_url:
        return ""
    path = re.sub(r"^[a-z]+://[^/]+", "", endpoint_url)
    path = path.split("?", 1)[0].rstrip("/")
    return path.lower() or "/"


def link_findings(endpoint_dicts: list, findings: list) -> dict:
    """Connect static attack-surface entries to runtime probe/scanner findings (item 3).

    Annotates each endpoint dict in place with `tested_by` (the findings that
    exercised it, with their verification result and lifecycle status) and a
    `tested` flag. Returns finding-id -> [related endpoint refs]. This is an
    observed linkage between "where we looked statically" and "what the probes
    reported" — it never infers a vulnerability from a risk tag.
    """
    by_path = {}
    for ep in endpoint_dicts:
        ep.setdefault("tested_by", [])
        ep["tested"] = False
        by_path.setdefault(_finding_path(ep.get("path", "")), []).append(ep)

    reverse: dict = {}
    for finding in findings:
        fpath = _finding_path(getattr(finding, "endpoint", None) or "")
        if not fpath:
            continue
        matches = list(by_path.get(fpath, []))
        for ep in endpoint_dicts:                       # suffix match for nested routes
            ep_path = _finding_path(ep.get("path", ""))
            if ep in matches or not ep_path or ep_path == "/":
                continue
            if fpath == ep_path or fpath.endswith(ep_path):
                matches.append(ep)
        result = (getattr(finding, "verification", None) or {}).get("result")
        for ep in matches:
            ep["tested"] = True
            ep["tested_by"].append({
                "tool": finding.tool, "finding_id": finding.id,
                "result": result, "status": finding.status})
            reverse.setdefault(finding.id, []).append({
                "path": ep.get("path"), "component": ep.get("component"),
                "risk_tags": ep.get("risk_tags", [])})
    return reverse

