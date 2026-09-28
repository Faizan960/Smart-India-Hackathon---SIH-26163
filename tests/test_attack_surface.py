"""Tests for static attack-surface discovery (Phase 5, item 1-3).

These build a tiny synthetic Vercel/Convex-style repository in a temp dir so the
test is hermetic and never depends on the real World Monitor checkout.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import attack_surface as asf  # noqa: E402
from model.finding import Finding, Severity, Status  # noqa: E402


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_repo(root):
    _write(os.path.join(root, "package.json"),
           '{"dependencies": {"@clerk/clerk-js": "1.0.0", "convex": "1.2.0", '
           '"@upstash/ratelimit": "2.0.0"}}')
    _write(os.path.join(root, "middleware.ts"),
           "import { getAuth } from '@clerk/nextjs';\n"
           "export function middleware(req){ return getAuth(req); }\n")
    _write(os.path.join(root, "api", "rss-proxy.js"),
           "export const config = { runtime: 'edge' };\n"
           "import { getCorsHeaders } from './_cors.js';\n"
           "import { checkRateLimit } from './_rate-limit.js';\n"
           "export default async function (req){\n"
           "  const url = new URL(req.url).searchParams.get('url');\n"
           "  const key = process.env.RSS_API_KEY;\n"
           "  return fetch(url);\n}\n")
    _write(os.path.join(root, "api", "mcp-proxy.ts"),
           "import { getCorsHeaders } from './_cors';\n"
           "export default async function (req){\n"
           "  if (req.method === 'POST') { return fetch('https://mcp'); }\n"
           "  // tools/list jsonrpc\n}\n")
    _write(os.path.join(root, "api", "health.ts"),
           "// intentionally public\nexport default () => new Response('ok');\n")
    _write(os.path.join(root, "api", "news", "latest.ts"),
           "export default (req) => { const q = req.query; return q; }\n")
    _write(os.path.join(root, "api", "_cors.js"), "export function getCorsHeaders(){}\n")
    _write(os.path.join(root, "api", "_rate-limit.js"), "export function checkRateLimit(){}\n")
    _write(os.path.join(root, "convex", "apiKeys.ts"),
           "import { mutation, query } from './_generated/server';\n"
           "export const create = mutation(async (ctx, args) => {});\n"
           "export const list = query(async (ctx) => {});\n")
    _write(os.path.join(root, "convex", "schema.ts"), "export default {};\n")


class TestAttackSurface(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wt-asf-")
        build_repo(self.tmp)
        self.surface = asf.discover_attack_surface(self.tmp)
        self.by_path = {e.path: e for e in self.surface.endpoints}

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_routes_discovered_and_helpers_excluded(self):
        paths = set(self.by_path)
        self.assertIn("/api/rss-proxy", paths)
        self.assertIn("/api/mcp-proxy", paths)
        self.assertIn("/api/news/latest", paths)
        # `_`-prefixed helpers are NOT endpoints.
        self.assertNotIn("/api/_cors", paths)
        self.assertNotIn("/api/_rate-limit", paths)

    def test_rss_proxy_tagged_ssrf_and_external_fetch(self):
        ep = self.by_path["/api/rss-proxy"]
        self.assertIn(asf.SSRF_CANDIDATE, ep.risk_tags)
        self.assertIn(asf.EXTERNAL_FETCH, ep.risk_tags)
        self.assertIn(asf.CORS_CANDIDATE, ep.risk_tags)
        self.assertIn(asf.RATE_LIMIT_CANDIDATE, ep.risk_tags)
        self.assertIn(asf.SECRET_SENSITIVE, ep.risk_tags)  # RSS_API_KEY
        self.assertEqual(ep.evidence.get("runtime"), "edge")

    def test_mcp_proxy_tagged_mcp(self):
        ep = self.by_path["/api/mcp-proxy"]
        self.assertIn(asf.MCP, ep.risk_tags)
        self.assertIn("POST", ep.methods)

    def test_health_is_public(self):
        self.assertEqual(self.by_path["/api/health"].authentication, "public")

    def test_middleware_is_auth_boundary(self):
        mw = [e for e in self.surface.endpoints if e.kind == asf.KIND_MIDDLEWARE]
        self.assertEqual(len(mw), 1)
        self.assertIn(asf.AUTH_BOUNDARY, mw[0].risk_tags)

    def test_convex_rpc_discovered(self):
        rpc = [e for e in self.surface.endpoints if e.kind == asf.KIND_RPC]
        names = {e.path for e in rpc}
        self.assertIn("convex:apiKeys.create", names)
        self.assertIn("convex:apiKeys.list", names)
        for e in rpc:
            self.assertIn(asf.RPC, e.risk_tags)

    def test_security_modules_and_integrations(self):
        files = {m["file"] for m in self.surface.security_modules}
        self.assertTrue(any(f.endswith("_cors.js") for f in files))
        self.assertTrue(any(f.endswith("_rate-limit.js") for f in files))
        names = {i["name"] for i in self.surface.integrations}
        self.assertEqual({"Clerk", "Convex", "Upstash"}, names)

    def test_env_references_collected_without_values(self):
        self.assertIn("RSS_API_KEY", self.surface.env_references)

    def test_summary_and_disclaimer(self):
        d = self.surface.to_dict()
        self.assertEqual(d["summary"]["endpoint_count"], len(self.surface.endpoints))
        self.assertIn("NOT", d["disclaimer"])
        self.assertGreaterEqual(d["summary"]["risk_tag_counts"][asf.SSRF_CANDIDATE], 1)

    def test_empty_repo_notes_nothing_found(self):
        empty = tempfile.mkdtemp(prefix="wt-empty-")
        try:
            surface = asf.discover_attack_surface(empty)
            self.assertEqual(surface.endpoints, [])
            self.assertTrue(any("found nothing" in n for n in surface.notes))
        finally:
            import shutil
            shutil.rmtree(empty, ignore_errors=True)

    def test_link_findings_connects_probe_to_endpoint(self):
        endpoint_dicts = [e.to_dict() for e in self.surface.endpoints]
        finding = Finding(tool="ssrf", title="SSRF probe", description="d",
                          severity=Severity.INFO, status=Status.FALSE_POSITIVE, id="WT-SSRF-0001",
                          endpoint="http://localhost:3000/api/rss-proxy",
                          verification={"result": "refuted"})
        reverse = asf.link_findings(endpoint_dicts, [finding])
        self.assertIn("WT-SSRF-0001", reverse)
        linked = {ep["path"]: ep for ep in endpoint_dicts}
        self.assertTrue(linked["/api/rss-proxy"]["tested"])
        self.assertEqual(linked["/api/rss-proxy"]["tested_by"][0]["result"], "refuted")
        # An untested endpoint stays honestly marked untested.
        self.assertFalse(linked["/api/health"]["tested"])


if __name__ == "__main__":
    unittest.main()

