"""Dependency reachability analysis over an npm project's manifests (read-only).

Reads the target's package.json and package-lock.json to answer, for a package named
in a scanner advisory:
  * is it actually present in the installed tree?
  * production or development dependency?
  * a direct (declared) dependency, or pulled in transitively?
  * is it imported anywhere in the application source we can see?

These facts let a verifier decide, honestly, whether an npm/OSV advisory plausibly
affects the *running* target — instead of asserting a vulnerability just because a
scanner listed the package. Nothing here modifies the target; it only reads files.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# Directories treated as "application source" when searching for an import. node_modules
# and build output are deliberately excluded — a dependency living only there is not
# evidence that application code reaches it.
DEFAULT_SOURCE_DIRS = ("src", "app", "api", "server", "convex", "sidecar", "electron",
                       "lib", "libs", "packages", "components", "pages", "routes",
                       "scripts", "worker", "workers")
_IGNORE_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".vercel", "out",
                "coverage", ".turbo", ".cache", ".svelte-kit", ".output", "vendor"}
_SOURCE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
_MAX_FILE_BYTES = 512 * 1024
_MAX_FILES = 6000


@dataclass
class DependencyFacts:
    package: str
    present_in_lock: bool = False
    installed_versions: list = field(default_factory=list)
    dependency_type: str = "unknown"       # production | development | optional | unknown
    direct_or_transitive: str = "unknown"  # direct | transitive | unknown
    reachable: str = "unknown"             # imported | not-imported | not-applicable | unknown
    reachability_reason: str = ""
    parents: list = field(default_factory=list)
    manifest_error: Optional[str] = None

    def as_evidence(self) -> dict:
        return {
            "dependency": self.package,
            "version": self.installed_versions[0] if self.installed_versions else None,
            "installed_versions": self.installed_versions,
            "dependency_type": self.dependency_type,
            "direct_or_transitive": self.direct_or_transitive,
            "reachable": self.reachable,
            "reachability_reason": self.reachability_reason,
            "present_in_lock": self.present_in_lock,
            "lock_nodes": self.parents,
            "manifest_error": self.manifest_error,
        }


def _read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def load_manifests(repo_path: str):
    """Return (package_json, package_lock) dicts; either may be None if absent/unreadable."""
    if not repo_path:
        return None, None
    pkg = _read_json(os.path.join(repo_path, "package.json"))
    lock = _read_json(os.path.join(repo_path, "package-lock.json"))
    return pkg, lock


def _lock_nodes_for(lock: dict, name: str) -> list:
    """All installed nodes for `name` in a lockfileVersion 2/3 package-lock.json.

    Node keys look like 'node_modules/uuid' or
    'node_modules/rpc-websockets/node_modules/uuid'; the effective package name is the
    path segment after the final 'node_modules/'. Falls back to the legacy v1 tree.
    """
    nodes = []
    packages = (lock or {}).get("packages") or {}
    for key, node in packages.items():
        if not key or "node_modules/" not in key:
            continue
        if key.split("node_modules/")[-1] != name:
            continue
        nodes.append({
            "path": key,
            "version": node.get("version"),
            "dev": bool(node.get("dev", False)),
            "optional": bool(node.get("optional", False)),
        })
    if not nodes and isinstance((lock or {}).get("dependencies"), dict):
        stack = [("", n, d) for n, d in lock["dependencies"].items()]
        while stack:
            parent, cur_name, meta = stack.pop()
            meta = meta or {}
            if cur_name == name:
                nodes.append({
                    "path": f"{parent}/{cur_name}".strip("/"),
                    "version": meta.get("version"),
                    "dev": bool(meta.get("dev", False)),
                    "optional": bool(meta.get("optional", False)),
                })
            for sub, submeta in (meta.get("dependencies") or {}).items():
                stack.append((cur_name, sub, submeta))
    return nodes


def _is_direct(pkg_json: dict, name: str) -> bool:
    if not isinstance(pkg_json, dict):
        return False
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        if name in (pkg_json.get(section) or {}):
            return True
    return False


def _import_pattern(name: str):
    esc = re.escape(name)
    return re.compile(
        r"from\s+['\"]" + esc + r"(?:/[^'\"]*)?['\"]"          # import ... from 'name'
        r"|require\(\s*['\"]" + esc + r"(?:/[^'\"]*)?['\"]\s*\)"  # require('name')
        r"|import\(\s*['\"]" + esc + r"(?:/[^'\"]*)?['\"]\s*\)"   # import('name')
    )


def _search_imports(repo_path: str, name: str, source_dirs) -> tuple:
    """Return (imported: bool, first_file). Scans only application source, read-only."""
    if not repo_path:
        return False, None
    pattern = _import_pattern(name)
    scanned = 0
    for root in source_dirs:
        base = os.path.join(repo_path, root)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in _SOURCE_EXT:
                    continue
                scanned += 1
                if scanned > _MAX_FILES:
                    return False, None
                full = os.path.join(dirpath, fn)
                try:
                    if os.path.getsize(full) > _MAX_FILE_BYTES:
                        continue
                    with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                        text = handle.read()
                except OSError:
                    continue
                if pattern.search(text):
                    return True, os.path.relpath(full, repo_path).replace("\\", "/")
    return False, None


def analyze_dependency(repo_path: str, name: str, source_dirs=DEFAULT_SOURCE_DIRS,
                       pkg_json: dict = None, lock: dict = None) -> DependencyFacts:
    """Classify a dependency by production/dev, direct/transitive, and reachability."""
    facts = DependencyFacts(package=name)
    if not name:
        facts.manifest_error = "No package name on the finding."
        facts.reachability_reason = facts.manifest_error
        return facts
    if pkg_json is None and lock is None:
        pkg_json, lock = load_manifests(repo_path)
    if not pkg_json and not lock:
        facts.manifest_error = "package.json / package-lock.json not found or unreadable."
        facts.reachability_reason = facts.manifest_error
        return facts

    nodes = _lock_nodes_for(lock, name) if lock else []
    facts.present_in_lock = bool(nodes)
    facts.installed_versions = sorted({n["version"] for n in nodes if n.get("version")})
    facts.parents = [n["path"] for n in nodes]

    if nodes:
        has_prod = any(not n["dev"] and not n["optional"] for n in nodes)
        if has_prod:
            facts.dependency_type = "production"
        elif all(n["optional"] for n in nodes):
            facts.dependency_type = "optional"
        else:
            facts.dependency_type = "development"
    facts.direct_or_transitive = "direct" if _is_direct(pkg_json, name) else (
        "transitive" if (facts.present_in_lock or pkg_json) else "unknown")

    if not facts.present_in_lock:
        facts.reachable = "not-applicable"
        facts.reachability_reason = (
            f"'{name}' is not present in package-lock.json; the advisory does not match any "
            "installed package in this project's dependency tree.")
        return facts
    if facts.dependency_type == "development":
        facts.reachable = "not-applicable"
        facts.reachability_reason = (
            f"'{name}' is a development-only dependency (package-lock dev:true) via "
            f"{', '.join(facts.parents[:4])}; it is not part of the production runtime by default.")
        return facts

    imported, where = _search_imports(repo_path, name, source_dirs)
    if imported:
        facts.reachable = "imported"
        facts.reachability_reason = (
            f"'{name}' is imported by application source at {where}.")
    else:
        facts.reachable = "not-imported"
        facts.reachability_reason = (
            f"'{name}' is a {facts.dependency_type} {facts.direct_or_transitive} dependency but "
            "is not imported directly by scanned application source; it is present transitively "
            f"({', '.join(facts.parents[:4])}). Exploitability depends on whether a parent "
            "package forwards untrusted input to it.")
    return facts
