"""Convert raw scanner/probe output into normalized Findings and assign stable IDs.

Scanners and probes emit raw structures; this module is the ONLY place that turns
them into Finding objects, maps severities, infers the affected asset, and assigns
the per-run human IDs (WT-SEM-0001, WT-HDR-0001). It never invents data — every
field is derived from what the tool actually reported.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Optional

from checks.security_headers import (
    REFERENCES as HEADER_REFERENCES,
    SECURITY_HEADERS,
    is_loopback,
)
from model.finding import AssetKind, Finding, Severity, Status
from engine.dedup import group_duplicates

_ID_PREFIX = {
    "semgrep": "SEM",
    "security-headers": "HDR",
    "gitleaks": "GLK",
    "osv-scanner": "OSV",
    "npm-audit": "NPM",
    "zap": "ZAP",
    "nuclei": "NUC",
}

_SEMGREP_SEVERITY = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Qualitative severities as reported by the ecosystems (GHSA / OSV database_specific).
_QUALITATIVE_SEVERITY = {
    "LOW": Severity.LOW,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}

# npm audit severities (moderate == our medium).
_NPM_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

# ZAP riskcode -> severity (3 High, 2 Medium, 1 Low, 0 Informational).
_ZAP_RISK = {3: Severity.HIGH, 2: Severity.MEDIUM, 1: Severity.LOW, 0: Severity.INFO}

# Nuclei info.severity -> severity ("unknown" carries no rating, so INFO).
_NUCLEI_SEVERITY = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}

_ID_RE = re.compile(r"(?:GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|CVE-\d{4}-\d+)", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _prefix_for(tool: str) -> str:
    alpha = "".join(c for c in tool.upper() if c.isalpha())
    return _ID_PREFIX.get(tool, alpha[:3] or "GEN")


def _parse_cwe(metadata: dict) -> Optional[str]:
    """Extract a CWE identifier only if the tool actually supplied one."""
    if not isinstance(metadata, dict):
        return None
    cwe = metadata.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if not cwe:
        return None
    match = re.search(r"CWE-\d+", str(cwe))
    return match.group(0) if match else None


def _infer_asset_kind(path: str) -> str:
    p = (path or "").lower().replace("\\", "/")
    if any(k in p for k in ("auth", "clerk", "session", "login", "oauth", "jwt")):
        return AssetKind.AUTHENTICATION
    if any(k in p for k in ("api-key", "api_key", "apikey")):
        return AssetKind.API_KEY
    if "mcp" in p:
        return AssetKind.MCP
    if p.startswith("api/") or "/api/" in p or p.startswith("server/") or "/server/" in p:
        return AssetKind.API
    if p.startswith("src/") or "/src/" in p:
        return AssetKind.UI
    return AssetKind.OTHER


def _relativize(path: str, repo_path: Optional[str]) -> str:
    if not path:
        return path
    if repo_path:
        try:
            rel = os.path.relpath(path, repo_path)
            if not rel.startswith(".."):
                return rel.replace("\\", "/")
        except ValueError:
            pass
    return path.replace("\\", "/")


def _cwe_from(value) -> Optional[str]:
    """Normalize a tool-provided CWE (str / list / 'cwe-79' / 693) to 'CWE-<n>'."""
    if value in (None, "", [], {}):
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value in (None, ""):
        return None
    text = str(value)
    match = re.search(r"CWE-\d+", text, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    if text.isdigit() and text != "0":
        return f"CWE-{text}"
    return None


def _extract_ids(*values) -> list:
    """Collect distinct GHSA-/CVE- identifiers from arbitrary strings/lists (upper-cased)."""
    found: list[str] = []
    stack = list(values)
    while stack:
        item = stack.pop(0)
        if item is None:
            continue
        if isinstance(item, (list, tuple)):
            stack.extend(item)
            continue
        for match in _ID_RE.findall(str(item)):
            token = match.upper()
            if token not in found:
                found.append(token)
    return found


def _endpoint_asset_kind(url: str) -> str:
    """Classify a URL-based finding's asset (API path vs. general UI)."""
    lowered = (url or "").lower()
    if "/api/" in lowered or lowered.rstrip("/").endswith("/api"):
        return AssetKind.API
    return AssetKind.UI


def normalize_semgrep(result, repo_path: Optional[str] = None) -> list[Finding]:
    """Map a SemgrepResult's parsed JSON into Findings (status: suspected)."""
    findings: list[Finding] = []
    if not result or not getattr(result, "parsed", None):
        return findings
    for item in result.parsed.get("results", []) or []:
        check_id = item.get("check_id") or "semgrep-rule"
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        raw_sev = str(extra.get("severity", "")).upper()
        severity = _SEMGREP_SEVERITY.get(raw_sev, Severity.INFO)
        rel = _relativize(item.get("path", ""), repo_path)
        line = (item.get("start", {}) or {}).get("line")
        refs = list(metadata.get("references", []) or [])
        source_url = metadata.get("source") or metadata.get("shortlink")
        if source_url and source_url not in refs:
            refs.append(source_url)
        findings.append(
            Finding(
                tool="semgrep",
                title=check_id.split(".")[-1],
                description=extra.get("message") or check_id,
                severity=severity,
                status=Status.SUSPECTED,
                cwe=_parse_cwe(metadata),
                file=rel,
                line=line,
                evidence={
                    "rule": check_id,
                    "raw_severity": raw_sev or None,
                    "location": f"{rel}:{line}" if line else rel,
                    "notes": (
                        "Single-source Semgrep static detection; not correlated or "
                        "verified. Full raw match is preserved in the run's evidence "
                        "store (raw/semgrep.json)."
                    ),
                },
                asset={"kind": _infer_asset_kind(rel), "ref": rel, "weight": 1.0},
                verification={
                    "method": "none",
                    "probe": None,
                    "result": None,
                    "rationale": "Static analysis result; not exercised against the running target.",
                    "timestamp": _now(),
                },
                references=refs,
            )
        )
    return findings


def normalize_headers(result) -> list[Finding]:
    """Map a HeadersProbeResult into Findings (status: verified via active probe).

    An unreachable target yields NO findings — absence of data is never turned
    into a fabricated result.
    """
    findings: list[Finding] = []
    if not result or not getattr(result, "reachable", False):
        return findings
    loopback_http = result.scheme == "http" and is_loopback(result.host)
    for header, missing_severity in SECURITY_HEADERS.items():
        value = result.headers.get(header)
        present = value is not None
        if present:
            severity, result_state = Severity.INFO, "refuted"
            rationale = f"Header present on {result.url}; missing-header concern refuted."
            desc = (
                f"{header} is present on the target response. Presence is informational; "
                "the correctness of the policy value is not assessed in this phase."
            )
        elif header == "Strict-Transport-Security" and loopback_http:
            severity, result_state = Severity.INFO, "not_applicable"
            rationale = (
                "HSTS cannot apply over plain HTTP on a loopback host; its absence here "
                "is expected and is not a weakness."
            )
            desc = (
                f"{header} is absent, but the target is plain HTTP on a loopback host, so "
                "HSTS does not apply. Recorded as informational, not a weakness."
            )
        else:
            severity, result_state = missing_severity, "confirmed"
            rationale = f"Header absent from the response on {result.url}."
            desc = (
                f"{header} is not set on the target response. A missing response-hardening "
                "header is a defense-in-depth gap, not necessarily an exploitable vulnerability."
            )
        findings.append(
            Finding(
                tool="security-headers",
                title=f"{header} assessment",
                description=desc,
                severity=severity,
                status=Status.VERIFIED,
                endpoint=result.url,
                evidence={
                    "header": header,
                    "present": present,
                    "value": value,
                    "status_code": result.status_code,
                    "response_time_ms": result.response_time_ms,
                },
                asset={"kind": AssetKind.UI, "ref": result.url, "weight": 1.0},
                verification={
                    "method": "active_probe",
                    "probe": "security-headers",
                    "result": result_state,
                    "rationale": rationale,
                    "timestamp": _now(),
                },
                references=list(HEADER_REFERENCES),
            )
        )
    return findings


def assign_ids(findings: list[Finding]) -> list[Finding]:
    """Assign deterministic per-run IDs (WT-<PREFIX>-####), stable for a given set.

    The stable identity is each finding's content fingerprint (also stored in
    evidence); the numeric label is derived by ordering a tool's findings by that
    fingerprint, so the same finding set always produces the same IDs.
    """
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        buckets.setdefault(_prefix_for(finding.tool), []).append(finding)
    for prefix, group in buckets.items():
        group.sort(key=lambda f: f.fingerprint())
        for index, finding in enumerate(group, start=1):
            finding.id = f"WT-{prefix}-{index:04d}"
            if isinstance(finding.evidence, dict):
                finding.evidence.setdefault("fingerprint", finding.fingerprint())
    return findings


def normalize(
    semgrep_result=None,
    headers_result=None,
    gitleaks_result=None,
    osv_result=None,
    npm_audit_result=None,
    zap_result=None,
    nuclei_result=None,
    repo_path: Optional[str] = None,
) -> list[Finding]:
    """Normalize every collector's output into Findings, dedup-tag, and assign IDs."""
    findings: list[Finding] = []
    if semgrep_result is not None:
        findings.extend(normalize_semgrep(semgrep_result, repo_path))
    if gitleaks_result is not None:
        findings.extend(normalize_gitleaks(gitleaks_result, repo_path))
    if osv_result is not None:
        findings.extend(normalize_osv(osv_result, repo_path))
    if npm_audit_result is not None:
        findings.extend(normalize_npm_audit(npm_audit_result, repo_path))
    if headers_result is not None:
        findings.extend(normalize_headers(headers_result))
    if zap_result is not None:
        findings.extend(normalize_zap(zap_result))
    if nuclei_result is not None:
        findings.extend(normalize_nuclei(nuclei_result))
    group_duplicates(findings)
    assign_ids(findings)
    return findings


def normalize_gitleaks(result, repo_path: Optional[str] = None) -> list[Finding]:
    """Map redacted Gitleaks entries into Findings (status: suspected).

    Secret values never reach here — the adapter redacted them. Severity is taken
    from a Gitleaks 'severity:<level>' rule tag when present, else recorded as
    tool-unspecified rather than invented.
    """
    findings: list[Finding] = []
    for entry in getattr(result, "parsed", None) or []:
        rule = entry.get("RuleID") or "secret"
        rel = _relativize(entry.get("File", ""), repo_path)
        severity, severity_source = Severity.INFO, "unspecified-by-tool"
        for tag in entry.get("Tags") or []:
            token = str(tag).lower()
            if token.startswith("severity:"):
                mapped = _QUALITATIVE_SEVERITY.get(token.split(":", 1)[1].strip().upper())
                if mapped:
                    severity, severity_source = mapped, "gitleaks-tag"
        findings.append(Finding(
            tool="gitleaks",
            title=f"Potential secret: {rule}",
            description=(
                f"Gitleaks matched rule '{rule}' in {rel or 'the repository'}. The secret "
                "value is redacted; only its presence and location are recorded."
            ),
            severity=severity,
            status=Status.SUSPECTED,
            file=rel or None,
            line=entry.get("StartLine"),
            evidence={
                "rule": rule,
                "description": entry.get("Description"),
                "match": "[REDACTED]",
                "secret_length": entry.get("SecretLength"),
                "entropy": entry.get("Entropy"),
                "commit": entry.get("Commit") or None,
                "tags": entry.get("Tags") or [],
                "severity_source": severity_source,
                "notes": "Value redacted at adapter; redacted tool output in raw/gitleaks.json.",
            },
            asset={"kind": _infer_asset_kind(rel), "ref": rel or "repository", "weight": 1.0},
            verification={
                "method": "none", "probe": None, "result": None,
                "rationale": "Static secret detection; not verified against a live secret store.",
                "timestamp": _now(),
            },
        ))
    return findings


def _osv_fixed_version(vuln: dict) -> Optional[str]:
    """Return the first 'fixed' version OSV lists for a vulnerability, if any."""
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if event.get("fixed"):
                    return event["fixed"]
    return None


def normalize_osv(result, repo_path: Optional[str] = None) -> list[Finding]:
    """Map OSV-Scanner output into dependency Findings (status: suspected)."""
    findings: list[Finding] = []
    parsed = getattr(result, "parsed", None) or {}
    for res in parsed.get("results", []) or []:
        source_path = _relativize((res.get("source") or {}).get("path", ""), repo_path)
        for pkg in res.get("packages", []) or []:
            package = pkg.get("package", {}) or {}
            name = package.get("name", "?")
            version = package.get("version", "?")
            ecosystem = package.get("ecosystem", "?")
            for vuln in pkg.get("vulnerabilities", []) or []:
                vid = vuln.get("id", "OSV")
                aliases = vuln.get("aliases", []) or []
                db = vuln.get("database_specific", {}) or {}
                severity = _QUALITATIVE_SEVERITY.get(str(db.get("severity", "")).upper(), Severity.INFO)
                sev_source = "osv-database_specific" if db.get("severity") else "unspecified-by-tool"
                refs = [r.get("url") for r in vuln.get("references", []) or [] if r.get("url")]
                findings.append(Finding(
                    tool="osv-scanner",
                    title=f"{vid}: {name} {version}",
                    description=(vuln.get("summary") or vuln.get("details") or vid)[:500],
                    severity=severity,
                    status=Status.SUSPECTED,
                    cwe=_cwe_from(db.get("cwe_ids")),
                    file=source_path or None,
                    evidence={
                        "vuln_id": vid,
                        "aliases": aliases,
                        "identifiers": _extract_ids(vid, aliases),
                        "package": name,
                        "ecosystem": ecosystem,
                        "installed_version": version,
                        "fixed_version": _osv_fixed_version(vuln),
                        "severity_source": sev_source,
                        "source_path": source_path or None,
                        "summary": vuln.get("summary"),
                    },
                    asset={"kind": AssetKind.OTHER, "ref": f"{ecosystem}:{name}@{version}", "weight": 1.0},
                    verification={
                        "method": "none", "probe": None, "result": None,
                        "rationale": "Dependency advisory reported by OSV; not exercised against the target.",
                        "timestamp": _now(),
                    },
                    references=refs,
                ))
    return findings


def _collect_npm_advisories(parsed: dict) -> list:
    """Collect unique npm advisory objects (dict 'via' entries) across the tree.

    npm audit lists the same root advisory under every affected package; de-duplicating
    by advisory URL/id here avoids emitting the same advisory many times.
    """
    advisories = []
    seen = set()
    for owner, entry in (parsed.get("vulnerabilities", {}) or {}).items():
        fix = entry.get("fixAvailable")
        for via in entry.get("via", []) or []:
            if not isinstance(via, dict):
                continue
            key = via.get("url") or via.get("source") or via.get("title")
            if key in seen:
                continue
            seen.add(key)
            advisories.append({"advisory": via, "fix": fix, "owner": owner})
    return advisories


def normalize_npm_audit(result, repo_path: Optional[str] = None) -> list[Finding]:
    """Map npm audit advisories into dependency Findings (status: suspected)."""
    findings: list[Finding] = []
    parsed = getattr(result, "parsed", None) or {}
    for record in _collect_npm_advisories(parsed):
        adv = record["advisory"]
        name = adv.get("name") or adv.get("dependency") or record["owner"]
        url = adv.get("url")
        severity = _NPM_SEVERITY.get(str(adv.get("severity", "")).lower(), Severity.INFO)
        sev_source = "npm-advisory" if adv.get("severity") else "unspecified-by-tool"
        fix = record["fix"]
        fix_version = fix.get("version") if isinstance(fix, dict) else None
        findings.append(Finding(
            tool="npm-audit",
            title=adv.get("title") or f"Advisory for {name}",
            description=(
                f"npm audit reports package '{name}' is affected"
                + (f" (vulnerable range {adv.get('range')})" if adv.get("range") else "")
                + ". Reported by npm audit; kept separate from any OSV finding for the same advisory."
            ),
            severity=severity,
            status=Status.SUSPECTED,
            cwe=_cwe_from(adv.get("cwe")),
            evidence={
                "package": name,
                "advisory_id": adv.get("source"),
                "identifiers": _extract_ids(url, adv.get("title")),
                "title": adv.get("title"),
                "url": url,
                "vulnerable_range": adv.get("range"),
                "severity_source": sev_source,
                "fix_available": fix,
                "fixed_version": fix_version,
            },
            asset={"kind": AssetKind.OTHER, "ref": f"npm:{name}", "weight": 1.0},
            verification={
                "method": "none", "probe": None, "result": None,
                "rationale": "Dependency advisory reported by npm audit; not exercised against the target.",
                "timestamp": _now(),
            },
            references=[url] if url else [],
        ))
    return findings


def _strip_html(text: str) -> str:
    """Collapse ZAP's HTML-formatted descriptions into plain text."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def normalize_zap(result) -> list[Finding]:
    """Map an OWASP ZAP baseline report into Findings (status: suspected)."""
    findings: list[Finding] = []
    parsed = getattr(result, "parsed", None) or {}
    for site in parsed.get("site", []) or []:
        site_name = site.get("@name") or site.get("@host") or ""
        for alert in site.get("alerts", []) or []:
            try:
                riskcode = int(alert.get("riskcode", -1))
            except (TypeError, ValueError):
                riskcode = -1
            severity = _ZAP_RISK.get(riskcode, Severity.INFO)
            instances = alert.get("instances", []) or []
            first = instances[0] if instances else {}
            endpoint = first.get("uri") or site_name
            cweid = alert.get("cweid")
            cwe = _cwe_from(cweid) if cweid not in (None, "", "-1", "0") else None
            reference = alert.get("reference")
            findings.append(Finding(
                tool="zap",
                title=alert.get("alert") or alert.get("name") or "ZAP alert",
                description=_strip_html(alert.get("desc") or "")[:800] or (alert.get("alert") or "ZAP alert"),
                severity=severity,
                status=Status.SUSPECTED,
                cwe=cwe,
                endpoint=endpoint,
                evidence={
                    "pluginid": alert.get("pluginid"),
                    "alertRef": alert.get("alertRef"),
                    "riskcode": alert.get("riskcode"),
                    "riskdesc": alert.get("riskdesc"),
                    "confidence": alert.get("confidence"),
                    "count": alert.get("count"),
                    "param": first.get("param"),
                    "evidence": first.get("evidence"),
                    "instance_count": len(instances),
                    "solution": _strip_html(alert.get("solution") or "")[:500] or None,
                },
                asset={"kind": _endpoint_asset_kind(endpoint), "ref": endpoint, "weight": 1.0},
                verification={
                    "method": "none", "probe": None, "result": None,
                    "rationale": "Passive ZAP baseline alert; a scanner rating, not a WATCHTOWER verification.",
                    "timestamp": _now(),
                },
                references=[reference] if reference else [],
            ))
    return findings


def normalize_nuclei(result) -> list[Finding]:
    """Map Nuclei JSONL findings into Findings (status: suspected)."""
    findings: list[Finding] = []
    for item in getattr(result, "parsed", None) or []:
        info = item.get("info", {}) or {}
        classification = info.get("classification", {}) or {}
        severity = _NUCLEI_SEVERITY.get(str(info.get("severity", "")).lower(), Severity.INFO)
        endpoint = item.get("matched-at") or item.get("host") or ""
        template_id = item.get("template-id") or "nuclei"
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        cve = classification.get("cve-id")
        findings.append(Finding(
            tool="nuclei",
            title=info.get("name") or template_id,
            description=(info.get("description") or info.get("name") or template_id)[:800],
            severity=severity,
            status=Status.SUSPECTED,
            cwe=_cwe_from(classification.get("cwe-id")),
            endpoint=endpoint or None,
            evidence={
                "template_id": template_id,
                "template_name": info.get("name"),
                "severity_source": "nuclei-template" if info.get("severity") else "unspecified-by-tool",
                "raw_severity": info.get("severity"),
                "matched_at": item.get("matched-at"),
                "matcher_name": item.get("matcher-name"),
                "extracted_results": item.get("extracted-results"),
                "type": item.get("type"),
                "identifiers": _extract_ids(cve),
                "tags": info.get("tags"),
            },
            asset={"kind": _endpoint_asset_kind(endpoint), "ref": endpoint or template_id, "weight": 1.0},
            verification={
                "method": "none", "probe": None, "result": None,
                "rationale": "Nuclei template match; a scanner rating, not a WATCHTOWER verification.",
                "timestamp": _now(),
            },
            references=list(refs),
        ))
    return findings
