"""WATCHTOWER — run configuration and version constant."""
from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

WATCHTOWER_VERSION = "0.1.0"

DEFAULT_OUTPUT_DIR = "./output"
DEFAULT_SEMGREP_TIMEOUT = 600  # seconds
DEFAULT_REQUEST_TIMEOUT = 10   # seconds
DEFAULT_TOOL_TIMEOUT = 300     # gitleaks / osv / npm audit (seconds)
DEFAULT_ZAP_TIMEOUT = 900      # ZAP baseline can take several minutes
DEFAULT_NUCLEI_TIMEOUT = 600   # controlled Nuclei template run
DEFAULT_RATE_LIMIT_COUNT = 10  # bounded, non-abusive request burst
DEFAULT_CANARY_PORT = 9001     # loopback-only SSRF canary port

# Internal WATCHTOWER component versions, recorded in the reproducibility manifest
# (Phase 5, item 8). These are OUR probe/analysis versions — not the external tool
# versions, which we deliberately do not shell out to collect.
PROBE_VERSIONS = {
    "attack-surface": "1", "security-headers": "1", "cors": "1", "rate-limit": "1",
    "auth-mcp": "1", "ssrf": "1", "correlator": "1", "verifier": "1",
    "evidence-graph": "1", "explainer": "1", "scorer": "watchtower-risk-score-v1",
}
# External scanners WATCHTOWER can orchestrate (versions not collected to avoid
# running tools purely for --version; execution status is recorded instead).
SCANNER_TOOLS = ("semgrep", "gitleaks", "osv-scanner", "npm-audit", "zap", "nuclei")


class ConfigError(Exception):
    """Raised when the run configuration is invalid."""


@dataclass
class WatchtowerConfig:
    """Validated inputs for a single WATCHTOWER run."""

    repo_path: str
    target_url: str
    output_dir: str = DEFAULT_OUTPUT_DIR
    semgrep_timeout: int = DEFAULT_SEMGREP_TIMEOUT
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    gitleaks_timeout: int = DEFAULT_TOOL_TIMEOUT
    osv_timeout: int = DEFAULT_TOOL_TIMEOUT
    npm_audit_timeout: int = DEFAULT_TOOL_TIMEOUT
    zap_timeout: int = DEFAULT_ZAP_TIMEOUT
    nuclei_timeout: int = DEFAULT_NUCLEI_TIMEOUT
    skip_semgrep: bool = False
    skip_headers: bool = False
    skip_gitleaks: bool = False
    skip_osv: bool = False
    skip_npm_audit: bool = False
    skip_zap: bool = False
    skip_nuclei: bool = False
    # Phase 5 — static attack-surface discovery (read-only).
    skip_attack_surface: bool = False
    # Phase 4 — active verification probes (local target only).
    skip_cors: bool = False
    skip_rate_limit: bool = False
    skip_auth_mcp: bool = False
    skip_ssrf: bool = False
    rate_limit_count: int = DEFAULT_RATE_LIMIT_COUNT
    canary_port: int = DEFAULT_CANARY_PORT
    # Safety gate: active probes refuse a non-local target unless this is explicitly set.
    allow_nonlocal_active: bool = False
    # Phase 5: optional baseline report.json to diff this run against (read-only).
    diff_against: str | None = None

    def validate(self) -> "WatchtowerConfig":
        """Fail fast on bad input before any tool runs."""
        if not self.repo_path or not os.path.isdir(self.repo_path):
            raise ConfigError(
                f"Repository path does not exist or is not a directory: {self.repo_path!r}"
            )

        parsed = urlparse(self.target_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ConfigError(
                f"Invalid target URL: {self.target_url!r} (expected http(s)://host[:port])"
            )

        if not 1 <= int(self.rate_limit_count) <= 25:
            raise ConfigError(
                f"rate_limit_count must be between 1 and 25 (bounded, non-abusive): "
                f"{self.rate_limit_count!r}"
            )
        if not 1 <= int(self.canary_port) <= 65535:
            raise ConfigError(f"canary_port out of range: {self.canary_port!r}")

        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as exc:
            raise ConfigError(
                f"Cannot create output directory {self.output_dir!r}: {exc}"
            ) from exc

        return self

    @property
    def normalized_target(self) -> str:
        """Target URL without a trailing slash (probes append their own path)."""
        return self.target_url.rstrip("/")

    @property
    def target_is_local(self) -> bool:
        """True only for loopback targets — the default gate for active probes."""
        host = (urlparse(self.target_url).hostname or "").strip("[]").lower()
        return host in {"localhost", "127.0.0.1", "::1"}

    def config_manifest(self) -> dict:
        """Sanitised configuration for the reproducibility manifest (no secrets)."""
        return {
            "target": self.normalized_target,
            "output_dir": self.output_dir,
            "timeouts": {
                "semgrep": self.semgrep_timeout, "request": self.request_timeout,
                "gitleaks": self.gitleaks_timeout, "osv": self.osv_timeout,
                "npm_audit": self.npm_audit_timeout, "zap": self.zap_timeout,
                "nuclei": self.nuclei_timeout,
            },
            "skips": {
                "attack_surface": self.skip_attack_surface, "semgrep": self.skip_semgrep,
                "gitleaks": self.skip_gitleaks, "osv": self.skip_osv,
                "npm_audit": self.skip_npm_audit, "headers": self.skip_headers,
                "zap": self.skip_zap, "nuclei": self.skip_nuclei, "cors": self.skip_cors,
                "rate_limit": self.skip_rate_limit, "auth_mcp": self.skip_auth_mcp,
                "ssrf": self.skip_ssrf,
            },
            "rate_limit_count": self.rate_limit_count,
            "canary_port": self.canary_port,
            "allow_nonlocal_active": self.allow_nonlocal_active,
            "target_is_local": self.target_is_local,
        }
