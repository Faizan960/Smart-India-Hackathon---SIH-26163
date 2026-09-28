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
