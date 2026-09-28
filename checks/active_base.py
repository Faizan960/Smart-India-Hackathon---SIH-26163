"""Shared plumbing for Phase-4 active verification probes.

Every active probe (CORS, rate-limit, auth/MCP, SSRF) targets the LOCAL running
application only. This module centralises two things they all need:

  * :func:`is_local_url` — the loopback allow-list. Active probes send real requests
    to the target, so they must refuse to run against a non-local host unless the run
    is explicitly configured to allow it.
  * :class:`ProbeVerdict` — the small, uniform object a probe's classifier returns:
    the verification *result* (confirmed / refuted / inconclusive / not_applicable),
    a human rationale, the severity to stamp on the finding, and any evidence to merge.
    The verifier turns this into a lifecycle transition via :mod:`engine.lifecycle`; a
    probe never sets a finding's status itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from engine.lifecycle import VERIFICATION_RESULTS

# The only hosts an active probe may target by default.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_local_url(url: str) -> bool:
    """True only for loopback targets (localhost / 127.0.0.1 / ::1)."""
    host = (urlparse(url).hostname or "").strip("[]").lower()
    return host in LOOPBACK_HOSTS


@dataclass
class ProbeVerdict:
    """A probe classifier's structured output; the verifier applies it to the finding."""

    result: str                       # one of engine.lifecycle.VERIFICATION_RESULTS
    rationale: str
    severity: str
    evidence: dict = field(default_factory=dict)
    remediation: str = ""

    def __post_init__(self) -> None:
        if self.result not in VERIFICATION_RESULTS:
            raise ValueError(
                f"Invalid verification result {self.result!r}; "
                f"expected one of {VERIFICATION_RESULTS}")
