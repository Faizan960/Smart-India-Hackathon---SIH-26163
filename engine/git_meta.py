"""Read git metadata from the target repository, without ever modifying it.

Uses ``git -C <repo>`` with argument arrays (never shell string concatenation),
so a repository path containing spaces is handled safely. Any failure returns
None values rather than raising — git metadata is best-effort context, not a
hard dependency.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Optional


def _git(repo_path: str, *args: str, timeout: int = 10) -> Optional[str]:
    if not shutil.which("git"):
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", repo_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None


def get_git_metadata(repo_path: str) -> dict:
    """Return {commit, branch, git_available}. Values are None when unavailable."""
    git_available = shutil.which("git") is not None
    return {
        "git_available": git_available,
        "commit": _git(repo_path, "rev-parse", "HEAD") if git_available else None,
        "branch": _git(repo_path, "branch", "--show-current") if git_available else None,
    }
