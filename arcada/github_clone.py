"""
GitHub Repository Cloning Utility
Clones public GitHub repos to temp directories for scanning.
"""

from __future__ import annotations
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse


def is_github_url(url: str) -> bool:
    """Check if a URL is a GitHub repository URL."""
    url = url.strip()
    if url.startswith("git@github.com:"):
        path = url.replace("git@github.com:", "")
        parts = path.split("/")
        return len(parts) >= 1 and len(parts[0]) > 0
    parsed = urlparse(url)
    return (
        parsed.hostname in ("github.com", "www.github.com")
        and len(parsed.path.strip("/").split("/")) >= 2
    )


def parse_github_url(url: str) -> tuple[str, str | None]:
    """Parse a GitHub URL and return (clone_url, branch_or_None).

    Supported formats:
      https://github.com/user/repo
      https://github.com/user/repo/
      https://github.com/user/repo/tree/main
      https://github.com/user/repo/tree/feature/branch-name
      git@github.com:user/repo.git
    """
    url = url.strip().rstrip("/")

    # SSH format
    if url.startswith("git@github.com:"):
        path = url.replace("git@github.com:", "").removesuffix(".git")
        return f"https://github.com/{path}.git", None

    parsed = urlparse(url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        raise ValueError(f"Not a GitHub URL: {url}")

    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid GitHub URL (need user/repo): {url}")

    user = parts[0]
    repo = parts[1]

    branch = None
    if len(parts) >= 4 and parts[2] == "tree":
        branch = "/".join(parts[3:])  # Support branch names with /

    clone_url = f"https://github.com/{user}/{repo}.git"
    return clone_url, branch


def clone_repo(url: str, timeout: int = 120) -> str:
    """Clone a public GitHub repo to a temp directory.

    Returns: path to the cloned directory.
    Caller is responsible for cleanup via cleanup_repo().

    Raises:
        ValueError: if not a valid GitHub URL
        subprocess.TimeoutExpired: if clone takes too long
        subprocess.CalledProcessError: if git clone fails
    """
    clone_url, branch = parse_github_url(url)
    tmpdir = tempfile.mkdtemp(prefix="arcada_scan_")

    cmd = ["git", "clone", "--depth", "1", "--single-branch"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [clone_url, tmpdir]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        cleanup_repo(tmpdir)
        raise subprocess.CalledProcessError(
            result.returncode, cmd, result.stdout, result.stderr
        )

    return tmpdir


def cleanup_repo(path: str):
    """Remove a cloned temp directory."""
    shutil.rmtree(path, ignore_errors=True)
