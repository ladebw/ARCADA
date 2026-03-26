"""
Tests for GitHub clone utility and web frontend.
"""

from __future__ import annotations
import pytest
from arcada.github_clone import parse_github_url, is_github_url


# ---------- URL Parsing ----------


def test_is_github_url_https():
    assert is_github_url("https://github.com/user/repo") is True
    assert is_github_url("https://github.com/user/repo/tree/main") is True


def test_is_github_url_not_github():
    assert is_github_url("https://gitlab.com/user/repo") is False
    assert is_github_url("https://example.com") is False
    assert is_github_url("not a url") is False


def test_parse_simple_url():
    clone_url, branch = parse_github_url("https://github.com/user/repo")
    assert clone_url == "https://github.com/user/repo.git"
    assert branch is None


def test_parse_url_with_trailing_slash():
    clone_url, branch = parse_github_url("https://github.com/user/repo/")
    assert clone_url == "https://github.com/user/repo.git"
    assert branch is None


def test_parse_url_with_branch():
    clone_url, branch = parse_github_url("https://github.com/user/repo/tree/main")
    assert clone_url == "https://github.com/user/repo.git"
    assert branch == "main"


def test_parse_url_with_slash_branch():
    clone_url, branch = parse_github_url(
        "https://github.com/user/repo/tree/feature/xyz"
    )
    assert clone_url == "https://github.com/user/repo.git"
    assert branch == "feature/xyz"


def test_parse_ssh_url():
    clone_url, branch = parse_github_url("git@github.com:user/repo.git")
    assert clone_url == "https://github.com/user/repo.git"
    assert branch is None


def test_parse_invalid_url():
    with pytest.raises(ValueError):
        parse_github_url("https://gitlab.com/user/repo")


def test_parse_too_short_url():
    with pytest.raises(ValueError):
        parse_github_url("https://github.com/user")


# ---------- Clone + Cleanup ----------


def test_clone_and_cleanup():
    """Clone a small public repo, verify it has files, then cleanup."""
    from arcada.github_clone import clone_repo, cleanup_repo
    import os

    repo_dir = clone_repo("https://github.com/kelseyhightower/nocode")
    assert os.path.isdir(repo_dir)
    assert os.path.isfile(os.path.join(repo_dir, "README.md"))
    cleanup_repo(repo_dir)
    assert not os.path.isdir(repo_dir)
