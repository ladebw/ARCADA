"""
ARCADA Orchestrator
Routes input to appropriate scanners, runs them in parallel,
and feeds results to the AI reasoning engine.
"""

from __future__ import annotations
import asyncio
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from arcada.models import AuditReport, AuditRequest, ScannerResult, Severity
from arcada.reasoning import ReasoningEngine
from arcada.scanners import (
    ALL_SCANNERS,
    SCANNER_MAP,
    DEEP_SCANNERS,
    DEEP_SCANNER_MAP,
    FAST_SCANNERS,
    FAST_SCANNER_MAP,
)
from arcada.github_clone import is_github_url, clone_repo, cleanup_repo

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from arcada.scanners.base import BaseScanner

# File extensions to collect when auditing a directory
SCANNABLE_EXTENSIONS = {
    # Python
    ".py",
    # JavaScript / TypeScript
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    # Go
    ".go",
    # Rust
    ".rs",
    # Java
    ".java",
    # Config / Build files
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
    ".json",
    ".env",
    ".sh",
    ".bash",
    "Dockerfile",
    "docker-compose.yml",
    ".tf",
    ".hcl",  # Terraform
    # Dependency files
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
}

MAX_FILE_SIZE = 500_000  # 500KB per file
MAX_FILES = 500  # Max files to scan per directory
MAX_TOTAL_SIZE = 50_000_000  # 50MB aggregate size
MAX_CONCURRENT_SCANNERS = 20
BATCH_SIZE = int(os.environ.get("ARCADA_BATCH_SIZE", "50"))


def detect_target_type(target: str) -> str:
    """Auto-detect what kind of target was provided."""
    if os.path.isdir(target):
        return "directory"
    if os.path.isfile(target):
        name = Path(target).name.lower()
        suffix = Path(target).suffix.lower()
        if name in (
            "requirements.txt",
            "requirements-dev.txt",
            "requirements.in",
            "pyproject.toml",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.mod",
            "go.sum",
            "cargo.toml",
            "cargo.lock",
            "gemfile",
            "gemfile.lock",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "composer.json",
            "composer.lock",
            "pipfile",
            "setup.py",
        ):
            return "dependencies"
        if name in ("dockerfile",) or suffix in (".dockerfile",):
            return "docker"
        if suffix in (".yaml", ".yml", ".toml", ".json", ".tf", ".hcl"):
            return "config"
        return "code"
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    # Treat as inline content
    if len(target) > 100:
        return "code"
    return "unknown"


def collect_files(directory: str) -> list[tuple[str, str]]:
    """Walk a directory and collect (path, content) for scannable files.
    Caps at MAX_FILES files and MAX_TOTAL_SIZE aggregate bytes."""
    SKIP_DIRS = {
        ".git",
        "node_modules",
        "__pycache__",
        "venv",
        ".venv",
        "dist",
        "build",
        "vendor",
    }
    results = []
    total_size = 0
    base = Path(directory)
    for path in base.rglob("*"):
        if len(results) >= MAX_FILES:
            break
        if total_size >= MAX_TOTAL_SIZE:
            break
        if path.is_file():
            parts = path.parts
            dir_parts = parts[len(base.parts) : -1]
            if any(d.startswith(".") for d in dir_parts):
                continue
            if any(d in SKIP_DIRS for d in dir_parts):
                continue
            if (
                path.suffix.lower() in SCANNABLE_EXTENSIONS
                or path.name in SCANNABLE_EXTENSIONS
            ):
                try:
                    file_size = path.stat().st_size
                    if file_size > MAX_FILE_SIZE:
                        continue
                    if total_size + file_size > MAX_TOTAL_SIZE:
                        continue
                    content = path.read_text(encoding="utf-8", errors="replace")
                    results.append((str(path), content))
                    total_size += file_size
                except (PermissionError, OSError):
                    continue
    return results


async def run_scanner(
    scanner_cls: type,
    content: str,
    path: str,
    metadata: dict,
) -> list[ScannerResult]:
    """Run a single scanner and return its findings."""
    try:
        scanner = scanner_cls(content=content, path=path, metadata=metadata)
        return await scanner.scan()
    except Exception as e:
        # Never let a scanner crash the whole audit
        return [
            ScannerResult(
                scanner=scanner_cls.name,
                title=f"Scanner error: {scanner_cls.name}",
                description=f"Scanner failed with error: {e}",
                severity=Severity.LOW,
                evidence=str(e),
            )
        ]


class Orchestrator:
    def __init__(self):
        self.engine = ReasoningEngine()

    async def audit(self, request: AuditRequest) -> AuditReport:
        """Main entry point — run full audit pipeline."""
        target = request.target
        target_type = request.target_type

        if target_type == "auto":
            target_type = detect_target_type(target)

        # Clone GitHub repos to temp directory
        repo_dir = None
        if is_github_url(target):
            repo_dir = clone_repo(target)
            target = repo_dir
            target_type = "directory"

        try:
            return await self._run_audit(
                request, target, target_type, scanner_classes_override=None
            )
        finally:
            if repo_dir:
                cleanup_repo(repo_dir)

    async def _run_audit(
        self,
        request: AuditRequest,
        target: str,
        target_type: str,
        scanner_classes_override: list | None = None,
    ) -> AuditReport:
        """Internal audit pipeline."""
        # Determine scanner classes to use
        if request.scanners:
            scanner_classes = [
                SCANNER_MAP[s] for s in request.scanners if s in SCANNER_MAP
            ]
        elif scanner_classes_override:
            scanner_classes = scanner_classes_override
        else:
            # Always use FAST_SCANNERS for project code scanning
            # Deep scans add dependency scanning on top of this
            scanner_classes = FAST_SCANNERS

        # Collect all (path, content) pairs to scan (async to avoid blocking event loop)
        file_pairs: list[tuple[str, str]] = []

        if target_type == "directory":
            file_pairs = await asyncio.to_thread(collect_files, target)
        elif target_type in ("code", "dependencies", "docker", "config"):
            if os.path.isfile(target):
                content = Path(target).read_text(encoding="utf-8", errors="replace")
                file_pairs = [(target, content)]
            else:
                # Inline content
                file_pairs = [("<inline>", target)]
        elif target_type == "url":
            content = await self._fetch_url(target)
            file_pairs = [(target, content)]
        else:
            # Treat as raw inline content
            file_pairs = [("<inline>", target)]

        # Run all scanners on all files concurrently with a semaphore limit
        # Process in batches to avoid task explosion (thousands of tasks at once)
        all_findings: list[ScannerResult] = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANNERS)

        async def run_scanner_limited(scanner_cls, content, path, metadata):
            async with semaphore:
                await asyncio.sleep(0)  # Yield to event loop for CPU-bound scanners
                return await run_scanner(scanner_cls, content, path, metadata)

        # Process files in batches
        for i in range(0, len(file_pairs), BATCH_SIZE):
            batch = file_pairs[i : i + BATCH_SIZE]
            tasks = [
                run_scanner_limited(
                    scanner_cls,
                    content,
                    path,
                    {
                        "target_type": target_type,
                        "path": path,
                        "file_pairs": file_pairs,
                    },
                )
                for path, content in batch
                for scanner_cls in scanner_classes
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)

        # Deduplicate identical findings
        all_findings = self._deduplicate(all_findings)

        # Send to DeepSeek for AI-powered analysis
        max_findings = (
            request.max_findings_per_call if request.max_findings_per_call > 0 else None
        )
        report = await self.engine.analyze(
            all_findings, target, target_type, max_findings
        )
        return report

    def _deduplicate(self, findings: list[ScannerResult]) -> list[ScannerResult]:
        """Remove duplicate findings (same title)."""
        seen = set()
        unique = []
        for f in findings:
            key = f.title
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    async def deep_audit(self, request: AuditRequest) -> AuditReport:
        """Deep audit: scan project code + installed dependency source + metadata."""
        import importlib.metadata

        target = request.target
        target_type = request.target_type

        if target_type == "auto":
            target_type = detect_target_type(target)

        # Clone GitHub repos to temp directory
        repo_dir = None
        if is_github_url(target):
            repo_dir = clone_repo(target)
            target = repo_dir
            target_type = "directory"

        try:
            return await self._run_deep_audit(request, target, target_type)
        finally:
            if repo_dir:
                cleanup_repo(repo_dir)

    async def _run_deep_audit(
        self, request: AuditRequest, target: str, target_type: str
    ) -> AuditReport:
        """Internal deep audit pipeline."""
        import importlib.metadata

        # Phase 1: Run normal audit on project code
        report = await self._run_audit(request, target, target_type)
        all_findings = list(report.raw_scanner_results)

        # Phase 2: Resolve installed packages to scan
        packages = self._get_packages_to_scan(request)

        # Phase 3: Scan installed package source code through existing scanners
        dep_source = DEEP_SCANNER_MAP["dep_source"]
        scanner = dep_source(content="", path=target, metadata={"packages": packages})
        dep_findings = await scanner.scan()
        all_findings.extend(dep_findings)

        # Phase 4: Check package metadata via PyPI/npm APIs
        meta_scanner_cls = DEEP_SCANNER_MAP["package_metadata"]
        pkg_tuples = [(name, ver) for name, ver, _ in packages]
        meta_scanner = meta_scanner_cls(
            content="", path=target, metadata={"packages": pkg_tuples}
        )
        meta_findings = await meta_scanner.scan()
        all_findings.extend(meta_findings)

        # Phase 5: Behavioral analysis of installed packages
        PACKAGE_TIMEOUT = 30
        behavior_scanner_cls = DEEP_SCANNER_MAP["dep_behavior"]
        for name, version, pkg_path in packages[:50]:
            try:
                async with asyncio.timeout(PACKAGE_TIMEOUT):
                    bh_scanner = behavior_scanner_cls(
                        content="",
                        path="",
                        metadata={
                            "pkg_path": pkg_path,
                            "package": name,
                            "version": version,
                        },
                    )
                    bh_findings = await bh_scanner.scan()
                    all_findings.extend(bh_findings)
            except asyncio.TimeoutError:
                logger.warning(
                    f"Timeout scanning package {name} ({version}) after {PACKAGE_TIMEOUT}s"
                )
                continue
            except Exception:
                continue

        # Phase 6: Deduplicate + AI reasoning
        all_findings = self._deduplicate(all_findings)
        max_findings = (
            request.max_findings_per_call if request.max_findings_per_call > 0 else None
        )
        report = await self.engine.analyze(
            all_findings, target, target_type, max_findings
        )
        report.raw_scanner_results = all_findings
        return report

    def _get_packages_to_scan(
        self, request: AuditRequest
    ) -> list[tuple[str, str, str]]:
        """Resolve which installed packages to scan. Returns (name, version, path)."""
        import importlib.metadata

        results = []
        if request.packages:
            # Only scan specified packages
            for pkg_name in request.packages:
                try:
                    dist = importlib.metadata.distribution(pkg_name)
                    name = dist.metadata.get("Name", pkg_name)
                    version = dist.metadata.get("Version", "0.0.0")
                    loc = str(dist._path.parent) if hasattr(dist, "_path") else ""
                    if loc:
                        results.append((name, version, loc))
                except importlib.metadata.PackageNotFoundError:
                    continue
        else:
            # Scan all installed packages
            for dist in importlib.metadata.distributions():
                name = dist.metadata.get("Name", "unknown")
                version = dist.metadata.get("Version", "0.0.0")
                loc = str(dist._path.parent) if hasattr(dist, "_path") else ""
                if loc and name != "arcada":
                    results.append((name, version, loc))
        return results

    async def _fetch_url(self, url: str) -> str:
        """Fetch content from a URL for auditing."""
        import httpx

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.text
