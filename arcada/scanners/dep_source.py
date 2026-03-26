"""
Scanner 11: Deep Dependency Source Code Analysis
Enumerates installed packages, reads their source files,
and runs existing scanners against each dependency's code.
"""

from __future__ import annotations
import os
import importlib.metadata
from pathlib import Path
from arcada.scanners.base import BaseScanner
from arcada.models import PackageFinding, ScannerResult, Severity

MAX_FILE_SIZE = 500_000
SCAN_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".sh",
    ".go",
    ".rs",
    ".java",
}

# Scanners to run against dependency source code (exclude self + dep_source to avoid recursion)
_DEFERRED_SCANNERS = None


def _get_scanner_classes():
    global _DEFERRED_SCANNERS
    if _DEFERRED_SCANNERS is None:
        from arcada.scanners import ALL_SCANNERS

        _DEFERRED_SCANNERS = [
            s
            for s in ALL_SCANNERS
            if s.name
            not in (
                "dep_source",
                "package_metadata",
                "dep_behavior",
                "dependency",
            )
        ]
    return _DEFERRED_SCANNERS


class DepSourceScanner(BaseScanner):
    name = "dep_source"

    async def scan(self) -> list[ScannerResult]:
        packages = self.metadata.get("packages", [])
        if not packages:
            packages = self._get_all_installed()
        for pkg_name, pkg_version, pkg_path in packages:
            py_files = self._collect_files(pkg_path)
            for file_path, content in py_files:
                await self._scan_file(pkg_name, pkg_version, file_path, content)
        return self.findings

    def _get_all_installed(self) -> list[tuple[str, str, str]]:
        """Get all installed packages: (name, version, location)."""
        results = []
        for dist in importlib.metadata.distributions():
            name = dist.metadata.get("Name", "unknown")
            version = dist.metadata.get("Version", "0.0.0")
            loc = str(dist._path.parent) if hasattr(dist, "_path") else ""
            if loc:
                results.append((name, version, loc))
        return results

    def _collect_files(self, pkg_path: str) -> list[tuple[str, str]]:
        """Collect scannable files from a package directory."""
        results = []
        base = Path(pkg_path)
        if not base.is_dir():
            return results
        skip_dirs = {"__pycache__", ".git", "node_modules", "test", "tests", "docs"}
        for path in base.rglob("*"):
            if path.is_file():
                parts = path.parts
                if any(p in skip_dirs for p in parts):
                    continue
                if path.suffix.lower() in SCAN_EXTENSIONS:
                    try:
                        if path.stat().st_size > MAX_FILE_SIZE:
                            continue
                        content = path.read_text(encoding="utf-8", errors="replace")
                        results.append((str(path), content))
                    except (PermissionError, OSError):
                        continue
        return results

    async def _scan_file(
        self, pkg_name: str, pkg_version: str, file_path: str, content: str
    ):
        """Run all scanners against a single dependency source file."""
        scanner_classes = _get_scanner_classes()
        rel_path = file_path
        for scanner_cls in scanner_classes:
            try:
                scanner = scanner_cls(
                    content=content,
                    path=rel_path,
                    metadata={
                        "package": pkg_name,
                        "version": pkg_version,
                        "source": "dep_source",
                    },
                )
                sub_findings = await scanner.scan()
                for f in sub_findings:
                    pf = PackageFinding(
                        scanner=self.name,
                        title=f"Dependency backdoor signal in {pkg_name} v{pkg_version}: {f.title}",
                        description=(
                            f"Package '{pkg_name}' (v{pkg_version}) file {rel_path} "
                            f"contains a suspicious pattern detected by the '{f.scanner}' scanner.\n\n"
                            f"Original finding: {f.description}"
                        ),
                        severity=f.severity,
                        evidence=f"[{pkg_name} v{pkg_version}] {f.evidence}",
                        location=rel_path,
                        fix=f"Review the source of '{pkg_name}' v{pkg_version}. {f.fix}",
                        impact=f"Backdoor in a dependency affects all consumers. {f.impact}",
                        package_name=pkg_name,
                        package_version=pkg_version,
                        package_file=rel_path,
                    )
                    self.findings.append(pf)
            except Exception:
                continue
