"""
SCA Scanner - Software Composition Analysis
Full transitive dependency resolution, SBOM generation, and dependency tracking.
"""

from __future__ import annotations
import os
import re
import json
from pathlib import Path
from typing import Dict, List, Optional

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.analysis.dep_graph import (
    DependencyResolver,
    SBOMGenerator,
    AIBOMGenerator,
    generate_dependency_graph,
)


class SCAScanner(BaseScanner):
    name = "sca"

    POPULAR_IMPERSONATION = {
        "django": ["djano", "djago", "djngi", "djinn", "donjo"],
        "requests": ["requesrs", "requsts", "reqeusts", "requrests"],
        "numpy": ["numby", "numpi", "numpt", "numpyy"],
        "pandas": ["pandass", "pandaas", "pnadas"],
        "flask": ["flaks", "flsk", "flace", "flaskr"],
        "tensorflow": ["tensorflw", "tensorfolw", "tennsorflow"],
        "pytest": ["pyetst", "pyets", "pytestt"],
    }

    KNOWN_MALICIOUS = {
        "emailvalidator": ["1.3.0", "1.3.1"],  # typosquatting
        " Colour": ["0.0.1"],  # space prefix
        "python-dateutil": ["2.8.0"],  # malicious after compromise
    }

    async def scan(self) -> list[ScannerResult]:
        if not self.path or not os.path.isdir(self.path):
            return []

        await self._scan_dependencies()
        await self._detect_typosquatting()
        await self._detect_dependency_confusion()
        await self._check_for_abandoned()

        return self.findings

    async def _scan_dependencies(self):
        """Scan for dependency files and analyze them."""
        dep_files = self._find_dependency_files()

        for dep_file in dep_files:
            await self._analyze_dependency_file(dep_file)

    def _find_dependency_files(self) -> List[str]:
        """Find all dependency manifest files in the project."""
        dep_files = []

        patterns = [
            "requirements*.txt",
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "Pipfile",
            "Pipfile.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "Cargo.lock",
            "composer.json",
        ]

        for root, dirs, files in os.walk(self.path):
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "__pycache__", "node_modules", "venv", ".venv"}
            ]

            for pattern in patterns:
                for file in files:
                    if self._match_pattern(file, pattern):
                        dep_files.append(os.path.join(root, file))

        return dep_files

    def _match_pattern(self, filename: str, pattern: str) -> bool:
        """Match filename against pattern."""
        if "*" in pattern:
            base = pattern.replace("*", "")
            return filename.startswith(base)
        return filename == pattern

    async def _analyze_dependency_file(self, dep_file: str):
        """Analyze a single dependency file."""
        rel_path = os.path.relpath(dep_file, self.path)

        try:
            graph = generate_dependency_graph(dep_file)

            dep_count = graph.get("total_count", 0)
            ai_packages = len(graph.get("ai_bom", {}).get("ai_packages", []))

            if dep_count > 100:
                self.add_finding(
                    title=f"Excessive dependencies: {dep_count} packages",
                    description=f"Found {dep_count} transitive dependencies. High dependency count increases attack surface.",
                    severity=Severity.MEDIUM,
                    evidence=f"Dependency file: {rel_path}",
                    location=rel_file,
                    fix="Audit dependencies. Remove unused ones. Consider alternatives with fewer deps.",
                    impact="Supply chain attack surface is proportional to dependency count.",
                )

            if ai_packages > 0:
                self.add_finding(
                    title=f"AI/ML packages detected: {ai_packages} packages",
                    description=f"Found {ai_packages} AI/ML dependencies requiring special security review.",
                    severity=Severity.INFO,
                    evidence=f"AI packages: {graph.get('ai_bom', {}).get('ai_packages', [])}",
                    location=rel_path,
                    fix="Review AI packages for model security, data handling, and API key exposure.",
                    impact="AI packages may handle sensitive data or execute untrusted code.",
                )

        except Exception as e:
            pass

    async def _detect_typosquatting(self):
        """Detect potential typosquatting attacks in dependencies."""
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file in ("requirements.txt", "package.json", "pyproject.toml"):
                    path = os.path.join(root, file)

                    try:
                        content = Path(path).read_text(
                            encoding="utf-8", errors="ignore"
                        )

                        for pkg, typos in self.POPULAR_IMPERSONATION.items():
                            for typo in typos:
                                if typo in content.lower():
                                    self.add_finding(
                                        title=f"Potential typosquatting: {typo}",
                                        description=f"'{typo}' looks like '{pkg}' - possible typosquatting attack",
                                        severity=Severity.HIGH,
                                        evidence=f"Found in {file}: {typo}",
                                        location=f"{file}",
                                        fix=f"Verify package name: should be '{pkg}' not '{typo}'",
                                        impact="Typosquatting packages may contain malicious code.",
                                    )
                    except Exception:
                        continue

    async def _detect_dependency_confusion(self):
        """Detect dependency confusion attacks."""
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file in ("requirements.txt", "package.json", "pyproject.toml"):
                    path = os.path.join(root, file)

                    try:
                        content = Path(path).read_text(
                            encoding="utf-8", errors="ignore"
                        )

                        private_patterns = [
                            r"--extra-index-url\s+https?://[^/]+/simple",
                            r"--index-url\s+https?://[^/]+/simple",
                            r"--find-links\s+https?://[^/]+",
                        ]

                        for pattern in private_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self.add_finding(
                                    title="Potential dependency confusion",
                                    description="Custom package index detected - verify it's not vulnerable to dependency confusion",
                                    severity=Severity.MEDIUM,
                                    evidence=f"Custom index URL in {file}",
                                    location=file,
                                    fix="Use internal package index with proper ownership verification",
                                    impact="Attacker could publish malicious package with same name on public index",
                                )
                    except Exception:
                        continue

    async def _check_for_abandoned(self):
        """Check for abandoned or unmaintained dependencies."""
        abandoned_patterns = [
            (r"django(?:-?(?:rest|allauth|cms|channels|contrib))?", "Django", "3.0"),
            (r"flask(?:-?(?:restful|login|sqlalchemy|wtf))?", "Flask", "2.0"),
            (r"requests(?:-?(?:oauth|async|cache))?", "requests", "2.28"),
        ]

        for root, dirs, files in os.walk(self.path):
            for file in files:
                if file in ("requirements.txt", "pyproject.toml", "package.json"):
                    path = os.path.join(root, file)

                    try:
                        content = Path(path).read_text(
                            encoding="utf-8", errors="ignore"
                        )

                        for pattern, pkg, min_ver in abandoned_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self.add_finding(
                                    title=f"Potentially outdated {pkg}",
                                    description=f"{pkg} version should be at least {min_ver}",
                                    severity=Severity.LOW,
                                    evidence=f"Found {pkg} in {file}",
                                    location=file,
                                    fix=f"Update {pkg} to latest version",
                                    impact="Older versions may have known vulnerabilities",
                                )
                    except Exception:
                        continue


def analyze_dependency_security(dependencies: List[Dict]) -> Dict[str, List[str]]:
    """Analyze dependencies for security issues."""
    issues = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for dep in dependencies:
        name = dep.get("name", "").lower()

        if dep.get("yanked"):
            issues["critical"].append(f"{name}: yanked version {dep.get('version')}")

        if dep.get("publish_date"):
            import time

            try:
                pub_time = time.mktime(time.strptime(dep["publish_date"], "%Y-%m-%d"))
                age_days = (time.time() - pub_time) / 86400
                if age_days > 365:
                    issues["medium"].append(
                        f"{name}: no updates in {int(age_days)} days"
                    )
            except Exception:
                pass

    return issues
