"""
Scanner 1: Dependency Analysis
Detects unpinned, suspicious, or known-vulnerable dependencies.
Supports Python, npm, Go, Rust, Java, Ruby, PHP ecosystems.
"""

from __future__ import annotations
import re
import json
import subprocess
import tempfile
import logging
from pathlib import Path
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.ecosystem_parsers import (
    parse_dependency_file,
    detect_ecosystem,
    PARSERS,
)
from arcada.scanners.osv_integration import (
    query_osv_batch,
    format_osv_finding,
)

logger = logging.getLogger(__name__)

# Known AI/LLM-related packages that warrant extra scrutiny
AI_PACKAGES = {
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-openai",
    "openai",
    "anthropic",
    "llama-index",
    "llama_index",
    "llamaindex",
    "autogen",
    "pyautogen",
    "crewai",
    "haystack-ai",
    "guidance",
    "outlines",
    "instructor",
    "litellm",
    "groq",
    "cohere",
    "together",
    "transformers",
    "sentence-transformers",
    "faiss-cpu",
    "faiss-gpu",
    "chromadb",
    "weaviate-client",
    "pinecone-client",
    "qdrant-client",
    "mcp",
    "model-context-protocol",
    "agentops",
    "langfuse",
    "mlflow",
    "dspy-ai",
    "smolagents",
    "pydantic-ai",
}

# Typosquatting targets (common misspellings of popular packages)
TYPOSQUAT_TARGETS = {
    "requets": "requests",
    "reqests": "requests",
    "requsets": "requests",
    "numpY": "numpy",
    "numPy": "numpy",
    "panads": "pandas",
    "openia": "openai",
    "open-ai": "openai",
    "langchin": "langchain",
    "antropic": "anthropic",
    "antrhopic": "anthropic",
    "pydantics": "pydantic",
    "pytoch": "torch",
    "tensrflow": "tensorflow",
    "fasapi": "fastapi",
    "fast-api": "fastapi",
}


class DependencyScanner(BaseScanner):
    name = "dependency"

    async def scan(self) -> list[ScannerResult]:
        self._detect_unpinned()
        self._detect_ai_packages()
        self._detect_typosquatting()
        self._detect_git_dependencies()
        self._detect_local_path_dependencies()
        self._detect_transitive_deps()
        self._detect_npm_lock_scripts()
        self._detect_go_risks()
        self._detect_rust_risks()
        self._detect_java_risks()
        await self._run_osv_audit()
        await self._run_pip_audit()
        return self.findings

    def _parse_deps(self) -> list[tuple[str, str, str]]:
        """Parse dependencies using ecosystem parsers. Returns [(name, version_spec, ecosystem)]."""
        deps = parse_dependency_file(self.path, self.content)
        if deps:
            return deps
        # Fallback to legacy Python-only parsers
        py_deps = self._parse_requirements() or self._parse_pyproject()
        return [(name, spec, "python") for name, spec in py_deps]

    def _parse_requirements(self) -> list[tuple[str, str]]:
        """Parse requirements.txt style lines. Returns [(name, version_spec)]."""
        deps = []
        for line in self.content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Strip extras like package[extra]
            match = re.match(r"^([A-Za-z0-9_\-\.]+)(\[.*?\])?(.*)?$", line)
            if match:
                name = match.group(1).lower()
                spec = (match.group(3) or "").strip()
                deps.append((name, spec))
        return deps

    def _parse_pyproject(self) -> list[tuple[str, str]]:
        """Parse dependencies from pyproject.toml content."""
        deps = []
        in_deps = False
        for line in self.content.splitlines():
            stripped = line.strip()
            # Reset when entering a new TOML section
            if stripped.startswith("["):
                in_deps = False
            if "[project.dependencies]" in line or "dependencies = [" in line:
                in_deps = True
                continue
            if in_deps and (stripped.startswith('"') or stripped.startswith("'")):
                pkg_line = stripped.strip('"').strip("'").strip(",")
                match = re.match(r"^([A-Za-z0-9_\-\.]+)(.*)?$", pkg_line)
                if match:
                    deps.append(
                        (match.group(1).lower(), (match.group(2) or "").strip())
                    )
        return deps

    def _detect_unpinned(self):
        deps = self._parse_deps()
        for name, spec, ecosystem in deps:
            if not spec or spec in ("", "*"):
                self.add_finding(
                    title=f"Unpinned dependency: {name}",
                    description=(
                        f"The package '{name}' has no version constraint. "
                        "This means any update — including malicious ones — "
                        "will be silently installed."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"{name}{spec or ''}",
                    fix=f"Pin to a specific version ({ecosystem} ecosystem)",
                    impact="Attacker can push a malicious update that gets auto-installed.",
                )
            elif spec.startswith(">=") and not re.search(r",\s*<", spec):
                self.add_finding(
                    title=f"Loosely pinned dependency: {name}",
                    description=(
                        f"'{name}{spec}' allows any future major version. "
                        "A compromised release could be pulled automatically."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"{name}{spec}",
                    fix=f"Add an upper bound: {name}{spec},<next_major",
                    impact="Future compromised versions are automatically trusted.",
                )
            elif ecosystem == "npm" and spec in ("*", "latest"):
                self.add_finding(
                    title=f"Unpinned npm dependency: {name}@{spec}",
                    description=(
                        f"'{name}@{spec}' allows any version. "
                        "A compromised release will be installed automatically."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"{name}@{spec}",
                    fix=f"Pin to exact version: {name}@<exact-version>",
                    impact="Attacker pushes malicious npm update, auto-installed on next npm install.",
                )

    def _detect_ai_packages(self):
        deps = self._parse_deps()
        found = [name for name, _, _ in deps if name in AI_PACKAGES]
        for pkg in found:
            self.add_finding(
                title=f"AI/LLM library detected: {pkg}",
                description=(
                    f"'{pkg}' is an AI/LLM-related package. These libraries "
                    "often make outbound API calls, may log prompts/responses, "
                    "and have rapidly changing attack surfaces."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Dependency: {pkg}",
                fix=(
                    "Audit all API calls made by this library. "
                    "Verify it does not send prompts to unintended endpoints. "
                    "Review their data retention and logging policies."
                ),
                impact="Prompts and responses may be exfiltrated or logged by the library.",
            )

    def _detect_typosquatting(self):
        deps = self._parse_deps()
        for name, _, ecosystem in deps:
            if name.lower() in TYPOSQUAT_TARGETS:
                intended = TYPOSQUAT_TARGETS[name.lower()]
                self.add_finding(
                    title=f"Possible typosquatting: {name}",
                    description=(
                        f"'{name}' looks like a misspelling of '{intended}'. "
                        "Typosquatted packages often contain malware."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Found: {name} — did you mean: {intended}?",
                    fix=f"Replace '{name}' with '{intended}' and verify the package on PyPI.",
                    impact="Package may be malware designed to steal credentials or execute backdoors.",
                )

    def _detect_git_dependencies(self):
        matches = self.grep_lines(r"git\+https?://|git\+ssh://|@git\+")
        for lineno, line in matches:
            has_ref = re.search(r"@[a-f0-9]{40}|@v?\d+\.\d+", line)
            self.add_finding(
                title="Git dependency without commit hash"
                if not has_ref
                else "Git dependency (review recommended)",
                description=(
                    "Installing from a git URL pulls live code that can change at any time. "
                    + (
                        "No commit hash is pinned — this is especially dangerous."
                        if not has_ref
                        else "A ref is pinned but branches/tags can be moved."
                    )
                ),
                severity=Severity.HIGH if not has_ref else Severity.MEDIUM,
                evidence=f"Line {lineno}: {line}",
                fix="Pin to a specific commit SHA: git+https://...@<40-char-sha>",
                impact="Maintainer or attacker can push malicious code that gets installed silently.",
            )

    def _detect_local_path_dependencies(self):
        matches = self.grep_lines(r"^\s*(file://|\.\.?/|/[^/])")
        for lineno, line in matches:
            self.add_finding(
                title="Local path dependency",
                description=(
                    "A local path dependency is used. This bypasses PyPI security "
                    "scanning and may include development code or secrets."
                ),
                severity=Severity.LOW,
                evidence=f"Line {lineno}: {line}",
                fix="Publish the package to a private registry and depend on it properly.",
                impact="Dev-only code or secrets in local packages may reach production.",
            )

    # Known-malicious packages (blocklist)
    BLOCKLISTED = {
        "event-stream",
        "flatmap-stream",
        "ua-parser-js",
        "colors-1.4.0",
        "faker-1.4.0",
        "coa-2.0.3",
        "rc-1.2.9",
        "peacenotwar",
        "node-ipc",
        "noblox.js-proxy",
    }

    def _detect_transitive_deps(self):
        """Resolve transitive dependencies and check for known-malicious packages."""
        import importlib.metadata

        top_level = self._parse_requirements() or self._parse_pyproject()
        visited = set()
        queue = [name for name, _ in top_level]

        while queue:
            pkg = queue.pop(0)
            pkg = pkg.lower().replace("-", "_")
            if pkg in visited:
                continue
            visited.add(pkg)
            try:
                dist = importlib.metadata.distribution(pkg)
                requires = dist.requires or []
                deps = []
                for req in requires:
                    # Parse: "package-name (>=1.0) ; extra == 'dev'"
                    dep_name = re.split(r"[;(\s<>=!~\[]", req)[0].strip().lower()
                    if dep_name:
                        deps.append(dep_name)
                        queue.append(dep_name)

                # Check blocklist
                if pkg in self.BLOCKLISTED:
                    self.add_finding(
                        title=f"KNOWN MALICIOUS transitive dependency: {pkg}",
                        description=(
                            f"'{pkg}' is on the known-malicious package blocklist. "
                            "This package has been involved in documented supply-chain attacks."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=f"Transitive dependency '{pkg}' matched blocklist.",
                        fix="Remove immediately. Run a full system audit. Check npm advisories.",
                        impact="Known backdoor — data theft, crypto mining, or credential exfiltration.",
                    )

                # Check for abandoned transitive deps (>3 years old)
                version = dist.metadata.get("Version", "")
                if self._is_abandoned(pkg, version):
                    self.add_finding(
                        title=f"Abandoned transitive dependency: {pkg} v{version}",
                        description=(
                            f"Transitive dependency '{pkg}' (v{version}) appears abandoned. "
                            "Abandoned packages are prime targets for maintainer account takeover."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"Package '{pkg}' version {version}",
                        fix=f"Consider replacing '{pkg}' with an actively maintained alternative.",
                        impact="Compromised abandoned package affects all dependents.",
                    )

            except importlib.metadata.PackageNotFoundError:
                self.add_finding(
                    title=f"Missing transitive dependency: {pkg}",
                    description=(
                        f"Transitive dependency '{pkg}' is referenced but not installed. "
                        "This could indicate dependency confusion — a public package "
                        "with the same name as a private/internal package."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Package '{pkg}' not found in installed packages.",
                    fix="Verify this is not a private package name collision. Use a private registry.",
                    impact="Dependency confusion — pip may install a malicious public package.",
                )

    def _is_abandoned(self, pkg_name: str, version: str) -> bool:
        """Heuristic: check if package version suggests abandonment."""
        # Simple heuristic: version is 0.0.x or very old-style
        if version.startswith("0.0.") or version.startswith("0.1."):
            return True
        return False

    def _detect_npm_lock_scripts(self):
        """Parse package-lock.json or yarn.lock for install scripts in transitive deps."""
        if "package-lock" not in self.path and "yarn.lock" not in self.path:
            return

        if "package-lock" in self.path:
            try:
                data = json.loads(self.content)
                # v2/v3 format
                packages = data.get("packages", {})
                # v1 format
                deps = data.get("dependencies", {})

                for pkg_path, info in {**packages, **deps}.items():
                    scripts = info.get("scripts", {})
                    dangerous = {"preinstall", "postinstall", "install"}
                    found = dangerous & set(scripts.keys())
                    if found:
                        pkg_name = (
                            pkg_path.replace("node_modules/", "")
                            if pkg_path
                            else "root"
                        )
                        self.add_finding(
                            title=f"npm transitive dep has install script: {pkg_name}",
                            description=(
                                f"Transitive npm dependency '{pkg_name}' has install-time "
                                f"scripts: {found}. These execute automatically during npm install."
                            ),
                            severity=Severity.CRITICAL,
                            evidence=f"Package: {pkg_name}, Scripts: {json.dumps({k: scripts[k] for k in found})}",
                            fix="Audit the script source. Use npm install --ignore-scripts.",
                            impact="Arbitrary code execution on every machine that installs this dependency.",
                        )
            except (json.JSONDecodeError, KeyError):
                pass

        if "yarn.lock" in self.path:
            # Check for postinstall/preinstall in yarn.lock entries
            for lineno, line in self.grep_lines(r'"(?:pre|post)install"'):
                self.add_finding(
                    title="yarn.lock contains install script reference",
                    description=(
                        "An install script reference was found in yarn.lock. "
                        "These scripts execute on every yarn install."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit the script. Use yarn install --ignore-scripts.",
                    impact="Shell command execution on developer/CI machines.",
                )

    def _detect_go_risks(self):
        """Detect Go-specific dependency risks."""
        if not self.path or not self.path.lower().endswith((".go", "go.mod", "go.sum")):
            return
        deps = self._parse_deps()
        for name, version, ecosystem in deps:
            if ecosystem != "go":
                continue
            # Check for modules without version pinning
            if not version:
                self.add_finding(
                    title=f"Unpinned Go module: {name}",
                    description=(
                        f"Go module '{name}' has no version pinned. "
                        "Run 'go mod tidy' and ensure go.sum has integrity hashes."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Module: {name}",
                    fix="Pin to a specific version in go.mod and verify go.sum hashes.",
                    impact="Attacker can push a malicious version that gets installed.",
                )
            # Check for modules using replace directive with local path
            if re.search(rf"replace\s+{re.escape(name)}\s+=>\s+\./", self.content):
                self.add_finding(
                    title=f"Go module replaced with local path: {name}",
                    description=(
                        f"Module '{name}' is replaced with a local path. "
                        "Local replacements bypass Go module verification."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"replace {name} => ./...",
                    fix="Publish the local module and use a proper version reference.",
                    impact="Local code may contain unverified or development-only changes.",
                )

    def _detect_rust_risks(self):
        """Detect Rust-specific dependency risks."""
        if not self.path or not self.path.lower().endswith((".toml", ".lock")):
            return
        deps = self._parse_deps()
        for name, version, ecosystem in deps:
            if ecosystem != "rust":
                continue
            if not version:
                self.add_finding(
                    title=f"Unpinned Rust crate: {name}",
                    description=(
                        f"Rust crate '{name}' has no version constraint. "
                        "Any version including malicious ones can be pulled."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Crate: {name}",
                    fix=f'Pin to a specific version: {name} = "<version>"',
                    impact="Malicious crate update auto-installed.",
                )
            # Check for git dependencies in Cargo.toml
            if re.search(rf"{re.escape(name)}\s*=\s*\{{\s*git\s*=", self.content):
                self.add_finding(
                    title=f"Rust git dependency: {name}",
                    description=(
                        f"Crate '{name}' is sourced from git. "
                        "Without a pinned revision, any pushed change is included."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"{name} = {{ git = ... }}",
                    fix="Pin to a specific commit: rev = '<commit-hash>'",
                    impact="Attacker pushes malicious code to the git repo.",
                )

    def _detect_java_risks(self):
        """Detect Java/Maven/Gradle-specific dependency risks."""
        if not self.path or not self.path.lower().endswith((".xml", ".gradle", ".kts")):
            return
        deps = self._parse_deps()
        for name, version, ecosystem in deps:
            if ecosystem != "java":
                continue
            if not version or version == "LATEST" or version == "RELEASE":
                self.add_finding(
                    title=f"Unpinned Java dependency: {name}",
                    description=(
                        f"Java dependency '{name}' has version '{version or 'none'}'. "
                        "Dynamic versions pull whatever is latest, including compromised releases."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Dependency: {name} version={version or 'none'}",
                    fix="Pin to a specific version number.",
                    impact="Compromised latest release auto-installed.",
                )
            # Check for SNAPSHOT versions
            if version and "SNAPSHOT" in version.upper():
                self.add_finding(
                    title=f"SNAPSHOT dependency: {name}",
                    description=(
                        f"Dependency '{name}' uses a SNAPSHOT version. "
                        "SNAPSHOTs are mutable and may contain unstable or malicious code."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"{name}:{version}",
                    fix="Use a stable release version in production.",
                    impact="Unstable code or injected malicious code from snapshot repository.",
                )

    async def _run_osv_audit(self):
        """Query OSV.dev for known vulnerabilities across all ecosystems."""
        deps = self._parse_deps()
        if not deps:
            return
        try:
            vuln_results = await query_osv_batch(deps)
            for (name, version), vulns in vuln_results.items():
                for vuln in vulns:
                    info = format_osv_finding(vuln)
                    sev = (
                        Severity(info["severity"].lower())
                        if info["severity"].lower()
                        in ("critical", "high", "medium", "low")
                        else Severity.HIGH
                    )
                    self.add_finding(
                        title=f"{info['id']} in {name}@{version}",
                        description=info["description"],
                        severity=sev,
                        evidence=f"{name}@{version} — {info['id']}",
                        fix=f"Upgrade to fixed version(s): {', '.join(info['fix_versions']) if info['fix_versions'] else 'see advisory'}. {info['references']}",
                        impact="Known vulnerability that may be actively exploited.",
                    )
        except Exception as e:
            logger.debug(f"OSV audit failed: {e}")

    async def _run_pip_audit(self):
        """Run pip-audit on requirements content if available (Python-only fallback)."""
        if not self.content.strip():
            return
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                f.write(self.content)
                tmp_path = f.name

            result = subprocess.run(
                ["pip-audit", "-r", tmp_path, "--format", "json", "--skip-editable"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.stdout:
                data = json.loads(result.stdout)
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        self.add_finding(
                            title=f"Known CVE in {dep['name']}: {vuln['id']}",
                            description=vuln.get(
                                "description", "No description available."
                            ),
                            severity=Severity.CRITICAL,
                            evidence=f"{dep['name']}=={dep.get('version', '?')} — {vuln['id']}",
                            fix=f"Upgrade to a fixed version. See: {', '.join(vuln.get('fix_versions', ['unknown']))}",
                            impact="Known vulnerability that may be actively exploited.",
                        )
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        finally:
            if tmp_path:
                try:
                    Path(tmp_path).unlink(missing_ok=True)
                except Exception:
                    pass
