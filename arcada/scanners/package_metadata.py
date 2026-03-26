"""
Scanner 12: Package Metadata Analysis
Queries PyPI, npm, crates.io, Go proxy, and Maven registries to detect
suspicious metadata signals indicative of supply-chain compromise or typosquatting.
"""

from __future__ import annotations
import asyncio
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import httpx

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.ecosystem_parsers import parse_dependency_file, detect_ecosystem

PYPI_API = "https://pypi.org/pypi/{pkg}/json"
NPM_API = "https://registry.npmjs.org/{pkg}"
CRATES_API = "https://crates.io/api/v1/crates/{pkg}"
GO_PROXY_API = "https://proxy.golang.org/{pkg}/@latest"
MAVEN_API = "https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json"
METADATA_SEMAPHORE = asyncio.Semaphore(5)

MALICIOUS_PACKAGES = {
    "event-stream",
    "flatmap-stream",
    "ua-parser-js-0.7.29",
    "colors-1.4.0",
    "faker-1.4.0",
    "coa-2.0.3",
    "rc-1.2.9",
    "peacenotwar",
    "node-ipc",
}


class PackageMetadataScanner(BaseScanner):
    name = "package_metadata"

    async def scan(self) -> list[ScannerResult]:
        packages = self.metadata.get("packages", [])
        if not packages:
            packages = self._parse_packages()
        tasks = []
        for pkg_info in packages:
            if isinstance(pkg_info, (list, tuple)):
                pkg_name, pkg_version = (
                    pkg_info[0],
                    pkg_info[1] if len(pkg_info) > 1 else "",
                )
                ecosystem = pkg_info[2] if len(pkg_info) > 2 else ""
            else:
                pkg_name, pkg_version, ecosystem = pkg_info, "", ""

            eco = ecosystem or self._detect_pkg_ecosystem(pkg_name)
            if eco == "npm":
                tasks.append(self._check_npm(pkg_name, pkg_version))
            elif eco == "python":
                tasks.append(self._check_pypi(pkg_name, pkg_version))
            elif eco == "rust":
                tasks.append(self._check_crates(pkg_name, pkg_version))
            elif eco == "go":
                tasks.append(self._check_go_proxy(pkg_name, pkg_version))
            elif eco == "java":
                tasks.append(self._check_maven(pkg_name, pkg_version))
            else:
                tasks.append(self._check_pypi(pkg_name, pkg_version))
        await asyncio.gather(*tasks, return_exceptions=True)
        return self.findings

    def _detect_pkg_ecosystem(self, pkg_name: str) -> str:
        """Detect ecosystem from package name and file path."""
        if pkg_name.startswith("@"):
            return "npm"
        if self.path:
            eco = detect_ecosystem(self.path, self.content)
            if eco != "unknown":
                return eco
        # Guess from name patterns
        if "/" in pkg_name and not pkg_name.startswith("@"):
            return "go"  # Go modules use domain/path format
        if ":" in pkg_name:
            return "java"  # Maven uses group:artifact
        return "python"  # Default

    def _parse_packages(self) -> list[tuple[str, str, str]]:
        """Parse package names from the content (any ecosystem). Returns [(name, version, ecosystem)]."""
        # Use ecosystem parsers first
        deps = parse_dependency_file(self.path, self.content)
        if deps:
            return deps
        # Fallback: regex-based parsing
        pkgs = []
        for line in self.content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            import re

            match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?(.*)?$", line)
            if match:
                pkgs.append(
                    (match.group(1).lower(), (match.group(2) or "").strip(), "python")
                )
        return pkgs

    def _is_npm(self, pkg_name: str) -> bool:
        """Heuristic: if the content file is package.json or name starts with @."""
        return pkg_name.startswith("@") or self.path.endswith("package.json")

    async def _check_pypi(self, pkg_name: str, pkg_version: str):
        """Query PyPI for a package and check 7 signals."""
        url = PYPI_API.format(pkg=pkg_name)
        try:
            async with METADATA_SEMAPHORE:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(url)
            if resp.status_code == 404:
                self.add_finding(
                    title=f"Package not found on PyPI: {pkg_name}",
                    description=(
                        f"'{pkg_name}' does not exist on PyPI. This could indicate "
                        "a private package, a typo, or dependency confusion."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"PyPI returned 404 for {pkg_name}",
                    fix="Verify the package name is correct. Use a private registry for internal packages.",
                    impact="Dependency confusion — pip may install a public package with the same name.",
                )
                return
            if resp.status_code != 200:
                return
            data = resp.json()
            info = data.get("info", {})
            releases = data.get("releases", {})

            # Check 1: Blocklist
            if pkg_name in MALICIOUS_PACKAGES:
                self.add_finding(
                    title=f"KNOWN MALICIOUS package: {pkg_name}",
                    description=f"'{pkg_name}' is on the known-malicious package blocklist.",
                    severity=Severity.CRITICAL,
                    evidence=f"Package '{pkg_name}' matched blocklist entry.",
                    fix="Remove immediately. Audit your system for compromise.",
                    impact="Known backdoor — data theft, credential exfiltration, or crypto mining.",
                )

            # Check 2: Package age
            if pkg_version and pkg_version in releases:
                release_files = releases[pkg_version]
                if release_files:
                    upload_time_str = release_files[0].get("upload_time", "")
                    if upload_time_str:
                        upload_time = datetime.fromisoformat(
                            upload_time_str.replace("Z", "+00:00")
                        )
                        age_days = (datetime.now(timezone.utc) - upload_time).days
                        if age_days < 30:
                            self.add_finding(
                                title=f"Very new package release: {pkg_name} v{pkg_version} ({age_days} days old)",
                                description=(
                                    f"Release v{pkg_version} of '{pkg_name}' was uploaded only "
                                    f"{age_days} days ago. New packages are higher risk for supply-chain attacks."
                                ),
                                severity=Severity.HIGH
                                if age_days < 7
                                else Severity.MEDIUM,
                                evidence=f"Uploaded: {upload_time_str}",
                                fix="Review the package source code before trusting it. Pin to a specific hash.",
                                impact="Recently uploaded packages have had less community scrutiny.",
                            )

            # Check 3: Single maintainer
            maintainer = info.get("maintainer", "")
            author = info.get("author", "")
            if maintainer and maintainer == author and not info.get("maintainer_email"):
                self.add_finding(
                    title=f"Single maintainer with no email: {pkg_name}",
                    description=(
                        f"'{pkg_name}' has only one maintainer/author. "
                        "Single-maintainer packages are a higher takeover risk."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Maintainer: {maintainer}",
                    fix="Vendor the package source. Consider alternatives with larger teams.",
                    impact="Account compromise of the single maintainer compromises all users.",
                )

            # Check 4: No source repository
            project_urls = info.get("project_urls") or {}
            has_source = any(
                k.lower() in ("source", "repository", "repo", "github", "source code")
                for k in project_urls
            )
            if not has_source and not info.get("home_page"):
                self.add_finding(
                    title=f"No source repository: {pkg_name}",
                    description=(
                        f"'{pkg_name}' has no linked source repository. "
                        "This makes independent auditing impossible."
                    ),
                    severity=Severity.LOW,
                    evidence="No 'Source' or 'Repository' in project_urls.",
                    fix="Only use packages with verifiable source repositories.",
                    impact="Cannot verify what code is actually installed.",
                )

            # Check 5: Missing/unknown transitive deps (requires_dist)
            requires = info.get("requires_dist") or []
            for req in requires:
                dep_name = (
                    req.split(";")[0]
                    .split()[0]
                    .split(">")[0]
                    .split("<")[0]
                    .split("=")[0]
                    .split("!")[0]
                    .strip()
                    .lower()
                )
                if dep_name and dep_name not in MALICIOUS_PACKAGES:
                    try:
                        import importlib.metadata

                        importlib.metadata.distribution(dep_name)
                    except importlib.metadata.PackageNotFoundError:
                        # This is normal for optional deps, check if it has extras marker
                        if "; extra ==" not in req.lower():
                            pass  # Will be caught by transitive dep scanner

        except (
            httpx.TimeoutException,
            httpx.HTTPError,
            json.JSONDecodeError,
            Exception,
        ):
            pass

    async def _check_crates(self, pkg_name: str, pkg_version: str):
        """Query crates.io for a Rust crate."""
        url = CRATES_API.format(pkg=pkg_name)
        try:
            async with METADATA_SEMAPHORE:
                async with httpx.AsyncClient(
                    timeout=15.0,
                    headers={"User-Agent": "ARCADA-Security-Scanner/1.0"},
                ) as client:
                    resp = await client.get(url)
            if resp.status_code == 404:
                self.add_finding(
                    title=f"Crate not found on crates.io: {pkg_name}",
                    description=f"'{pkg_name}' does not exist on crates.io.",
                    severity=Severity.HIGH,
                    evidence=f"crates.io returned 404 for {pkg_name}",
                    fix="Verify the crate name. Check for typosquatting.",
                    impact="May be a non-existent crate or dependency confusion.",
                )
                return
            if resp.status_code != 200:
                return
            data = resp.json().get("crate", {})

            # Check 1: Package age
            created = data.get("created_at", "")
            if created:
                create_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - create_dt).days
                if age_days < 30:
                    self.add_finding(
                        title=f"Very new Rust crate: {pkg_name} ({age_days} days old)",
                        severity=Severity.HIGH if age_days < 7 else Severity.MEDIUM,
                        evidence=f"Created: {created}",
                        fix="Review source code before trusting.",
                        impact="New crates have had less community scrutiny.",
                    )

            # Check 2: Download count (very low = suspicious)
            recent_downloads = data.get("recent_downloads", 0)
            total_downloads = data.get("downloads", 0)
            if total_downloads < 100 and age_days and age_days > 30:
                self.add_finding(
                    title=f"Low-download Rust crate: {pkg_name} ({total_downloads} total downloads)",
                    description=(
                        f"'{pkg_name}' has very few downloads ({total_downloads}). "
                        "Low-popularity packages are less scrutinized and higher risk."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Total downloads: {total_downloads}",
                    fix="Verify the crate source and maintainer before use.",
                    impact="Low-visibility packages may contain undetected vulnerabilities or backdoors.",
                )

            # Check 3: Deprecated
            if data.get("max_version") and data.get("max_stable_version"):
                latest = data.get("max_stable_version", "")
                max_ver = data.get("max_version", "")
                if latest and max_ver and max_ver > latest:
                    pass  # Pre-release, fine

        except (
            httpx.TimeoutException,
            httpx.HTTPError,
            json.JSONDecodeError,
            Exception,
        ):
            pass

    async def _check_go_proxy(self, pkg_name: str, pkg_version: str):
        """Query Go proxy for a Go module."""
        # Go module names are often like github.com/user/repo
        url = GO_PROXY_API.format(pkg=pkg_name.replace("@", "/"))
        try:
            async with METADATA_SEMAPHORE:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(url)
            if resp.status_code == 404 or resp.status_code == 410:
                self.add_finding(
                    title=f"Go module not found on proxy: {pkg_name}",
                    description=(
                        f"'{pkg_name}' was not found on the Go module proxy. "
                        "This could indicate a private module, a typo, or dependency confusion."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Go proxy returned {resp.status_code} for {pkg_name}",
                    fix="Verify the module path. Use a private Go proxy for internal modules.",
                    impact="Dependency confusion — go get may fetch a malicious module.",
                )
                return
            if resp.status_code != 200:
                return
            data = resp.json()
            version = data.get("Version", "")
            timestamp = data.get("Time", "")
            if timestamp:
                try:
                    ts_dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - ts_dt).days
                    if age_days < 30:
                        self.add_finding(
                            title=f"Very new Go module version: {pkg_name}@{version} ({age_days} days old)",
                            severity=Severity.HIGH if age_days < 7 else Severity.MEDIUM,
                            evidence=f"Version {version} published: {timestamp}",
                            fix="Review the module source before trusting.",
                            impact="New versions have had less community scrutiny.",
                        )
                except (ValueError, TypeError):
                    pass
        except (
            httpx.TimeoutException,
            httpx.HTTPError,
            json.JSONDecodeError,
            Exception,
        ):
            pass

    async def _check_maven(self, pkg_name: str, pkg_version: str):
        """Query Maven Central for a Java dependency."""
        if ":" not in pkg_name:
            return
        parts = pkg_name.split(":", 1)
        group_id, artifact_id = parts[0], parts[1]
        url = MAVEN_API.format(group=group_id, artifact=artifact_id)
        try:
            async with METADATA_SEMAPHORE:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(url)
            if resp.status_code != 200:
                return
            data = resp.json()
            docs = data.get("response", {}).get("docs", [])
            if not docs:
                self.add_finding(
                    title=f"Java dependency not found on Maven Central: {pkg_name}",
                    description=f"'{pkg_name}' was not found on Maven Central.",
                    severity=Severity.HIGH,
                    evidence=f"Maven Central search returned 0 results for {pkg_name}",
                    fix="Verify the groupId:artifactId. Check for typosquatting.",
                    impact="May be a non-existent artifact or from a private repository.",
                )
                return
            latest_version = docs[0].get("latestVersion", "")
            timestamp = docs[0].get("timestamp", 0)
            if timestamp:
                try:
                    ts_dt = datetime.fromtimestamp(timestamp / 1000, tz=timezone.utc)
                    age_days = (datetime.now(timezone.utc) - ts_dt).days
                    if age_days < 30:
                        self.add_finding(
                            title=f"Recently updated Maven artifact: {pkg_name} (latest: {latest_version})",
                            severity=Severity.MEDIUM,
                            evidence=f"Latest version: {latest_version}, timestamp: {ts_dt.isoformat()}",
                            fix="Review the artifact changes before upgrading.",
                            impact="Recently updated artifacts may have introduced vulnerabilities or malicious code.",
                        )
                except (ValueError, TypeError):
                    pass
        except (
            httpx.TimeoutException,
            httpx.HTTPError,
            json.JSONDecodeError,
            Exception,
        ):
            pass

    async def _check_npm(self, pkg_name: str, pkg_version: str):
        """Query npm registry for a package and check 5 signals."""
        url = NPM_API.format(pkg=pkg_name)
        try:
            async with METADATA_SEMAPHORE:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.get(url)
            if resp.status_code == 404:
                self.add_finding(
                    title=f"Package not found on npm: {pkg_name}",
                    description=f"'{pkg_name}' does not exist on npm registry.",
                    severity=Severity.HIGH,
                    evidence=f"npm returned 404 for {pkg_name}",
                    fix="Verify the package name. Check for typosquatting.",
                    impact="May be a non-existent package or dependency confusion attack.",
                )
                return
            if resp.status_code != 200:
                return
            data = resp.json()

            # Check 1: Known malicious
            if pkg_name in MALICIOUS_PACKAGES:
                self.add_finding(
                    title=f"KNOWN MALICIOUS npm package: {pkg_name}",
                    severity=Severity.CRITICAL,
                    evidence=f"Package '{pkg_name}' is on the known-malicious blocklist.",
                    fix="Remove immediately and audit your system.",
                    impact="Known backdoor or supply-chain attack.",
                )

            # Check 2: Package age
            time_info = data.get("time", {})
            created = time_info.get("created", "")
            if created:
                create_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age_days = (datetime.now(timezone.utc) - create_dt).days
                if age_days < 30:
                    self.add_finding(
                        title=f"Very new npm package: {pkg_name} ({age_days} days old)",
                        severity=Severity.HIGH if age_days < 7 else Severity.MEDIUM,
                        evidence=f"Created: {created}",
                        fix="Review source code before trusting. Pin exact versions.",
                        impact="New packages have had less community scrutiny.",
                    )

            # Check 3: Deprecated
            latest_version = data.get("dist-tags", {}).get("latest", "")
            if latest_version:
                version_info = data.get("versions", {}).get(latest_version, {})
                if version_info.get("deprecated"):
                    self.add_finding(
                        title=f"Deprecated npm package: {pkg_name}",
                        description=f"'{pkg_name}' latest version is deprecated: {version_info['deprecated']}",
                        severity=Severity.MEDIUM,
                        evidence=f"Deprecated: {version_info['deprecated']}",
                        fix="Find an actively maintained alternative.",
                        impact="Deprecated packages may receive malicious maintainers.",
                    )

            # Check 4: Install scripts in any version
            for ver, ver_data in data.get("versions", {}).items():
                scripts = ver_data.get("scripts", {})
                dangerous_scripts = {"preinstall", "postinstall", "install"}
                found_scripts = dangerous_scripts & set(scripts.keys())
                if found_scripts:
                    self.add_finding(
                        title=f"npm install scripts in {pkg_name}@{ver}: {', '.join(found_scripts)}",
                        description=(
                            f"'{pkg_name}' version {ver} has install-time scripts: "
                            f"{found_scripts}. These execute automatically on npm install."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=f"Scripts: {json.dumps({k: scripts[k] for k in found_scripts})}",
                        fix="Audit the script source. Use --ignore-scripts during install.",
                        impact="Arbitrary code execution on every developer/CI machine that installs this.",
                    )
                    break  # Only report once per package

            # Check 5: Single maintainer
            maintainers = data.get("maintainers", [])
            if len(maintainers) == 1:
                self.add_finding(
                    title=f"Single npm maintainer: {pkg_name}",
                    description=(
                        f"'{pkg_name}' has only 1 npm maintainer: {maintainers[0].get('name', 'unknown')}. "
                        "This is a single point of compromise."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Maintainer: {maintainers[0].get('name', 'unknown')}",
                    fix="Vendor the source. Consider alternatives with larger teams.",
                    impact="npm account takeover compromises the package for all consumers.",
                )

        except (
            httpx.TimeoutException,
            httpx.HTTPError,
            json.JSONDecodeError,
            Exception,
        ):
            pass
