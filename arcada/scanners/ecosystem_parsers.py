"""
Multi-ecosystem dependency parsers.
Parses dependency files from Python, Node.js, Go, Rust, Java (Maven/Gradle), Ruby, and PHP.
Returns normalized (name, version_spec) tuples for each ecosystem.
"""

from __future__ import annotations
import re
import json
import tomllib
from pathlib import Path


def detect_ecosystem(path: str, content: str) -> str:
    """Detect which ecosystem a dependency file belongs to."""
    name = Path(path).name.lower() if path else ""
    if name in (
        "requirements.txt",
        "requirements-dev.txt",
        "requirements.in",
        "pyproject.toml",
        "setup.cfg",
        "setup.py",
        "Pipfile",
    ):
        return "python"
    if name in (
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        ".npmrc",
    ):
        return "npm"
    if name == "go.mod":
        return "go"
    if name in ("cargo.toml", "cargo.lock"):
        return "rust"
    if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return "java"
    if name in ("gemfile", "gemfile.lock"):
        return "ruby"
    if name in ("composer.json", "composer.lock"):
        return "php"
    if name == "csproj" or name.endswith(".csproj"):
        return "dotnet"
    # Fallback content-based detection
    if content and "module " in content[:200] and "require " in content:
        return "go"
    return "unknown"


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------


def parse_requirements(content: str) -> list[tuple[str, str, str]]:
    """Parse requirements.txt. Returns [(name, version_spec, ecosystem)]."""
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:\[.*?\])?(.*)?$", line)
        if match:
            name = match.group(1).lower()
            spec = (match.group(2) or "").strip()
            deps.append((name, spec, "python"))
    return deps


def parse_pyproject(content: str) -> list[tuple[str, str, str]]:
    """Parse pyproject.toml [project.dependencies] and [tool.poetry.dependencies]."""
    deps = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return _parse_pyproject_regex(content)

    # PEP 621 style
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep in project_deps:
        match = re.match(r"^([A-Za-z0-9_\-\.]+)(.*)?$", dep)
        if match:
            deps.append(
                (match.group(1).lower(), (match.group(2) or "").strip(), "python")
            )

    # Poetry style
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, str):
            deps.append((name.lower(), spec, "python"))
        elif isinstance(spec, dict):
            version = spec.get("version", "")
            deps.append((name.lower(), version, "python"))

    return deps


def _parse_pyproject_regex(content: str) -> list[tuple[str, str, str]]:
    """Fallback regex parser for pyproject.toml when tomllib fails."""
    deps = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
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
                    (match.group(1).lower(), (match.group(2) or "").strip(), "python")
                )
    return deps


def parse_pipfile(content: str) -> list[tuple[str, str, str]]:
    """Parse Pipfile for dependencies."""
    deps = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return deps
    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                deps.append((name.lower(), spec, "python"))
            elif isinstance(spec, dict):
                deps.append((name.lower(), spec.get("version", ""), "python"))
    return deps


# ---------------------------------------------------------------------------
# npm / Node.js
# ---------------------------------------------------------------------------


def parse_package_json(content: str) -> list[tuple[str, str, str]]:
    """Parse package.json dependencies."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        for name, version in data.get(section, {}).items():
            deps.append((name, version, "npm"))
    return deps


def parse_package_lock(content: str) -> list[tuple[str, str, str]]:
    """Parse package-lock.json (v1, v2, v3 formats)."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    # v2/v3: packages dict
    for pkg_path, info in data.get("packages", {}).items():
        if not pkg_path or pkg_path == "":
            continue
        name = pkg_path.replace("node_modules/", "")
        version = info.get("version", "")
        deps.append((name, version, "npm"))
    # v1: dependencies dict
    for name, info in data.get("dependencies", {}).items():
        version = info.get("version", "")
        deps.append((name, version, "npm"))
    return deps


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------


def parse_go_mod(content: str) -> list[tuple[str, str, str]]:
    """Parse go.mod require blocks."""
    deps = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if stripped == ")" and in_require:
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            cleaned = stripped.replace("require ", "").strip()
            match = re.match(r"^([^\s]+)\s+(v[\d\.]+[^\s]*)", cleaned)
            if match:
                deps.append((match.group(1), match.group(2), "go"))
            elif cleaned and not cleaned.startswith("//"):
                # Module without version (rare)
                parts = cleaned.split()
                if len(parts) >= 1:
                    deps.append((parts[0], parts[1] if len(parts) > 1 else "", "go"))
    return deps


def parse_go_sum(content: str) -> list[tuple[str, str, str]]:
    """Parse go.sum for all dependency versions."""
    deps = []
    seen = set()
    for line in content.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            module_version = parts[0]  # e.g., "github.com/gin-gonic/gin v1.9.1"
            match = re.match(r"^(.+)\s+(v[\d\.]+.*)", module_version)
            if match:
                key = (match.group(1), match.group(2))
                if key not in seen:
                    seen.add(key)
                    deps.append((match.group(1), match.group(2), "go"))
    return deps


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------


def parse_cargo_toml(content: str) -> list[tuple[str, str, str]]:
    """Parse Cargo.toml [dependencies] and [dev-dependencies]."""
    deps = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return deps
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, str):
                deps.append((name, spec, "rust"))
            elif isinstance(spec, dict):
                version = spec.get("version", "")
                deps.append((name, version, "rust"))
    return deps


def parse_cargo_lock(content: str) -> list[tuple[str, str, str]]:
    """Parse Cargo.lock for pinned dependency versions."""
    deps = []
    current_name = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[[package]]"):
            current_name = None
        elif stripped.startswith("name = "):
            current_name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = ") and current_name:
            version = stripped.split("=", 1)[1].strip().strip('"')
            deps.append((current_name, version, "rust"))
    return deps


# ---------------------------------------------------------------------------
# Java (Maven / Gradle)
# ---------------------------------------------------------------------------


def parse_pom_xml(content: str) -> list[tuple[str, str, str]]:
    """Parse pom.xml <dependency> blocks. Regex-based (no XML parser dependency)."""
    deps = []
    pattern = re.compile(
        r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]*)</version>)?",
        re.DOTALL,
    )
    for match in pattern.finditer(content):
        group_id = match.group(1).strip()
        artifact_id = match.group(2).strip()
        version = (match.group(3) or "").strip()
        name = f"{group_id}:{artifact_id}"
        deps.append((name, version, "java"))
    return deps


def parse_gradle(content: str) -> list[tuple[str, str, str]]:
    """Parse build.gradle / build.gradle.kts dependency declarations."""
    deps = []
    patterns = [
        # implementation 'group:artifact:version'
        re.compile(
            r"""(?:implementation|api|compile|testImplementation|testCompile)\s+['"]([^'"]+)['"]"""
        ),
        # implementation group: 'g', name: 'a', version: 'v'
        re.compile(
            r"""(?:implementation|api|compile)\s+group:\s*['"]([^'"]+)['"],\s*name:\s*['"]([^'"]+)['"]"""
        ),
    ]
    for line in content.splitlines():
        line = line.strip()
        m = patterns[0].search(line)
        if m:
            coord = m.group(1)
            parts = coord.split(":")
            if len(parts) >= 2:
                name = f"{parts[0]}:{parts[1]}"
                version = parts[2] if len(parts) >= 3 else ""
                deps.append((name, version, "java"))
            continue
        m = patterns[1].search(line)
        if m:
            deps.append((f"{m.group(1)}:{m.group(2)}", "", "java"))
    return deps


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------


def parse_gemfile(content: str) -> list[tuple[str, str, str]]:
    """Parse Gemfile gem declarations."""
    deps = []
    pattern = re.compile(r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?"?""")
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        m = pattern.search(line)
        if m:
            name = m.group(1)
            version = m.group(2) or ""
            deps.append((name, version, "ruby"))
    return deps


def parse_gemfile_lock(content: str) -> list[tuple[str, str, str]]:
    """Parse Gemfile.lock GEM section."""
    deps = []
    in_gem = False
    for line in content.splitlines():
        if line.strip() == "GEM":
            in_gem = True
            continue
        if line.strip() in ("DEPENDENCIES", "PLATFORMS", "BUNDLED WITH"):
            in_gem = False
            continue
        if in_gem:
            match = re.match(r"^\s{4}(\S+)\s+\(([^)]+)\)", line)
            if match:
                deps.append((match.group(1), match.group(2), "ruby"))
    return deps


# ---------------------------------------------------------------------------
# PHP (Composer)
# ---------------------------------------------------------------------------


def parse_composer_json(content: str) -> list[tuple[str, str, str]]:
    """Parse composer.json require/require-dev."""
    deps = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return deps
    for section in ("require", "require-dev"):
        for name, version in data.get(section, {}).items():
            if name == "php":
                continue
            deps.append((name, version, "php"))
    return deps


# ---------------------------------------------------------------------------
# Unified parser
# ---------------------------------------------------------------------------

PARSERS = {
    "requirements.txt": parse_requirements,
    "pyproject.toml": parse_pyproject,
    "Pipfile": parse_pipfile,
    "package.json": parse_package_json,
    "package-lock.json": parse_package_lock,
    "go.mod": parse_go_mod,
    "go.sum": parse_go_sum,
    "Cargo.toml": parse_cargo_toml,
    "Cargo.lock": parse_cargo_lock,
    "pom.xml": parse_pom_xml,
    "build.gradle": parse_gradle,
    "build.gradle.kts": parse_gradle,
    "Gemfile": parse_gemfile,
    "Gemfile.lock": parse_gemfile_lock,
    "composer.json": parse_composer_json,
}


def parse_dependency_file(path: str, content: str) -> list[tuple[str, str, str]]:
    """Auto-detect file type and parse dependencies. Returns [(name, version, ecosystem)]."""
    filename = Path(path).name if path else ""
    parser = PARSERS.get(filename)
    if parser:
        return parser(content)
    return []
