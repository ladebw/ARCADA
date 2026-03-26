"""
Dependency Graph Analysis
Full transitive dependency resolution and SBOM/AI-BOM generation.
"""

from __future__ import annotations
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from packaging import version


@dataclass
class Dependency:
    """Represents a package dependency."""

    name: str
    version: str
    ecosystem: str  # pip, npm, maven, go
    resolved_version: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    dependencies: List["Dependency"] = field(default_factory=list)
    is_direct: bool = False
    is_dev: bool = False
    yanked: bool = False
    publish_date: Optional[str] = None
    last_update: Optional[str] = None
    maintainers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "resolved_version": self.resolved_version,
            "ecosystem": self.ecosystem,
            "repository": self.repository,
            "license": self.license,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "yanked": self.yanked,
            "publish_date": self.publish_date,
            "maintainers": self.maintainers,
            "dependencies": [d.to_dict() for d in self.dependencies],
        }


class DependencyResolver:
    """Resolves transitive dependencies for multiple package ecosystems."""

    MAX_DEPTH = 15

    def __init__(self, max_depth: int = MAX_DEPTH):
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.resolved: Dict[str, Dependency] = {}

    def resolve(self, manifest_path: str) -> List[Dependency]:
        """Resolve dependencies from a manifest file."""
        self.visited.clear()
        self.resolved.clear()

        ecosystem = self._detect_ecosystem(manifest_path)

        if ecosystem == "pip":
            return self._resolve_pip(manifest_path)
        elif ecosystem == "npm":
            return self._resolve_npm(manifest_path)
        elif ecosystem == "maven":
            return self._resolve_maven(manifest_path)
        elif ecosystem == "go":
            return self._resolve_go(manifest_path)

        return []

    def _detect_ecosystem(self, manifest_path: str) -> str:
        """Detect the package ecosystem from manifest file."""
        name = Path(manifest_path).name.lower()

        if name in (
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile",
        ):
            return "pip"
        elif name in ("package.json", "package-lock.json", "yarn.lock"):
            return "npm"
        elif name in ("pom.xml", "build.gradle", "build.gradle.kts"):
            return "maven"
        elif name in ("go.mod", "go.sum"):
            return "go"

        return "unknown"

    def _resolve_pip(self, manifest_path: str) -> List[Dependency]:
        """Resolve Python dependencies."""
        direct_deps = self._parse_requirements(manifest_path)

        results = []
        for name, version_spec in direct_deps:
            dep = Dependency(
                name=name, version=version_spec, ecosystem="pip", is_direct=True
            )
            self._resolve_pip_recursive(dep, depth=0)
            results.append(dep)
            self.resolved[dep.name.lower()] = dep

        return results

    def _resolve_pip_recursive(self, dep: Dependency, depth: int):
        """Recursively resolve Python dependencies."""
        if depth >= self.max_depth:
            return

        key = f"{dep.name.lower()}"
        if key in self.visited:
            return
        self.visited.add(key)

        try:
            result = subprocess.run(
                ["pip", "show", dep.name],
                capture_output=True,
                text=True,
                timeout=10,
            )

            for line in result.stdout.splitlines():
                if line.startswith("Requires:"):
                    requires = line.split(":", 1)[1].strip()
                    if requires:
                        for req in requires.split(","):
                            req = req.strip()
                            if req:
                                child = Dependency(
                                    name=req,
                                    version="unknown",
                                    ecosystem="pip",
                                    is_direct=False,
                                )
                                self._resolve_pip_recursive(child, depth + 1)
                                dep.dependencies.append(child)
        except Exception:
            pass

    def _parse_requirements(self, path: str) -> List[tuple]:
        """Parse requirements.txt file."""
        deps = []

        try:
            content = Path(path).read_text(encoding="utf-8", errors="ignore")

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                if "==" in line:
                    name, version = line.split("==", 1)
                    deps.append((name.strip(), f"=={version.strip()}"))
                elif ">=" in line:
                    name, version = line.split(">=", 1)
                    deps.append((name.strip(), f">={version.strip()}"))
                elif "<=" in line:
                    name, version = line.split("<=", 1)
                    deps.append((name.strip(), f"<={version.strip()}"))
                elif "~=" in line:
                    name, version = line.split("~=", 1)
                    deps.append((name.strip(), f"~={version.strip()}"))
                else:
                    deps.append((line, "*"))
        except Exception:
            pass

        return deps

    def _resolve_npm(self, manifest_path: str) -> List[Dependency]:
        """Resolve npm dependencies."""
        try:
            content = Path(manifest_path).read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)

            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})

            results = []

            for name, ver in deps.items():
                dep = Dependency(
                    name=name, version=ver, ecosystem="npm", is_direct=True
                )
                results.append(dep)
                self.resolved[f"npm:{name.lower()}"] = dep

            for name, ver in dev_deps.items():
                dep = Dependency(
                    name=name, version=ver, ecosystem="npm", is_direct=True, is_dev=True
                )
                results.append(dep)
                self.resolved[f"npm:{name.lower()}"] = dep

            return results
        except Exception:
            return []

    def _resolve_maven(self, manifest_path: str) -> List[Dependency]:
        """Resolve Maven dependencies."""
        deps = []

        try:
            content = Path(manifest_path).read_text(encoding="utf-8", errors="ignore")

            import re

            dep_pattern = r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?"

            for match in re.finditer(dep_pattern, content, re.DOTALL):
                group_id = match.group(1)
                artifact_id = match.group(2)
                ver = match.group(3) or "unknown"

                deps.append(
                    Dependency(
                        name=f"{group_id}:{artifact_id}",
                        version=ver,
                        ecosystem="maven",
                        is_direct=True,
                    )
                )
        except Exception:
            pass

        return deps

    def _resolve_go(self, manifest_path: str) -> List[Dependency]:
        """Resolve Go module dependencies."""
        deps = []

        try:
            content = Path(manifest_path).read_text(encoding="utf-8", errors="ignore")

            in_require = False
            for line in content.splitlines():
                line = line.strip()

                if line == "require (":
                    in_require = True
                    continue
                elif line == ")" and in_require:
                    in_require = False
                    continue

                if in_require and line:
                    parts = line.split()
                    if parts:
                        name = parts[0]
                        ver = parts[1] if len(parts) > 1 else "unknown"
                        deps.append(
                            Dependency(
                                name=name, version=ver, ecosystem="go", is_direct=True
                            )
                        )
        except Exception:
            pass

        return deps


class SBOMGenerator:
    """Generates Software Bill of Materials (SBOM) in various formats."""

    def generate(self, dependencies: List[Dependency], format: str = "spdx") -> str:
        """Generate SBOM in specified format."""
        if format == "spdx":
            return self._generate_spdx(dependencies)
        elif format == "cyclonedx":
            return self._generate_cyclonedx(dependencies)
        elif format == "json":
            return self._generate_json(dependencies)

        return self._generate_json(dependencies)

    def _generate_spdx(self, dependencies: List[Dependency]) -> str:
        """Generate SPDX format SBOM."""
        lines = [
            "SPDXVersion: SPDX-2.3",
            "DataLicense: CC0-1.0",
            "SPDXID: SPDXRef-DOCUMENT",
            "DocumentName: ARCADA-SBOM",
            "DocumentNamespace: https://arcada.dev/sbom",
            "",
            "CreationInfo:",
            "  Created: " + str(Path(__file__).stat().st_ctime),
            "  Creator: ARCADA",
            "",
        ]

        for i, dep in enumerate(dependencies):
            ref = f"Package-{i + 1}"
            lines.extend(
                [
                    f"PackageName: {dep.name}",
                    f"SPDXID: SPDXRef-{ref}",
                    f"PackageVersion: {dep.version}",
                    f"PackageDownloadLocation: {dep.repository or 'NOASSERTION'}",
                    f"FilesAnalyzed: false",
                    "",
                ]
            )

        return "\n".join(lines)

    def _generate_cyclonedx(self, dependencies: List[Dependency]) -> str:
        """Generate CycloneDX format SBOM."""
        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:" + str(Path(__file__).stat().st_ctime),
            "version": 1,
            "components": [],
        }

        for dep in dependencies:
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
            }

            if dep.license:
                component["licenses"] = [{"expression": dep.license}]

            if dep.repository:
                component["purl"] = f"pkg:{dep.ecosystem}/{dep.name}@{dep.version}"

            bom["components"].append(component)

        return json.dumps(bom, indent=2)

    def _generate_json(self, dependencies: List[Dependency]) -> str:
        """Generate JSON format SBOM."""
        return json.dumps(
            {
                "sbom_version": "1.0",
                "generator": "ARCADA",
                "dependencies": [d.to_dict() for d in dependencies],
            },
            indent=2,
        )


class AIBOMGenerator:
    """Generates AI-specific Bill of Materials (AI-BOM)."""

    def generate(
        self, dependencies: List[Dependency], code_analysis: Dict = None
    ) -> Dict:
        """Generate AI-BOM with model and ML-specific metadata."""

        ai_packages = self._identify_ai_packages(dependencies)
        model_deps = self._identify_model_dependencies(dependencies)
        api_deps = self._identify_api_dependencies(dependencies)

        return {
            "ai_bom_version": "1.0",
            "generated_by": "ARCADA",
            "ai_packages": [p.to_dict() for p in ai_packages],
            "model_dependencies": model_deps,
            "api_dependencies": api_deps,
            "code_analysis": code_analysis or {},
        }

    def _identify_ai_packages(self, dependencies: List[Dependency]) -> List[Dependency]:
        """Identify AI/ML packages in dependency list."""
        ai_keywords = {
            "torch",
            "tensorflow",
            "keras",
            "sklearn",
            "scikit",
            "numpy",
            "pandas",
            "transformers",
            "huggingface",
            "openai",
            "anthropic",
            "cohere",
            "together",
            "langchain",
            "llama",
            "diffusers",
            "accelerate",
            "peft",
            "bitsandbytes",
            "autogpt",
            "agent",
            "crewai",
            "autogen",
            "prompt",
            "rag",
            "vector",
            "chromadb",
            "pinecone",
            "weaviate",
            "milvus",
            "qdrant",
            "faiss",
            "onnx",
            "tensorrt",
            "openvino",
            "timm",
            "torchvision",
            "torchaudio",
            "jax",
            "flax",
            "mlx",
            "candle",
            "litgpt",
            "vllm",
            "text generation",
            "stable-diffusion",
            "diffusion",
            "sd",
            "controlnet",
            "lora",
            "dreambooth",
        }

        return [
            d for d in dependencies if any(kw in d.name.lower() for kw in ai_keywords)
        ]

    def _identify_model_dependencies(
        self, dependencies: List[Dependency]
    ) -> List[Dict]:
        """Identify model loading and processing dependencies."""
        model_patterns = ["model", "weight", "checkpoint", "checkpoint", "safetensor"]

        model_deps = []
        for dep in dependencies:
            if any(p in dep.name.lower() for p in model_patterns):
                model_deps.append(
                    {
                        "name": dep.name,
                        "version": dep.version,
                        "type": "model_related",
                    }
                )

        return model_deps

    def _identify_api_dependencies(self, dependencies: List[Dependency]) -> List[Dict]:
        """Identify API client dependencies."""
        api_patterns = [
            "api",
            "client",
            "sdk",
            "openai",
            "anthropic",
            "google",
            "aws",
            "azure",
        ]

        api_deps = []
        for dep in dependencies:
            if any(p in dep.name.lower() for p in api_patterns):
                api_deps.append(
                    {
                        "name": dep.name,
                        "version": dep.version,
                        "type": "api_client",
                    }
                )

        return api_deps


def generate_dependency_graph(manifest_path: str, max_depth: int = 15) -> Dict:
    """Convenience function to generate full dependency graph."""
    resolver = DependencyResolver(max_depth)
    deps = resolver.resolve(manifest_path)

    sbom = SBOMGenerator()
    aibom = AIBOMGenerator()

    return {
        "dependencies": [d.to_dict() for d in deps],
        "sbom": sbom.generate(deps),
        "ai_bom": aibom.generate(deps),
        "total_count": len(deps),
    }
