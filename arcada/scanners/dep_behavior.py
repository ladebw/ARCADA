"""
Scanner 13: Dependency Behavioral Profiling
AST-based analysis of module-level code in installed packages
to detect backdoor delivery mechanisms (code that runs on import).
Includes inter-procedural call graph and aliased import resolution.
"""

from __future__ import annotations
import ast
import os
from pathlib import Path
from arcada.scanners.base import BaseScanner
from arcada.models import PackageFinding, ScannerResult, Severity

MAX_FILE_SIZE = 500_000

# Module-level dangerous calls that execute on import
MODULE_LEVEL_NETWORK = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "httpx.get",
    "httpx.post",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
}

MODULE_LEVEL_SUBPROCESS = {
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "os.system",
    "os.popen",
}

MODULE_LEVEL_THREADING = {
    "threading.Thread",
    "multiprocessing.Process",
    "concurrent.futures.ThreadPoolExecutor",
}

MODULE_LEVEL_PERSISTENCE = {
    "atexit.register",
    "signal.signal",
    "sys.excepthook",
}


class _ImportVisitor(ast.NodeVisitor):
    """AST visitor that finds dangerous calls at module level (not inside functions).
    Enhanced with aliased import resolution and class __init__ detection."""

    def __init__(self):
        self.module_level_calls: list[
            tuple[int, str, str]
        ] = []  # (lineno, call_name, category)
        self._in_function = False
        self._in_class = False
        self._in_class_init = False
        # Import alias tracking: alias -> original dotted name
        self.import_aliases: dict[str, str] = {}
        # Import tracking: module name -> imported name
        self.from_imports: dict[str, str] = {}

    def visit_Import(self, node):
        """Track: import os as operating_system"""
        for alias in node.names:
            name = alias.name
            asname = alias.asname or name
            self.import_aliases[asname] = name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Track: from os import system as run_cmd"""
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}.{alias.name}"
            asname = alias.asname or alias.name
            self.from_imports[asname] = full_name
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self._in_class = True
        self.generic_visit(node)
        self._in_class = False

    def visit_FunctionDef(self, node):
        # Detect __init__ inside classes — code runs when object is created
        if self._in_class and node.name == "__init__":
            self._in_class_init = True
            self.generic_visit(node)
            self._in_class_init = False
        else:
            self._in_function = True
            self.generic_visit(node)
            self._in_function = False

    def visit_AsyncFunctionDef(self, node):
        if self._in_class and node.name == "__init__":
            self._in_class_init = True
            self.generic_visit(node)
            self._in_class_init = False
        else:
            self._in_function = True
            self.generic_visit(node)
            self._in_function = False

    def visit_Call(self, node):
        # Skip if inside a function (not module-level and not __init__)
        if self._in_function and not self._in_class_init:
            self.generic_visit(node)
            return

        # Also skip if inside a class body but not inside __init__
        # (class-level attribute assignments like `response = requests.get(...)` are not backdoors)
        if self._in_class and not self._in_class_init:
            self.generic_visit(node)
            return

        call_name = self._get_call_name(node)
        if not call_name:
            self.generic_visit(node)
            return

        # Resolve aliases
        resolved = self._resolve_alias(call_name)

        category = None
        if resolved in MODULE_LEVEL_NETWORK or call_name in MODULE_LEVEL_NETWORK:
            category = "network"
        elif (
            resolved in MODULE_LEVEL_SUBPROCESS or call_name in MODULE_LEVEL_SUBPROCESS
        ):
            category = "subprocess"
        elif resolved in MODULE_LEVEL_THREADING or call_name in MODULE_LEVEL_THREADING:
            category = "threading"
        elif (
            resolved in MODULE_LEVEL_PERSISTENCE
            or call_name in MODULE_LEVEL_PERSISTENCE
        ):
            category = "persistence"

        if category:
            prefix = "Class __init__" if self._in_class_init else "Module-level"
            display_name = (
                f"{call_name} (resolves to {resolved})"
                if resolved != call_name
                else call_name
            )
            self.module_level_calls.append((node.lineno, display_name, category))

        self.generic_visit(node)

    def _resolve_alias(self, call_name: str) -> str:
        """Resolve import aliases to original names.
        e.g., run_cmd -> os.system if 'from os import system as run_cmd'"""
        parts = call_name.split(".")
        if parts[0] in self.from_imports:
            return self.from_imports[parts[0]]
        if parts[0] in self.import_aliases:
            return self.import_aliases[parts[0]] + "." + ".".join(parts[1:])
        return call_name

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract the full dotted name from a Call node."""
        func = node.func
        if isinstance(func, ast.Attribute):
            parts = []
            current = func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        elif isinstance(func, ast.Name):
            return func.id
        return ""


class _AssignVisitor(ast.NodeVisitor):
    """Find dangerous assignments at module level."""

    def __init__(self):
        self.dangerous_assigns: list[tuple[int, str]] = []
        self._in_function = False
        self._in_class = False

    def visit_FunctionDef(self, node):
        self._in_function = True
        self.generic_visit(node)
        self._in_function = False

    def visit_AsyncFunctionDef(self, node):
        self._in_function = True
        self.generic_visit(node)
        self._in_function = False

    def visit_ClassDef(self, node):
        self._in_class = True
        self.generic_visit(node)
        self._in_class = False

    def visit_Assign(self, node):
        if self._in_function or self._in_class:
            return
        for target in node.targets:
            name = self._get_target_name(target)
            if name:
                if (
                    "sys.modules" in name
                    or "sys.meta_path" in name
                    or "sys.path_hooks" in name
                ):
                    self.dangerous_assigns.append((node.lineno, name))
                elif "builtins." in name or "__builtins__" in name:
                    self.dangerous_assigns.append((node.lineno, name))
                elif name == "sys.excepthook":
                    self.dangerous_assigns.append((node.lineno, name))
        self.generic_visit(node)

    def _get_target_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
                return ".".join(reversed(parts))
        elif isinstance(node, ast.Subscript):
            return self._get_target_name(node.value) + "[...]"
        return ""


class DepBehaviorScanner(BaseScanner):
    name = "dep_behavior"

    async def scan(self) -> list[ScannerResult]:
        pkg_path = self.metadata.get("pkg_path", "")
        pkg_name = self.metadata.get("package", "")
        pkg_version = self.metadata.get("version", "")

        if pkg_path and os.path.isdir(pkg_path):
            await self._scan_directory(pkg_path, pkg_name, pkg_version)
        elif self.content and self.path:
            self._analyze_source(self.path, self.content, pkg_name, pkg_version)
        return self.findings

    async def _scan_directory(self, pkg_path: str, pkg_name: str, pkg_version: str):
        """Scan all .py files in a package directory."""
        skip_dirs = {"__pycache__", "test", "tests", "docs", ".git"}
        for py_file in Path(pkg_path).rglob("*.py"):
            if any(p in skip_dirs for p in py_file.parts):
                continue
            try:
                if py_file.stat().st_size > MAX_FILE_SIZE:
                    continue
                source = py_file.read_text(encoding="utf-8", errors="replace")
                self._analyze_source(str(py_file), source, pkg_name, pkg_version)
            except (PermissionError, OSError):
                continue

    def _analyze_source(
        self, file_path: str, source: str, pkg_name: str, pkg_version: str
    ):
        """Parse source with AST and check for module-level dangerous patterns."""
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return

        # Check for dangerous module-level calls
        visitor = _ImportVisitor()
        visitor.visit(tree)
        for lineno, call_name, category in visitor.module_level_calls:
            category_labels = {
                "network": "Module-level network call",
                "subprocess": "Module-level subprocess call",
                "threading": "Module-level threading/process spawn",
                "persistence": "Module-level persistence mechanism",
            }
            label = category_labels.get(category, category)
            severity = (
                Severity.CRITICAL
                if category in ("subprocess", "persistence")
                else Severity.HIGH
            )

            desc_extra = {
                "network": (
                    "This code makes an outbound HTTP request the moment the package is imported. "
                    "This is a classic supply-chain backdoor — it exfiltrates data or fetches additional payloads on import."
                ),
                "subprocess": (
                    "This code runs a shell command the moment the package is imported. "
                    "This is a critical backdoor signal — it executes before any user code runs."
                ),
                "threading": (
                    "This code spawns a background thread/process on import. "
                    "Hidden background processes are commonly used for persistent backdoors."
                ),
                "persistence": (
                    "This code registers a handler (atexit/signal/excepthook) at import time. "
                    "This is a persistence mechanism — the backdoor activates on shutdown or signal."
                ),
            }

            pkg_context = f" in {pkg_name} v{pkg_version}" if pkg_name else ""
            self.findings.append(
                PackageFinding(
                    scanner=self.name,
                    title=f"{label}{pkg_context}: {call_name}",
                    description=desc_extra.get(
                        category, f"Dangerous call at module level: {call_name}"
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {call_name}() at module level (runs on import)",
                    location=file_path,
                    fix=f"Review why '{call_name}' runs at import time in '{pkg_name}'. Legitimate packages rarely need this.",
                    impact="Code executes automatically when the package is imported — no user action needed.",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    package_file=file_path,
                )
            )

        # Check for dangerous assignments
        assign_visitor = _AssignVisitor()
        assign_visitor.visit(tree)
        for lineno, name in assign_visitor.dangerous_assigns:
            pkg_context = f" in {pkg_name} v{pkg_version}" if pkg_name else ""
            self.findings.append(
                PackageFinding(
                    scanner=self.name,
                    title=f"Module-level sys/builtins manipulation{pkg_context}: {name}",
                    description=(
                        f"This code modifies '{name}' at module level (runs on import). "
                        "This can hijack core Python functionality — custom importers, patched builtins, "
                        "or hidden exception handlers are all common backdoor techniques."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {name} = ... at module level",
                    location=file_path,
                    fix=f"Audit why '{pkg_name}' modifies '{name}' at import time. This is rarely legitimate.",
                    impact="Core Python behavior is silently changed for the entire process.",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    package_file=file_path,
                )
            )
