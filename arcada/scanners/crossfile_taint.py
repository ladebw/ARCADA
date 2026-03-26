"""
Scanner 16: Cross-File Taint Analysis
Builds an import graph across all project files and tracks tainted data
from source in one file to sink in another file.

Example caught:
  config.py:   SECRET = os.environ["API_KEY"]     ← SOURCE
  utils.py:    from config import SECRET           ← TRANSIT
  app.py:      eval(utils.get_secret())            ← SINK
"""

from __future__ import annotations
import ast
import os
from pathlib import Path
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.taint_analysis import TAINT_SOURCES, TAINT_SINKS


class CrossFileTaintScanner(BaseScanner):
    name = "crossfile_taint"

    async def scan(self) -> list[ScannerResult]:
        # Only run when scanning a directory (has file_pairs in metadata)
        file_pairs = self.metadata.get("file_pairs", [])
        if not file_pairs:
            # Single file mode — nothing to do cross-file
            return self.findings

        py_files = {
            path: content
            for path, content in file_pairs
            if path.endswith(".py") and "__pycache__" not in path
        }
        if len(py_files) < 2:
            return self.findings

        # Phase 1: Build the import graph
        import_graph = self._build_import_graph(py_files)

        # Phase 2: Find tainted sources in each file
        tainted_exports = self._find_tainted_exports(py_files)

        # Phase 3: Track tainted data across imports to sinks
        self._track_cross_file_taint(py_files, import_graph, tainted_exports)

        return self.findings

    def _build_import_graph(
        self, py_files: dict[str, str]
    ) -> dict[str, list[tuple[str, str, int]]]:
        """Build: file -> [(imported_name, source_file, lineno)]"""
        graph: dict[str, list[tuple[str, str, int]]] = {}
        module_map = self._build_module_map(py_files)

        for file_path, content in py_files.items():
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue

            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        imported_name = alias.name
                        as_name = alias.asname or alias.name
                        module = node.module
                        # Resolve module to file path
                        resolved = self._resolve_module(module, module_map, file_path)
                        if resolved:
                            imports.append((as_name, resolved, node.lineno))
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        name = alias.name
                        as_name = alias.asname or name
                        resolved = self._resolve_module(name, module_map, file_path)
                        if resolved:
                            imports.append((as_name, resolved, node.lineno))

            graph[file_path] = imports

        return graph

    def _build_module_map(self, py_files: dict[str, str]) -> dict[str, str]:
        """Map module paths to file paths."""
        module_map = {}
        for file_path in py_files:
            # Convert file path to module name
            path = Path(file_path)
            parts = []
            for part in path.parts:
                if part.endswith(".py"):
                    parts.append(part[:-3])
                else:
                    parts.append(part)
            module_name = ".".join(parts)
            module_map[module_name] = file_path

            # Also map by just the filename
            module_map[path.stem] = file_path
        return module_map

    def _resolve_module(
        self, module: str, module_map: dict[str, str], current_file: str
    ) -> str | None:
        """Resolve a module import to a file path."""
        if module in module_map:
            return module_map[module]

        # Try relative import
        current_dir = str(Path(current_file).parent)
        parts = module.split(".")
        candidate = os.path.join(current_dir, *parts) + ".py"
        if candidate in module_map:
            return candidate
        candidate_init = os.path.join(current_dir, *parts, "__init__.py")
        if candidate_init in module_map:
            return candidate_init

        return None

    def _find_tainted_exports(
        self, py_files: dict[str, str]
    ) -> dict[str, dict[str, int]]:
        """Find which names in each file are tainted (assigned from taint sources).
        Returns: file_path -> {exported_name: source_line}
        """
        tainted_exports: dict[str, dict[str, int]] = {}

        for file_path, content in py_files.items():
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue

            file_tainted: dict[str, int] = {}

            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = []
                    if isinstance(node, ast.Assign):
                        targets = node.targets
                    elif isinstance(node, ast.AnnAssign) and node.value:
                        targets = [node.target]

                    value = node.value if hasattr(node, "value") else None
                    if not value:
                        continue

                    # Check if value is a taint source
                    is_source = self._is_taint_source_node(value)
                    if is_source:
                        for target in targets:
                            name = self._get_name(target)
                            if name:
                                file_tainted[name] = getattr(node, "lineno", 0)

                    # Check if value uses a tainted variable
                    tainted_var = self._get_tainted_ref(value, file_tainted)
                    if tainted_var:
                        for target in targets:
                            name = self._get_name(target)
                            if name:
                                file_tainted[name] = file_tainted.get(tainted_var, 0)

            if file_tainted:
                tainted_exports[file_path] = file_tainted

        return tainted_exports

    def _track_cross_file_taint(
        self,
        py_files: dict[str, str],
        import_graph: dict[str, list[tuple[str, str, int]]],
        tainted_exports: dict[str, dict[str, int]],
    ):
        """Track tainted data from source file through imports to sink file."""
        for file_path, content in py_files.items():
            imports = import_graph.get(file_path, [])
            if not imports:
                continue

            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue

            # Build a map: local_name -> (source_file, source_name, import_lineno)
            imported_tainted: dict[str, tuple[str, str, int]] = {}
            for local_name, source_file, import_lineno in imports:
                source_tainted = tainted_exports.get(source_file, {})
                if local_name in source_tainted:
                    imported_tainted[local_name] = (
                        source_file,
                        local_name,
                        import_lineno,
                    )

            if not imported_tainted:
                continue

            # Track how imported tainted names flow through this file
            local_tainted: dict[str, tuple[str, int]] = {}
            for local_name, (src_file, _, imp_line) in imported_tainted.items():
                local_tainted[local_name] = (src_file, imp_line)

            # Also track: from config import SECRET as KEY → KEY is tainted
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)):
                    value = node.value if hasattr(node, "value") else None
                    if not value:
                        continue
                    tainted_var = self._get_tainted_ref(value, local_tainted)
                    if tainted_var:
                        src_file, src_line = local_tainted[tainted_var]
                        for target in (
                            node.targets
                            if isinstance(node, ast.Assign)
                            else [node.target]
                        ):
                            name = self._get_name(target)
                            if name:
                                local_tainted[name] = (src_file, src_line)

                elif isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)
                    sink_severity = self._get_sink_severity(call_name)
                    if sink_severity:
                        for arg in node.args:
                            arg_name = self._get_name(arg)
                            if arg_name and arg_name in local_tainted:
                                src_file, src_line = local_tainted[arg_name]
                                self.findings.append(
                                    ScannerResult(
                                        scanner=self.name,
                                        title=f"Cross-file taint: {src_file} → {file_path} → {call_name}",
                                        description=(
                                            f"Untrusted data originates in '{src_file}' (line {src_line}), "
                                            f"is imported into '{file_path}', and reaches dangerous "
                                            f"sink '{call_name}' (line {node.lineno}) without sanitization."
                                        ),
                                        severity=sink_severity,
                                        evidence=(
                                            f"Source: {src_file}:{src_line} → Import: {file_path} → "
                                            f"Sink: {call_name} at line {node.lineno}"
                                        ),
                                        location=file_path,
                                        fix="Sanitize the imported data before passing to the sink.",
                                        impact="Cross-file data flow from untrusted source to dangerous sink — RCE/SQLi/file disclosure.",
                                    )
                                )

    def _is_taint_source_node(self, node) -> bool:
        """Check if an AST node is a taint source."""
        if isinstance(node, ast.Subscript):
            return self._is_taint_source_node(node.value)
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            if call_name in TAINT_SOURCES:
                return True
            for source in TAINT_SOURCES:
                if call_name.startswith(source + "."):
                    return True
        name = self._get_name(node)
        if name:
            for source in TAINT_SOURCES:
                if name == source or name.startswith(source + "."):
                    return True
        return False

    def _get_tainted_ref(self, node, tainted: dict) -> str | None:
        """Check if a node references a tainted variable."""
        name = self._get_name(node)
        if name and name in tainted:
            return name
        if isinstance(node, ast.BinOp):
            left = self._get_tainted_ref(node.left, tainted)
            if left:
                return left
            right = self._get_tainted_ref(node.right, tainted)
            if right:
                return right
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    v = self._get_tainted_ref(val.value, tainted)
                    if v:
                        return v
        return None

    def _get_sink_severity(self, call_name: str) -> Severity | None:
        if not call_name:
            return None
        if call_name in TAINT_SINKS:
            return TAINT_SINKS[call_name]
        for sink, sev in TAINT_SINKS.items():
            if call_name.endswith("." + sink.split(".")[-1]):
                return sev
        return None

    def _get_call_name(self, node: ast.Call) -> str:
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

    def _get_name(self, node) -> str:
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
            return self._get_name(node.value)
        return ""
