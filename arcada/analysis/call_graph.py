"""
Call Graph Analysis for Reachability
Builds AST-based call graphs to trace data flow and determine vulnerability reachability.
"""

from __future__ import annotations
import ast
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class CallGraph:
    def __init__(self):
        self.functions: Dict[str, FunctionDef] = {}
        self.calls: Dict[str, List[str]] = {}  # caller -> [callees]
        self.call_to: Dict[str, List[str]] = {}  # callee -> [callers]
        self.entry_points: List[str] = []
        self.sinks: Dict[str, List[str]] = {}  # sink_type -> [locations]
        self.sources: Dict[str, List[str]] = {}  # source_type -> [locations]

    def add_function(self, name: str, lineno: int, params: List[str], file: str):
        func = FunctionDef(name, lineno, params, file)
        self.functions[name] = func
        self.calls[name] = []
        return func

    def add_call(self, caller: str, callee: str):
        if caller in self.calls:
            self.calls[caller].append(callee)
        if callee not in self.call_to:
            self.call_to[callee] = []
        self.call_to[callee].append(caller)

    def add_sink(self, sink_type: str, location: str):
        if sink_type not in self.sinks:
            self.sinks[sink_type] = []
        self.sinks[sink_type].append(location)

    def add_source(self, source_type: str, location: str):
        if source_type not in self.sources:
            self.sources[source_type] = []
        self.sources[source_type].append(location)

    def is_reachable_from_entry(self, func_name: str) -> bool:
        """Check if function is reachable from any entry point."""
        if func_name in self.entry_points:
            return True

        visited = set()
        queue = list(self.entry_points)

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current in self.calls:
                for callee in self.calls[current]:
                    if callee == func_name:
                        return True
                    if callee not in visited:
                        queue.append(callee)
        return False

    def trace_to_sink(
        self, start_func: str, sink_types: List[str]
    ) -> Tuple[bool, List[str]]:
        """Trace from a function to any sink. Returns (is_reachable, path)."""
        visited = set()
        queue = [(start_func, [start_func])]

        while queue:
            current, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            if current in self.sinks:
                for sink_type in sink_types:
                    if sink_type in self.sinks:
                        return True, path

            if current in self.calls:
                for callee in self.calls[current]:
                    if callee not in visited:
                        queue.append((callee, path + [callee]))

        return False, []


class FunctionDef:
    def __init__(self, name: str, lineno: int, params: List[str], file: str):
        self.name = name
        self.lineno = lineno
        self.params = params
        self.file = file
        self.variables: Dict[str, str] = {}  # var -> type/source


class CallGraphBuilder(ast.NodeVisitor):
    """AST visitor that builds a call graph."""

    DANGEROUS_SINKS = {
        "exec",
        "eval",
        "compile",
        "exec",
        "__import__",
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.exec",
        "os.execl",
        "os.execv",
        "eval",
        "exec",
        "compile",
        "pickle.load",
        "pickle.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "marshal.loads",
        "exec_",
        "run_py",
        "os.chmod",
        "os.chown",
        "os.remove",
        "os.unlink",
        "shutil.rmtree",
        "shutil.move",
        "shutil.copy",
    }

    INPUT_SOURCES = {
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.headers",
        "request.cookies",
        "sys.argv",
        "os.environ",
        "os.getenv",
        "stdin.read",
        "input",
        "raw_input",
        "http.Request",
        "HttpRequest",
        "Request",
    }

    def __init__(self, content: str, file_path: str):
        self.content = content
        self.file_path = file_path
        self.graph = CallGraph()
        self.current_function: Optional[FunctionDef] = None
        self.current_class: Optional[str] = None
        self._in_entry_point = False

        try:
            self.tree = ast.parse(content, filename=file_path)
            self._build_graph()
        except SyntaxError:
            pass

    def _build_graph(self):
        """Build the call graph by traversing the AST."""
        self.visit(self.tree)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        func_name = node.name

        if self.current_class:
            func_name = f"{self.current_class}.{node.name}"

        params = [arg.arg for arg in node.args.args]
        self.graph.add_function(func_name, node.lineno, params, self.file_path)

        if node.name in ("main", "app", "application", "run", "serve", "handler"):
            self.graph.entry_points.append(func_name)
            self._in_entry_point = True

        old_function = self.current_function
        self.current_function = func_name
        self.generic_visit(node)
        self.current_function = old_function
        self._in_entry_point = False

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self.current_class
        self.current_class = node.name

        for base in node.bases:
            if hasattr(base, "id"):
                if base.id in ("Flask", "FastAPI", "Django", "APIRouter", "Controller"):
                    self.graph.entry_points.append(node.name)

        self.generic_visit(node)
        self.current_class = old_class

    def visit_Call(self, node: ast.Call):
        if self.current_function:
            callee = self._get_callee_name(node)
            if callee:
                self.graph.add_call(self.current_function, callee)

                if callee in self.DANGEROUS_SINKS:
                    self.graph.add_sink(callee, f"{self.file_path}:{node.lineno}")

                if any(src in callee for src in self.INPUT_SOURCES):
                    self.graph.add_source(callee, f"{self.file_path}:{node.lineno}")

        self.generic_visit(node)

    def _get_callee_name(self, node: ast.Call) -> Optional[str]:
        """Extract the function name being called."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name):
                return f"{obj.id}.{node.func.attr}"
            elif isinstance(obj, ast.Attribute):
                if isinstance(obj.value, ast.Name):
                    return f"{obj.value.id}.{obj.attr}.{node.func.attr}"
            return node.func.attr
        return None


def build_call_graph(file_path: str, content: str) -> CallGraph:
    """Build a call graph for a single file."""
    builder = CallGraphBuilder(content, file_path)
    return builder.graph


def build_project_call_graph(directory: str) -> CallGraph:
    """Build a combined call graph for an entire project."""
    combined = CallGraph()

    for root, dirs, files in os.walk(directory):
        dirs[:] = [
            d
            for d in dirs
            if d not in {".git", "__pycache__", "node_modules", "venv", ".venv"}
        ]

        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    content = Path(path).read_text(encoding="utf-8", errors="ignore")
                    graph = build_call_graph(path, content)

                    for func_name, func_def in graph.functions.items():
                        if func_name not in combined.functions:
                            combined.add_function(
                                func_name,
                                func_def.lineno,
                                func_def.params,
                                func_def.file,
                            )

                    for caller, callees in graph.calls.items():
                        full_caller = f"{Path(path).stem}:{caller}"
                        for callee in callees:
                            combined.add_call(full_caller, callee)

                    combined.entry_points.extend(graph.entry_points)

                except Exception:
                    continue

    return combined


def check_vuln_reachability(
    graph: CallGraph, vuln_location: str, entry_points: List[str] = None
) -> str:
    """Check if a vulnerability location is reachable from entry points.

    Returns: "REACHABLE", "LIKELY_REACHABLE", "UNLIKELY", "UNREACHABLE"
    """
    if entry_points:
        graph.entry_points.extend(entry_points)

    for func_name in graph.functions:
        if graph.is_reachable_from_entry(func_name):
            is_reachable, path = graph.trace_to_sink(
                func_name, list(graph.sinks.keys())
            )
            if is_reachable:
                return "REACHABLE"

    return "UNREACHABLE"
