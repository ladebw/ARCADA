"""
Taint Analysis Engine for Python source code.
Tracks data flow from untrusted sources (request.*, input(), sys.argv) to
dangerous sinks (eval, exec, os.system, cursor.execute, etc.)
"""

from __future__ import annotations
import ast
import re
from dataclasses import dataclass, field
from arcada.models import ScannerResult, Severity

# ---------------------------------------------------------------------------
# Source catalog — where untrusted data enters the program
# ---------------------------------------------------------------------------
TAINT_SOURCES = {
    # Flask / FastAPI / Django request objects
    "request.args",
    "request.form",
    "request.json",
    "request.data",
    "request.values",
    "request.params",
    "request.query",
    "request.files",
    "request.get_json",
    "request.get_data",
    "request.headers",
    "request.cookies",
    # Starlette / FastAPI
    "request.body",
    "request.path_params",
    "request.query_params",
    # Django
    "request.POST",
    "request.GET",
    "request.body",
    "request.FILES",
    "request.META",
    # Generic
    "input",
    "sys.stdin",
    "sys.stdin.read",
    "sys.stdin.readline",
    "sys.argv",
    "os.environ",
    "os.environ.get",
    # File reads
    "open",
    "pathlib.Path.read_text",
    "pathlib.Path.read_bytes",
    # Environment
    "environ.get",
    "os.getenv",
}

# ---------------------------------------------------------------------------
# Sink catalog — where tainted data causes damage
# ---------------------------------------------------------------------------
TAINT_SINKS = {
    # Code execution
    "eval": Severity.CRITICAL,
    "exec": Severity.CRITICAL,
    "compile": Severity.HIGH,
    "__import__": Severity.CRITICAL,
    "importlib.import_module": Severity.HIGH,
    # Shell
    "os.system": Severity.CRITICAL,
    "os.popen": Severity.CRITICAL,
    "subprocess.call": Severity.CRITICAL,
    "subprocess.run": Severity.CRITICAL,
    "subprocess.Popen": Severity.CRITICAL,
    "subprocess.check_output": Severity.CRITICAL,
    "subprocess.check_call": Severity.CRITICAL,
    "commands.getoutput": Severity.CRITICAL,
    # Deserialization
    "pickle.load": Severity.CRITICAL,
    "pickle.loads": Severity.CRITICAL,
    "pickle.Unpickler": Severity.CRITICAL,
    "yaml.load": Severity.HIGH,
    "jsonpickle.decode": Severity.HIGH,
    "dill.load": Severity.HIGH,
    "dill.loads": Severity.HIGH,
    "marshal.load": Severity.HIGH,
    "marshal.loads": Severity.HIGH,
    # SQL
    "cursor.execute": Severity.CRITICAL,
    "cursor.executemany": Severity.CRITICAL,
    "db.execute": Severity.CRITICAL,
    "session.execute": Severity.HIGH,
    "connection.execute": Severity.HIGH,
    # Templates
    "Template": Severity.CRITICAL,
    "render_template_string": Severity.CRITICAL,
    "jinja2.Template": Severity.CRITICAL,
    # File operations
    "open": Severity.HIGH,
    "os.remove": Severity.HIGH,
    "os.unlink": Severity.HIGH,
    "os.makedirs": Severity.HIGH,
    "shutil.rmtree": Severity.HIGH,
    # Network
    "requests.get": Severity.MEDIUM,
    "requests.post": Severity.MEDIUM,
    "urllib.request.urlopen": Severity.MEDIUM,
    "httpx.get": Severity.MEDIUM,
    "httpx.post": Severity.MEDIUM,
}

# Assignment patterns that propagate taint: tainted_var = source_var
# We track a set of tainted variable names and propagate through assignments


@dataclass
class TaintFinding:
    source_name: str
    source_line: int
    sink_name: str
    sink_line: int
    var_chain: list[str]
    severity: Severity


class _TaintVisitor(ast.NodeVisitor):
    """AST-based taint tracker. Tracks which variables are tainted and where they flow."""

    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.tainted_vars: dict[str, int] = {}  # var_name -> source_line
        self.tainted_attrs: dict[str, int] = {}  # "obj.attr" -> source_line
        self.findings: list[TaintFinding] = []
        self._in_function = False
        self._scope_depth = 0
        # Function parameters that receive tainted data
        self._func_params: dict[str, list[str]] = {}  # func_name -> [param_names]

    # -- Scope tracking --
    def visit_FunctionDef(self, node):
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node):
        self._scope_depth += 1
        self.generic_visit(node)
        self._scope_depth -= 1

    # -- Source detection: assignments from tainted sources --
    def visit_Assign(self, node):
        # Check if RHS is a taint source
        rhs_tainted_line = self._is_taint_source(node.value)
        if rhs_tainted_line:
            for target in node.targets:
                name = self._get_target_name(target)
                if name:
                    self.tainted_vars[name] = rhs_tainted_line
                    # Track attribute access too: request.json -> data
                    if "." in name:
                        self.tainted_attrs[name] = rhs_tainted_line

        # Check if RHS contains a tainted variable (propagation)
        rhs_tainted_var = self._get_tainted_var_from_expr(node.value)
        if rhs_tainted_var and rhs_tainted_var in self.tainted_vars:
            source_line = self.tainted_vars[rhs_tainted_var]
            for target in node.targets:
                name = self._get_target_name(target)
                if name:
                    self.tainted_vars[name] = source_line

        # Check if RHS is a method call on a tainted object
        if isinstance(node.value, ast.Call):
            call_name = self._get_call_name(node.value)
            if call_name:
                # Check if any argument is tainted
                for arg in node.value.args:
                    arg_name = self._get_expr_name(arg)
                    if arg_name and arg_name in self.tainted_vars:
                        for target in node.targets:
                            tname = self._get_target_name(target)
                            if tname:
                                self.tainted_vars[tname] = self.tainted_vars[arg_name]
                        break

        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            rhs_tainted_line = self._is_taint_source(node.value)
            if rhs_tainted_line:
                name = self._get_target_name(node.target)
                if name:
                    self.tainted_vars[name] = rhs_tainted_line
            rhs_var = self._get_tainted_var_from_expr(node.value)
            if rhs_var and rhs_var in self.tainted_vars:
                name = self._get_target_name(node.target)
                if name:
                    self.tainted_vars[name] = self.tainted_vars[rhs_var]
        self.generic_visit(node)

    # -- Sink detection: tainted data reaching dangerous functions --
    def visit_Call(self, node):
        call_name = self._get_call_name(node)
        if not call_name:
            self.generic_visit(node)
            return

        # Check if this call is a known sink
        sink_severity = self._get_sink_severity(call_name)
        if sink_severity:
            # Check if any argument is tainted
            for i, arg in enumerate(node.args):
                arg_name = self._get_expr_name(arg)
                if arg_name and arg_name in self.tainted_vars:
                    source_line = self.tainted_vars[arg_name]
                    self.findings.append(
                        TaintFinding(
                            source_name=arg_name,
                            source_line=source_line,
                            sink_name=call_name,
                            sink_line=node.lineno,
                            var_chain=[arg_name, f"arg[{i}]", call_name],
                            severity=sink_severity,
                        )
                    )
                elif isinstance(arg, ast.JoinedStr):
                    # f-string: check if any variable in it is tainted
                    for value in arg.values:
                        if isinstance(value, ast.FormattedValue):
                            var_name = self._get_expr_name(value.value)
                            if var_name and var_name in self.tainted_vars:
                                source_line = self.tainted_vars[var_name]
                                self.findings.append(
                                    TaintFinding(
                                        source_name=var_name,
                                        source_line=source_line,
                                        sink_name=f"{call_name}(f-string)",
                                        sink_line=node.lineno,
                                        var_chain=[var_name, f"f-string", call_name],
                                        severity=sink_severity,
                                    )
                                )
                elif isinstance(arg, ast.BinOp):
                    # String concatenation: 'SELECT ... ' + user_input
                    tainted_var = self._get_tainted_var_from_expr(arg)
                    if tainted_var and tainted_var in self.tainted_vars:
                        source_line = self.tainted_vars[tainted_var]
                        self.findings.append(
                            TaintFinding(
                                source_name=tainted_var,
                                source_line=source_line,
                                sink_name=f"{call_name}(concatenation)",
                                sink_line=node.lineno,
                                var_chain=[tainted_var, "concatenation", call_name],
                                severity=sink_severity,
                            )
                        )

            # Check keyword arguments
            for kw in node.keywords:
                kw_name = self._get_expr_name(kw.value)
                if kw_name and kw_name in self.tainted_vars:
                    source_line = self.tainted_vars[kw_name]
                    self.findings.append(
                        TaintFinding(
                            source_name=kw_name,
                            source_line=source_line,
                            sink_name=f"{call_name}({kw.arg}=)",
                            sink_line=node.lineno,
                            var_chain=[kw_name, f"kw:{kw.arg}", call_name],
                            severity=sink_severity,
                        )
                    )

            # Check if shell=True with tainted arg
            if "subprocess" in call_name:
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        for arg in node.args:
                            arg_name = self._get_expr_name(arg)
                            if arg_name and arg_name in self.tainted_vars:
                                source_line = self.tainted_vars[arg_name]
                                self.findings.append(
                                    TaintFinding(
                                        source_name=arg_name,
                                        source_line=source_line,
                                        sink_name=f"{call_name}(shell=True)",
                                        sink_line=node.lineno,
                                        var_chain=[arg_name, "shell=True", call_name],
                                        severity=Severity.CRITICAL,
                                    )
                                )

        # Also check for string operations on tainted data that create new tainted values
        # e.g., tainted_var + ".txt", f"{tainted_var}/path"
        self.generic_visit(node)

    # -- Return statement: taint propagation to caller --
    def visit_Return(self, node):
        if node.value:
            var_name = self._get_expr_name(node.value)
            if var_name and var_name in self.tainted_vars:
                # Mark that this function returns tainted data
                # (could be tracked across functions with call graph)
                pass
        self.generic_visit(node)

    # -- Helper methods --
    def _is_taint_source(self, node) -> int | None:
        """Check if a node is a taint source. Returns source line number or None."""
        # Handle subscript first: request.form['key'] -> check request.form
        if isinstance(node, ast.Subscript):
            return self._is_taint_source(node.value)

        name = self._get_expr_name(node)
        if not name:
            return None

        # Direct match
        if name in TAINT_SOURCES:
            return getattr(node, "lineno", 0)

        # Partial match: request.xxx
        for source in TAINT_SOURCES:
            if name.startswith(source + "."):
                return getattr(node, "lineno", 0)

        # Check if it's input() call
        if name == "input":
            return getattr(node, "lineno", 0)

        # Check method calls on request objects (request.get_json(), request.get_data())
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node)
            if call_name:
                # Check if the call itself is a source
                if call_name in TAINT_SOURCES:
                    return node.lineno
                # Check if the call is on a tainted object: request.get_json()
                obj_name = call_name.rsplit(".", 1)[0] if "." in call_name else ""
                if obj_name:
                    for source in TAINT_SOURCES:
                        if obj_name == source or obj_name.startswith(source + "."):
                            return node.lineno

        return None

    def _get_tainted_var_from_expr(self, node) -> str | None:
        """If an expression uses a tainted variable, return its name."""
        if isinstance(node, ast.Name) and node.id in self.tainted_vars:
            return node.id
        if isinstance(node, ast.Attribute):
            full = self._get_expr_name(node)
            if full and full in self.tainted_vars:
                return full
            # Check base object
            base = self._get_expr_name(node.value)
            if base and base in self.tainted_vars:
                return base
        # Binary operations: tainted + something
        if isinstance(node, ast.BinOp):
            left = self._get_tainted_var_from_expr(node.left)
            if left:
                return left
            right = self._get_tainted_var_from_expr(node.right)
            if right:
                return right
        # f-strings
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    v = self._get_tainted_var_from_expr(value.value)
                    if v:
                        return v
        # Subscript: tainted[key]
        if isinstance(node, ast.Subscript):
            return self._get_tainted_var_from_expr(node.value)
        return None

    def _get_sink_severity(self, call_name: str) -> Severity | None:
        """Check if a call name is a known taint sink."""
        if call_name in TAINT_SINKS:
            return TAINT_SINKS[call_name]
        # Partial match
        for sink, sev in TAINT_SINKS.items():
            if (
                call_name.endswith("." + sink.split(".")[-1])
                and sink.split(".")[-1] in call_name
            ):
                return sev
        return None

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract dotted call name."""
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

    def _get_expr_name(self, node) -> str:
        """Get a string representation of an expression."""
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
            base = self._get_expr_name(node.value)
            if base:
                return base + "[...]"
        elif isinstance(node, ast.Call):
            return self._get_call_name(node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            return f'"{node.value[:20]}"'
        return ""

    def _get_target_name(self, node) -> str:
        """Get variable name from assignment target."""
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
            return self._get_target_name(node.value)
        return ""


def run_taint_analysis(source: str, file_path: str = "") -> list[ScannerResult]:
    """Run taint analysis on Python source code. Returns ScannerResult list."""
    try:
        tree = ast.parse(source, filename=file_path or "<unknown>")
    except SyntaxError:
        return []

    lines = source.splitlines()
    visitor = _TaintVisitor(lines)
    visitor.visit(tree)

    results = []
    for tf in visitor.findings:
        chain_str = " → ".join(tf.var_chain)
        results.append(
            ScannerResult(
                scanner="taint_analysis",
                title=f"Tainted data flow: {tf.source_name} → {tf.sink_name}",
                description=(
                    f"Data from untrusted source '{tf.source_name}' (line {tf.source_line}) "
                    f"flows to dangerous sink '{tf.sink_name}' (line {tf.sink_line}) "
                    f"without sanitization.\n\n"
                    f"Flow chain: {chain_str}"
                ),
                severity=tf.severity,
                evidence=(
                    f"Source: line {tf.source_line} ({tf.source_name})\n"
                    f"Sink: line {tf.sink_line} ({tf.sink_name})\n"
                    f"Chain: {chain_str}"
                ),
                location=file_path,
                fix=(
                    "Sanitize the input before passing to the sink. "
                    "Use parameterized queries for SQL. "
                    "Use whitelisting for file operations. "
                    "Never pass user input to eval/exec/os.system."
                ),
                impact="Attacker controls input that reaches a dangerous operation — RCE, SQL injection, or file disclosure.",
            )
        )

    return results
