"""
Scanner 16: Taint Analysis
AST-based source→sink data flow tracking for Python.
Detects when untrusted input reaches dangerous operations without sanitization.
"""

from __future__ import annotations
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.taint_analysis import run_taint_analysis


class TaintScanner(BaseScanner):
    name = "taint_analysis"

    async def scan(self) -> list[ScannerResult]:
        if not self._is_python():
            return self.findings
        taint_results = run_taint_analysis(self.content, self.path)
        self.findings.extend(taint_results)
        self._detect_conditional_taint()
        return self.findings

    def _is_python(self) -> bool:
        if not self.path:
            return True
        return self.path.lower().endswith((".py", ".pyw"))

    def _detect_conditional_taint(self):
        """Detect tainted data flowing through conditional branches.
        Catches patterns like: if condition: eval(user_var)"""
        import re

        lines = self.content.splitlines()
        in_if = False
        if_indent = 0
        tainted_in_block = []

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            indent = len(line) - len(line.lstrip())

            # Track if/elif/else blocks
            if re.match(r"\s*(if|elif|else)\b", line):
                in_if = True
                if_indent = indent
                tainted_in_block = []
            elif in_if and indent <= if_indent and stripped:
                in_if = False

            # Inside an if block, check for sink patterns
            if in_if:
                for sink_pattern in [
                    r"\beval\s*\(\s*(\w+)",
                    r"\bexec\s*\(\s*(\w+)",
                    r"os\.system\s*\(\s*(\w+)",
                    r"subprocess\.\w+\s*\(\s*(\w+)",
                    r"cursor\.execute\s*\(\s*(\w+)",
                ]:
                    m = re.search(sink_pattern, line)
                    if m:
                        var_name = m.group(1)
                        # Check if this variable was assigned from a source above
                        for prev_line in lines[: lineno - 1]:
                            if re.search(
                                rf"{re.escape(var_name)}\s*=\s*(?:request\.|input\(|sys\.argv|os\.environ)",
                                prev_line,
                            ):
                                self.add_finding(
                                    title=f"Conditional taint: {var_name} → {m.group(0).strip()}",
                                    description=(
                                        f"Variable '{var_name}' was assigned from an untrusted source "
                                        f"and later used in a dangerous function call inside a conditional block. "
                                        f"The condition may not properly validate the data."
                                    ),
                                    severity=Severity.CRITICAL,
                                    evidence=f"Source assignment above, sink at line {lineno}: {line.strip()}",
                                    fix="Validate and sanitize the variable before any conditional use in dangerous functions.",
                                    impact="Attacker input may bypass conditional checks and reach dangerous operations.",
                                )
                                break
