"""
Obfuscation Scanner
Detects code obfuscation techniques: base64 chains, junk code, string obfuscation,
install hooks, and other anti-analysis patterns.
"""

from __future__ import annotations
import base64
import re
import ast
import zlib
from pathlib import Path

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class ObfuscationScanner(BaseScanner):
    name = "obfuscation"

    async def scan(self) -> list[ScannerResult]:
        if not self.path:
            return []

        if self.path.endswith(".py"):
            await self._scan_python_file()
        elif self.path.endswith((".whl", ".zip", ".tar", ".gz")):
            await self._scan_archive()

        return self.findings

    async def _scan_python_file(self):
        """Scan Python file for obfuscation patterns."""
        self._detect_base64_chains()
        self._detect_string_obfuscation()
        self._detect_junk_code()
        self._detect_bytecode_preload()
        self._detect_import_hooks()
        self._detect_dynamic_code()
        self._detect_polyglot_patterns()

    async def _scan_archive(self):
        """Scan archive files for obfuscation."""
        self._detect_packed_payloads()
        self._detect_stub_loaders()

    def _detect_base64_chains(self):
        """Detect base64 encoded payloads that may be decoded and executed."""
        patterns = [
            (r"base64\.b64decode\s*\([^\)]+\)", "base64.b64decode call"),
            (r"base64\.decodebytes\s*\([^\)]+\)", "base64.decodebytes call"),
            (
                r"base64\.urlsafe_b64decode\s*\([^\)]+\)",
                "base64.urlsafe_b64decode call",
            ),
            (r"b64decode\s*\([^\)]+\)", "b64decode call"),
            (r'__import__\s*\(\s*["\']base64["\']', "base64 import"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self._check_base64_context(lineno, line, label)

    def _check_base64_context(self, lineno: int, line: str, label: str):
        """Check if base64 is used with exec/eval."""
        context = "\n".join(self.content.splitlines()[max(0, lineno - 3) : lineno + 3])

        if any(x in context.lower() for x in ["exec", "eval", "compile", "__import__"]):
            self.add_finding(
                title=f"Base64 with code execution: {label}",
                description="Base64 decode followed by exec/eval - likely obfuscated payload",
                severity=Severity.CRITICAL,
                evidence=line[:150],
                location=f"{self.path}:{lineno}",
                fix="Decode the payload to analyze. This is a common obfuscation technique.",
                impact="Malicious code hidden via base64 encoding",
            )

        if line.count("base64") > 2:
            self.add_finding(
                title="Multiple base64 operations",
                description="Multiple base64 operations detected - possible encoding chain",
                severity=Severity.MEDIUM,
                evidence=line[:150],
                location=f"{self.path}:{lineno}",
                fix="Review all base64 operations for suspicious patterns",
                impact="Potential multi-layer obfuscation",
            )

    def _detect_string_obfuscation(self):
        """Detect string obfuscation techniques."""
        patterns = [
            (r"\.join\s*\(\s*\[.*\]\s*\)", "String join obfuscation"),
            (r"chr\s*\(\s*\d+\s*\)", "chr() obfuscation"),
            (r'\+\s*["\']["\']\s*\+', "Empty string concatenation"),
            (r'"\s*%\s*\(', "String % formatting"),
            (r'"\s*\.format\s*\(', "String .format()"),
            (r'f["\'][^"\']*\{', "f-string with expressions"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                if len(line) < 50 and "chr(" in line:
                    self.add_finding(
                        title=f"String obfuscation: {label}",
                        description=f"Detected: {label} - strings may be obfuscated",
                        severity=Severity.LOW,
                        evidence=line[:150],
                        location=f"{self.path}:{lineno}",
                        fix="Analyze string construction patterns",
                        impact="Hidden strings may conceal malicious code",
                    )

    def _detect_junk_code(self):
        """Detect junk code / dead code insertion."""
        patterns = [
            (r"if\s+False\s*:", "Dead code: if False"),
            (r"if\s+True\s*:", "Always true condition"),
            (r"pass\s*#.*", "Pass with comment"),
            (r"^\s*#.*dead.*code", "Dead code comment"),
            (r"0\s*\*\s*\w+", "Multiplication by zero"),
            (r'""\s*\*\s*\d+', "Empty string multiplication"),
            (r"\[\s*\]\s*\*\s*\d+", "Empty list multiplication"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Potential junk code: {label}",
                    description="Dead code may be used to confuse analysis",
                    severity=Severity.LOW,
                    evidence=line[:150],
                    location=f"{self.path}:{lineno}",
                    fix="Review if code serves a purpose",
                    impact="May be used to evade detection",
                )

    def _detect_bytecode_preload(self):
        """Detect bytecode manipulation / preloading."""
        patterns = [
            (r"import\s+py_compile", "py_compile import"),
            (r"py_compile\.compile\s*\(", "py_compile.compile call"),
            (r'compile\s*\([^,]+,\s*["\']<string["\']', "compile from string"),
            (r"marshal\.loads\s*\(", "marshal.loads call"),
            (r"marshal\.dumps\s*\(", "marshal.dumps call"),
            (r"importlib\.invalidate_caches\s*\(", "importlib.invalidate_caches"),
            (r"sys\.setdlopenflags\s*\(", "sys.setdlopenflags"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Bytecode manipulation: {label}",
                    description="Dynamic code loading - possible obfuscation",
                    severity=Severity.MEDIUM,
                    evidence=line[:150],
                    location=f"{self.path}:{lineno}",
                    fix="Review dynamic code loading purposes",
                    impact="May load malicious bytecode",
                )

    def _detect_import_hooks(self):
        """Detect custom import hooks and manipulators."""
        patterns = [
            (r"sys\.meta_path", "sys.meta_paths manipulation"),
            (r"sys\.path_hooks", "sys.path_hooks manipulation"),
            (r"importlib\.abc", "importlib.abc import"),
            (r"Finder\s*:\s*type\(.*MetaPathFinder", "Custom MetaPathFinder"),
            (r"Loader\s*:\s*type\(.*Loader", "Custom Loader"),
            (r"def\s+find_module\s*\(", "Custom find_module"),
            (r"def\s+load_module\s*\(", "Custom load_module"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Custom import hook: {label}",
                    description="Custom import system - can be used for supply chain attacks",
                    severity=Severity.HIGH,
                    evidence=line[:150],
                    location=f"{self.path}:{lineno}",
                    fix="Audit custom import hooks thoroughly",
                    impact="Module injection or modification possible",
                )

    def _detect_dynamic_code(self):
        """Detect dynamic code execution patterns."""
        patterns = [
            (r"eval\s*\(\s*[^)]*\)", "eval() call"),
            (r"exec\s*\(\s*[^)]*\)", "exec() call"),
            (r"compile\s*\([^,]+,[^,]+,[^)]+\)", "compile() call"),
            (r'__import__\s*\(\s*["\']', "__import__ dynamic"),
            (r'getattr\s*\([^,]+,\s*["\']', "getattr dynamic"),
            (r"setattr\s*\([^,]+,", "setattr dynamic"),
            (r"vars\s*\(\s*\)\s*\[", "vars() dictionary access"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                if "eval" in line.lower() or "exec" in line.lower():
                    self.add_finding(
                        title=f"Dynamic code execution: {label}",
                        description="Dynamic code execution - potential obfuscation",
                        severity=Severity.HIGH,
                        evidence=line[:150],
                        location=f"{self.path}:{lineno}",
                        fix="Review dynamic code execution purposes",
                        impact="Arbitrary code execution possible",
                    )

    def _detect_polyglot_patterns(self):
        """Detect polyglot / multi-format files."""
        content_start = self.content[:500]

        if "#!" in content_start and (
            "import" in content_start or "from" in content_start
        ):
            self.add_finding(
                title="Shebang + imports (polyglot)",
                description="File has both shebang and imports - may be polyglot",
                severity=Severity.MEDIUM,
                evidence=content_start[:100],
                location=self.path,
                fix="Analyze file carefully",
                impact="File may execute differently in different contexts",
            )

    def _detect_packed_payloads(self):
        """Detect packed executables in archives."""
        try:
            import zipfile

            if zipfile.is_zipfile(self.path):
                with zipfile.ZipFile(self.path) as zf:
                    for name in zf.namelist():
                        if any(
                            x in name.lower()
                            for x in [".pyd", ".so", ".dll", ".dylib", "stub", "loader"]
                        ):
                            self.add_finding(
                                title="Native library in archive",
                                description=f"Found native library: {name}",
                                severity=Severity.MEDIUM,
                                evidence=name,
                                location=self.path,
                                fix="Analyze native library",
                                impact="May contain malicious code",
                            )
        except Exception:
            pass

    def _detect_stub_loaders(self):
        """Detect stub loader patterns in archives."""
        stub_patterns = [
            b"__import__",
            b"eval(",
            b"exec(",
            b"base64",
            b"zlib",
            b"marshal",
        ]

        try:
            with open(self.path, "rb") as f:
                content = f.read(10000)

            for pattern in stub_patterns:
                if pattern in content:
                    self.add_finding(
                        title="Potential stub loader",
                        description=f"Found pattern: {pattern.decode()}",
                        severity=Severity.MEDIUM,
                        evidence=f"Pattern: {pattern.decode()}",
                        location=self.path,
                        fix="Analyze archive contents",
                        impact="May contain executable code",
                    )
        except Exception:
            pass
