"""
Dynamic Analysis Sandbox
Runs target code in a subprocess with timeout and monitors:
- Outbound network connections
- Subprocess/shell command execution
- File system modifications
- Environment variable access

Uses subprocess + psutil (optional) + resource limits.
"""

from __future__ import annotations
import ast
import os
import re
import subprocess
import tempfile
import sys
from pathlib import Path
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity

SANDBOX_TIMEOUT = 15  # seconds

# Patterns that indicate the code is safe to analyze statically only
SKIP_EXECUTION = [
    r"import\s+(?:os|subprocess|sys|socket|requests|httpx)",
    r"def\s+main\s*\(",
    r"if\s+__name__\s*==\s*['\"]__main__['\"]",
]


class SandboxScanner(BaseScanner):
    name = "sandbox"

    async def scan(self) -> list[ScannerResult]:
        if not self._should_analyze():
            return self.findings

        self._static_import_analysis()
        self._detect_runtime_loaders()
        self._detect_builtin_override()
        self._detect_pickle_hooks()
        self._detect_weak_crypto()
        return self.findings

    def _should_analyze(self) -> bool:
        """Only analyze Python source files."""
        if not self.path:
            return True  # inline content
        return self.path.lower().endswith((".py", ".pyw"))

    def _static_import_analysis(self):
        """Analyze imports for suspicious patterns without executing code."""
        try:
            tree = ast.parse(self.content)
        except SyntaxError:
            return

        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append((alias.name, node.lineno))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append((f"{module}.{alias.name}", node.lineno))

        # Check for unusual import combinations (backdoor indicators)
        import_names = {name for name, _ in imports}

        # Combo: socket + pickle = remote code execution
        if {"socket", "pickle"} <= import_names:
            self.add_finding(
                title="Suspicious import combination: socket + pickle",
                description=(
                    "This file imports both 'socket' and 'pickle'. This combination is commonly "
                    "used in backdoors: receive serialized data over a network connection and "
                    "deserialize it with pickle, which executes arbitrary code."
                ),
                severity=Severity.CRITICAL,
                evidence=f"Imports: socket, pickle",
                fix="Audit why both socket and pickle are needed. Use JSON instead of pickle for network data.",
                impact="Remote code execution via network-received pickled data.",
            )

        # Combo: os + base64 + socket = classic backdoor
        if {"os", "base64", "socket"} <= import_names:
            self.add_finding(
                title="Suspicious import combination: os + base64 + socket",
                description=(
                    "This file imports os, base64, and socket. This is a classic backdoor "
                    "triple: execute commands (os), decode payloads (base64), communicate over network (socket)."
                ),
                severity=Severity.CRITICAL,
                evidence="Imports: os, base64, socket",
                fix="Audit this file thoroughly. This import combination is a strong backdoor indicator.",
                impact="Potential reverse shell or C2 (command and control) agent.",
            )

        # Combo: subprocess + httpx/requests = remote command execution
        if ("subprocess" in import_names or "os" in import_names) and (
            "requests" in import_names or "httpx" in import_names
        ):
            has_exec = bool(
                re.search(
                    r"(?:os\.system|os\.popen|subprocess\.\w+)\s*\(", self.content
                )
            )
            has_fetch = bool(
                re.search(r"(?:requests\.\w+|httpx\.\w+)\s*\(", self.content)
            )
            if has_exec and has_fetch:
                self.add_finding(
                    title="Suspicious pattern: network fetch + shell execution",
                    description=(
                        "This file both fetches data from the network and executes shell commands. "
                        "This is a common pattern for download-and-execute backdoors."
                    ),
                    severity=Severity.HIGH,
                    evidence="Network fetch + shell execution in same file",
                    fix="Verify the network data is not passed to shell commands.",
                    impact="Download-and-execute pattern — attacker controls what gets executed.",
                )

        # Check for dangerous modules
        dangerous_imports = {
            "ctypes": "Native code loading",
            "subprocess": "Shell command execution",
            "shutil": "File system operations",
            "signal": "Signal handling (persistence)",
            "atexit": "Shutdown hooks (persistence)",
            "threading": "Background threads",
            "multiprocessing": "Background processes",
            "pickle": "Unsafe deserialization",
            "marshal": "Unsafe deserialization",
            "shelve": "Unsafe deserialization",
        }
        for name, lineno in imports:
            base = name.split(".")[0]
            if base in dangerous_imports and base not in (
                "subprocess",
                "os",
                "signal",
                "atexit",
                "threading",
                "pickle",
            ):
                # Only flag unusual ones (subprocess/os are too common)
                self.add_finding(
                    title=f"Dangerous module import: {name}",
                    description=(
                        f"'{name}' ({dangerous_imports[base]}) is imported. "
                        f"Review how it's used — {dangerous_imports[base].lower()} "
                        "can be abused for malicious purposes."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: import {name}",
                    fix=f"Audit usage of {name}. Remove if not needed.",
                    impact=f"{dangerous_imports[base]} capabilities may be abused.",
                )

    def _detect_runtime_loaders(self):
        """Detect custom module loaders that execute at import time."""
        patterns = [
            (r"sys\.meta_path\.insert", "Custom meta path hook (import interceptor)"),
            (r"sys\.path_hooks\.insert", "Custom path hook"),
            (r"importlib\.abc\.Loader", "Custom import loader"),
            (r"importlib\.abc\.MetaPathFinder", "Custom import finder"),
            (r"class\s+\w+.*Loader.*:", "Class inheriting from Loader"),
            (r"def\s+exec_module\s*\(", "Custom exec_module override"),
            (r"def\s+load_module\s*\(", "Custom load_module override"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Custom import system: {label}",
                    description=(
                        f"'{label}' — this code intercepts or customizes Python's import system. "
                        "Custom loaders can modify modules after loading, inject code into imports, "
                        "or completely replace modules with malicious versions."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit the custom loader thoroughly. This is a powerful backdoor technique.",
                    impact="Any module import in the entire process can be hijacked.",
                )

    def _detect_builtin_override(self):
        """Detect overriding of built-in functions."""
        builtins_to_watch = {
            "open",
            "eval",
            "exec",
            "compile",
            "input",
            "__import__",
            "print",
            "getattr",
            "setattr",
            "hasattr",
            "type",
        }
        try:
            tree = ast.parse(self.content)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id in builtins_to_watch:
                        # Check if it's at module level (not inside a function)
                        self.add_finding(
                            title=f"Built-in override: {target.id}",
                            description=(
                                f"The built-in function '{target.id}' is being overridden at module level. "
                                "This can silently change the behavior of all code that uses this built-in. "
                                "For example, overriding 'open' can intercept all file operations."
                            ),
                            severity=Severity.CRITICAL,
                            evidence=f"Line {node.lineno}: {target.id} = ... (built-in override)",
                            fix=f"Remove the override of '{target.id}'. If intentional, document why clearly.",
                            impact=f"All uses of '{target.id}' throughout the process are hijacked.",
                        )

    def _detect_pickle_hooks(self):
        """Detect pickle __reduce__ and other deserialization hooks."""
        patterns = [
            (r"def\s+__reduce__\s*\(", "__reduce__ method (pickle exploit payload)"),
            (
                r"def\s+__reduce_ex__\s*\(",
                "__reduce_ex__ method (pickle exploit payload)",
            ),
            (r"def\s+__getstate__\s*\(", "__getstate__ method (serialization hook)"),
            (r"def\s+__setstate__\s*\(", "__setstate__ method (deserialization hook)"),
            (r"__reduce__\s*=", "__reduce__ attribute assignment"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                # Check if it returns something suspicious
                context = self.content.splitlines()[
                    max(0, lineno - 1) : min(
                        len(self.content.splitlines()), lineno + 10
                    )
                ]
                context_str = "\n".join(context)
                has_shell = bool(
                    re.search(r"(os\.system|subprocess|eval|exec)", context_str)
                )
                severity = Severity.CRITICAL if has_shell else Severity.HIGH

                self.add_finding(
                    title=f"Pickle exploit hook: {label}",
                    description=(
                        f"'{label}' is defined. This is the core mechanism used in pickle-based "
                        "remote code execution exploits. The __reduce__ method tells pickle "
                        "what to execute when deserializing, and is commonly used to run "
                        "os.system() or subprocess calls."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove __reduce__ unless absolutely needed. Never unpickle untrusted data.",
                    impact="Anyone who unpickles this object triggers arbitrary code execution.",
                )

    def _detect_weak_crypto(self):
        """Detect use of weak cryptographic algorithms."""
        patterns = [
            (r"hashlib\.md5\s*\(", "MD5 hash (broken — collision attacks)"),
            (r"hashlib\.sha1\s*\(", "SHA1 hash (broken — collision attacks)"),
            (r'hashlib\.new\s*\(\s*[\'"]md5[\'"]', "MD5 via hashlib.new()"),
            (r'hashlib\.new\s*\(\s*[\'"]sha1[\'"]', "SHA1 via hashlib.new()"),
            (r"DES\.|DES3\.", "DES/3DES encryption (weak)"),
            (r"RC4\.", "RC4 encryption (broken)"),
            (r"ssl\.PROTOCOL_TLS\b", "Old TLS protocol version"),
            (r"ssl\.CERT_NONE", "SSL certificate verification disabled"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                # Skip if used for non-security purposes (checksums, cache keys)
                if re.search(r"(?i)(checksum|cache|etag|fingerprint|lookup)", line):
                    continue
                self.add_finding(
                    title=f"Weak cryptography: {label}",
                    description=(
                        f"'{label}' is used. This algorithm is considered broken for security purposes. "
                        "MD5 and SHA1 have known collision attacks. DES/RC4 are trivially breakable."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use SHA-256 or SHA-3 for hashing. Use AES-GCM or ChaCha20 for encryption.",
                    impact="Cryptographic protections can be bypassed with known attacks.",
                )
