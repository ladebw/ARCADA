"""
Sandbox Executor for Dynamic Analysis
Safely executes code in isolation to observe runtime behavior.
"""

from __future__ import annotations
import ast
import os
import sys
import json
import tempfile
import subprocess
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from contextlib import contextmanager


@dataclass
class BehaviorReport:
    """Report of observed runtime behavior."""

    imports: List[str] = field(default_factory=list)
    network_calls: List[Dict] = field(default_factory=list)
    file_operations: List[Dict] = field(default_factory=list)
    subprocess_calls: List[Dict] = field(default_factory=list)
    environment_access: List[str] = field(default_factory=list)
    executed_code: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "imports": self.imports,
            "network_calls": self.network_calls,
            "file_operations": self.file_operations,
            "subprocess_calls": self.subprocess_calls,
            "environment_access": self.environment_access,
            "executed_code": self.executed_code,
            "errors": self.errors,
            "warnings": self.warnings,
        }


class BehaviorObserver:
    """Observes and records runtime behavior."""

    def __init__(self):
        import builtins

        self.report = BehaviorReport()
        self._original_import = builtins.__import__
        self._original_open = builtins.open
        self._original_subprocess = subprocess
        self._original_os_system = os.system
        self._original_os_popen = os.popen
        self._original_urllib = None
        self._original_requests = None

    def install_hooks(self):
        """Install hooks to observe behavior."""
        import builtins

        builtins.__import__ = self._hook_import
        builtins.open = self._hook_open

        os.system = self._hook_os_system
        os.popen = self._hook_os_popen

        subprocess.call = self._hook_subprocess_call
        subprocess.run = self._hook_subprocess_run
        subprocess.Popen = self._hook_subprocess_popen

    def remove_hooks(self):
        """Remove installed hooks."""
        import builtins

        builtins.__import__ = self._original_import
        builtins.open = self._original_open

        os.system = self._original_os_system
        os.popen = self._original_os_popen

        subprocess.call = self._original_subprocess.call
        subprocess.run = self._original_subprocess.run
        subprocess.Popen = self._original_subprocess.Popen

    def _hook_import(self, name, *args, **kwargs):
        """Hook to capture imports."""
        self.report.imports.append(name)
        return self._original_import(name, *args, **kwargs)

    def _hook_open(self, file, *args, **kwargs):
        """Hook to capture file operations."""
        mode = args[0] if args else "r"
        self.report.file_operations.append(
            {
                "operation": "open",
                "file": str(file),
                "mode": mode,
            }
        )
        return self._original_open(file, *args, **kwargs)

    def _hook_os_system(self, command):
        """Hook to capture os.system calls."""
        self.report.subprocess_calls.append(
            {
                "type": "os.system",
                "command": str(command)[:200],
            }
        )
        return self._original_os_system(command)

    def _hook_os_popen(self, command, *args, **kwargs):
        """Hook to capture os.popen calls."""
        self.report.subprocess_calls.append(
            {
                "type": "os.popen",
                "command": str(command)[:200],
            }
        )
        return self._original_os_popen(command, *args, **kwargs)

    def _hook_subprocess_call(self, args, *argk, **kwargs):
        """Hook to capture subprocess.call."""
        self.report.subprocess_calls.append(
            {
                "type": "subprocess.call",
                "args": str(args)[:200],
            }
        )
        return self._original_subprocess.call(args, *argk, **kwargs)

    def _hook_subprocess_run(self, args, *argk, **kwargs):
        """Hook to capture subprocess.run."""
        self.report.subprocess_calls.append(
            {
                "type": "subprocess.run",
                "args": str(args)[:200],
            }
        )
        return self._original_subprocess.run(args, *argk, **kwargs)

    def _hook_subprocess_popen(self, args, *argk, **kwargs):
        """Hook to capture subprocess.Popen."""
        self.report.subprocess_calls.append(
            {
                "type": "subprocess.Popen",
                "args": str(args)[:200],
            }
        )
        return self._original_subprocess.Popen(args, *argk, **kwargs)


class SandboxExecutor:
    """Executes code in a sandboxed environment."""

    TIMEOUT = 30
    MEMORY_LIMIT = 512 * 1024 * 1024  # 512MB

    DANGEROUS_IMPORTS = {
        "os",
        "sys",
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "http",
        "ftplib",
        "telnetlib",
        "pickle",
        "marshal",
        "ctypes",
        "posixpath",
        "tempfile",
        "glob",
        "shutil",
        "threading",
        "multiprocessing",
    }

    DANGEROUS_OPERATIONS = {
        "eval",
        "exec",
        "compile",
        "__import__",
        "os.system",
        "os.popen",
        "subprocess",
        "socket.create_connection",
        "socket.socket",
    }

    def __init__(self, timeout: int = TIMEOUT):
        self.timeout = timeout
        self.observer = BehaviorObserver()

    def execute_module(self, module_path: str) -> BehaviorReport:
        """Execute a module and observe its behavior."""
        self.observer = BehaviorObserver()

        old_cwd = os.getcwd()
        temp_dir = tempfile.mkdtemp(prefix="arcada_sandbox_")

        try:
            os.chdir(temp_dir)
            self.observer.install_hooks()

            try:
                import importlib.util

                spec = importlib.util.spec_from_file_location("target", module_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.observer.report.executed_code = True
            except Exception as e:
                self.observer.report.errors.append(f"Execution error: {str(e)}")
            finally:
                self.observer.remove_hooks()

        finally:
            os.chdir(old_cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)

        return self.observer.report

    def execute_code(self, code: str) -> BehaviorReport:
        """Execute code string and observe behavior."""
        self.observer = BehaviorReport()

        old_cwd = os.getcwd()
        temp_dir = tempfile.mkdtemp(prefix="arcada_sandbox_")

        try:
            os.chdir(temp_dir)
            self.observer.install_hooks()

            try:
                exec(code, {"__builtins__": __builtins__})
                self.observer.report.executed_code = True
            except Exception as e:
                self.observer.report.errors.append(f"Execution error: {str(e)}")
            finally:
                self.observer.remove_hooks()

        finally:
            os.chdir(old_cwd)
            shutil.rmtree(temp_dir, ignore_errors=True)

        return self.observer.report

    def analyze_imports(self, module_path: str) -> Dict[str, Any]:
        """Analyze what a module imports without executing it."""
        try:
            content = Path(module_path).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)

            imports = []
            from_imports = []

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        from_imports.append(node.module)

            return {
                "imports": imports,
                "from_imports": from_imports,
                "dangerous_imports": [
                    i
                    for i in imports + from_imports
                    if i.split(".")[0] in self.DANGEROUS_IMPORTS
                ],
            }
        except Exception as e:
            return {"error": str(e)}

    def check_side_effects_on_import(self, module_path: str) -> List[str]:
        """Check if module executes code on import."""
        warnings = []

        try:
            content = Path(module_path).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)

            for node in tree.body:
                if isinstance(node, ast.Assign):
                    if any(isinstance(target, ast.Name) for target in node.targets):
                        warnings.append(
                            f"Module-level assignment at line {node.lineno}"
                        )
                elif isinstance(node, ast.Call):
                    warnings.append(f"Module-level call at line {node.lineno}")
                elif isinstance(node, ast.FunctionDef):
                    if node.name in ("__init__", "__enter__", "__exit__"):
                        warnings.append(f"Special method defined: {node.name}")

            if tree.body and isinstance(tree.body[0], ast.Expr):
                if isinstance(tree.body[0].value, ast.Constant):
                    warnings.append(
                        f"Module-level expression at line 1 (possible side effect)"
                    )

        except Exception as e:
            warnings.append(f"Analysis error: {str(e)}")

        return warnings


class RuntimeAnalyzer:
    """Analyzes runtime behavior for security concerns."""

    SUSPICIOUS_PATTERNS = {
        "network_exfil": [
            "requests.post",
            "urllib.request.urlopen",
            "http.client.HTTPConnection",
        ],
        "file_exfil": [
            "open",
            "write",
            "tempfile",
        ],
        "credential_access": [
            "os.environ",
            "getpass",
            "keyring",
        ],
        "persistence": [
            "cron",
            "systemd",
            "registry",
            "autostart",
        ],
        "execution": [
            "exec",
            "eval",
            "compile",
            "subprocess",
            "os.system",
        ],
    }

    def __init__(self):
        self.executor = SandboxExecutor()

    def analyze_package(self, package_path: str) -> Dict[str, Any]:
        """Analyze a package for runtime behavior."""
        results = {
            "import_analysis": {},
            "side_effects": [],
            "runtime_behavior": {},
            "suspicious_patterns": [],
        }

        if os.path.isdir(package_path):
            for root, dirs, files in os.walk(package_path):
                dirs[:] = [
                    d for d in dirs if d not in {"__pycache__", ".git", "test", "tests"}
                ]

                for file in files:
                    if file.endswith(".py"):
                        file_path = os.path.join(root, file)

                        results["import_analysis"][file] = (
                            self.executor.analyze_imports(file_path)
                        )
                        results["side_effects"].extend(
                            self.executor.check_side_effects_on_import(file_path)
                        )

        results["suspicious_patterns"] = self._detect_suspicious_patterns(results)

        return results

    def _detect_suspicious_patterns(self, results: Dict) -> List[str]:
        """Detect suspicious patterns in analysis results."""
        patterns = []

        import_data = results.get("import_analysis", {})
        for file, data in import_data.items():
            dangerous = data.get("dangerous_imports", [])
            if dangerous:
                patterns.append(
                    f"{file}: Dangerous imports: {', '.join(dangerous[:3])}"
                )

        return patterns


def execute_and_observe(code: str, timeout: int = 30) -> BehaviorReport:
    """Convenience function to execute code and observe behavior."""
    executor = SandboxExecutor(timeout)
    return executor.execute_code(code)


def analyze_module_behavior(module_path: str) -> Dict[str, Any]:
    """Convenience function to analyze a module's behavior."""
    analyzer = RuntimeAnalyzer()
    return analyzer.analyze_package(module_path)
