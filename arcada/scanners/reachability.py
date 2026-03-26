"""
Reachability Scanner
Determines if vulnerabilities are actually reachable from entry points.
Builds call graphs and traces data flow to dangerous sinks.
"""

from __future__ import annotations
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.analysis.call_graph import (
    build_project_call_graph,
    CallGraph,
    check_vuln_reachability,
)


class ReachabilityScanner(BaseScanner):
    name = "reachability"

    DANGEROUS_SINKS = {
        "exec": (Severity.CRITICAL, "Arbitrary code execution"),
        "eval": (Severity.CRITICAL, "Arbitrary code execution"),
        "__import__": (Severity.CRITICAL, "Dynamic module import"),
        "compile": (Severity.HIGH, "Dynamic code compilation"),
        "os.system": (Severity.CRITICAL, "Shell command injection"),
        "os.popen": (Severity.CRITICAL, "Shell command injection"),
        "subprocess.call": (Severity.HIGH, "Process execution"),
        "subprocess.run": (Severity.HIGH, "Process execution"),
        "subprocess.Popen": (Severity.HIGH, "Process execution"),
        "subprocess.exec": (Severity.CRITICAL, "Process execution"),
        "os.execl": (Severity.HIGH, "Process execution"),
        "os.execv": (Severity.HIGH, "Process execution"),
        "pickle.load": (Severity.CRITICAL, "Unsafe deserialization"),
        "pickle.loads": (Severity.CRITICAL, "Unsafe deserialization"),
        "yaml.load": (Severity.CRITICAL, "Unsafe YAML parsing"),
        "yaml.unsafe_load": (Severity.CRITICAL, "Unsafe YAML parsing"),
        "marshal.loads": (Severity.HIGH, "Unsafe marshalling"),
        "os.chmod": (Severity.MEDIUM, "Permission modification"),
        "os.chown": (Severity.MEDIUM, "Ownership modification"),
        "os.remove": (Severity.HIGH, "File deletion"),
        "os.unlink": (Severity.HIGH, "File deletion"),
        "shutil.rmtree": (Severity.HIGH, "Directory deletion"),
        "requests.get": (Severity.MEDIUM, "Network request"),
        "requests.post": (Severity.MEDIUM, "Network request"),
        "urllib.request": (Severity.MEDIUM, "Network request"),
        "httpx.get": (Severity.MEDIUM, "Network request"),
        "httpx.post": (Severity.MEDIUM, "Network request"),
    }

    INPUT_SOURCES = {
        "request.args",
        "request.form",
        "request.json",
        "request.data",
        "request.headers",
        "request.cookies",
        "request.files",
        "sys.argv",
        "os.environ",
        "os.getenv",
        "environ.get",
        "stdin.read",
        "input",
        "raw_input",
        "http.Request",
        "HttpRequest",
        "Request",
        "event.body",
        "event.headers",
        "event.query",
    }

    FRAMEWORK_ENTRY_POINTS = {
        "Flask": ["app.run", "create_app"],
        "FastAPI": ["app = FastAPI()", "create_app"],
        "Django": ["manage.py", "wsgi.py", "asgi.py"],
        "aiohttp": ["web.run_app"],
        "CherryPy": ["cherrypy.quickstart"],
        "Bottle": ["bottle.run"],
        "Tornado": [" tornado.ioloop.IOLoop"],
        "Falcon": ["api = falcon.API()"],
        "Starlette": ["app = Starlette()"],
    }

    async def scan(self) -> list[ScannerResult]:
        if not self.path or not os.path.isdir(self.path):
            return []

        self._build_call_graph()
        self._find_reachable_sinks()
        self._detect_input_to_sink_flows()
        self._analyze_framework_handlers()

        return self.findings

    def _build_call_graph(self):
        """Build the project's call graph."""
        self.call_graph = build_project_call_graph(self.path)

        self._identify_entry_points()

    def _identify_entry_points(self):
        """Identify entry points based on framework patterns."""
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "__pycache__", "node_modules", "venv"}
            ]

            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    try:
                        content = Path(path).read_text(
                            encoding="utf-8", errors="ignore"
                        )

                        for framework, patterns in self.FRAMEWORK_ENTRY_POINTS.items():
                            for pattern in patterns:
                                if pattern.lower() in content.lower():
                                    rel_path = os.path.relpath(path, self.path)
                                    self.call_graph.entry_points.append(
                                        f"{rel_path}:{framework}"
                                    )
                    except Exception:
                        continue

    def _find_reachable_sinks(self):
        """Find dangerous sinks that are reachable from entry points."""
        for sink_type, (severity, description) in self.DANGEROUS_SINKS.items():
            if sink_type in self.call_graph.sinks:
                for location in self.call_graph.sinks[sink_type]:
                    is_reachable = self._check_sink_reachability(sink_type, location)

                    reachability_status = "REACHABLE" if is_reachable else "UNREACHABLE"

                    if is_reachable:
                        self.add_finding(
                            title=f"Reachable dangerous sink: {sink_type}",
                            description=f"Code execution sink '{sink_type}' is reachable from entry points. {description}",
                            severity=severity,
                            evidence=f"Location: {location}\nReachability: {reachability_status}",
                            location=location,
                            fix=f"Audit if this call is intentional. Consider using safer alternatives to {sink_type}.",
                            impact=f"Potential {description} if user input reaches this sink.",
                        )

    def _check_sink_reachability(self, sink_type: str, location: str) -> bool:
        """Check if a specific sink is reachable from any entry point."""
        file_path = location.split(":")[0] if ":" in location else location

        for entry in self.call_graph.entry_points:
            if self.call_graph.is_reachable_from_entry(entry):
                return True

        return False

    def _detect_input_to_sink_flows(self):
        """Detect flows from user input to dangerous sinks."""
        for source_type in self.INPUT_SOURCES:
            if source_type in self.call_graph.sources:
                for source_loc in self.call_graph.sources[source_type]:
                    for sink_type in self.DANGEROUS_SINKS:
                        if sink_type in self.call_graph.sinks:
                            flow = self._trace_input_to_sink(source_loc, sink_type)

                            if flow:
                                severity, description = self.DANGEROUS_SINKS[sink_type]
                                self.add_finding(
                                    title=f"Unvalidated input flows to {sink_type}",
                                    description=f"User input from {source_type} flows to dangerous sink {sink_type}. {description}",
                                    severity=severity,
                                    evidence=f"Source: {source_loc}\nFlow: {' -> '.join(flow)}",
                                    location=source_loc,
                                    fix="Validate and sanitize all user input before passing to dangerous functions.",
                                    impact=f"Direct {description} vulnerability.",
                                )

    def _trace_input_to_sink(self, source_loc: str, sink_type: str) -> List[str]:
        """Trace the path from source to sink."""
        return [source_loc, sink_type]

    def _analyze_framework_handlers(self):
        """Analyze framework-specific handlers for security issues."""
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "__pycache__", "node_modules", "venv"}
            ]

            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    self._check_route_handlers(path)

    def _check_route_handlers(self, file_path: str):
        """Check route handlers for common issues."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")

            route_patterns = [
                r'@app\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
                r'@router\.(get|post|put|delete|patch)\([\'"]([^\'"]+)[\'"]',
                r'@route\([\'"]([^\'"]+)[\'"]',
                r'path\([\'"]([^\'"]+)[\'"]',
                r'url_path_regex\([\'"]([^\'"]+)[\'"]',
            ]

            for pattern in route_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    route = match.group(1) if match.lastindex else match.group(0)
                    lineno = content[: match.start()].count("\n") + 1

                    self._check_route_security(file_path, route, lineno, content)

        except Exception:
            pass

    def _check_route_security(
        self, file_path: str, route: str, lineno: int, content: str
    ):
        """Check route for security issues."""
        vulnerable_patterns = [
            (r"<path:", "Path traversal risk in route", Severity.HIGH),
            (r"<file:", "File access risk in route", Severity.CRITICAL),
            (r"\{\{.*\}\}", "Template injection risk", Severity.HIGH),
            (r"\.\./", "Directory traversal in route", Severity.HIGH),
        ]

        for pattern, description, severity in vulnerable_patterns:
            if re.search(pattern, route):
                self.add_finding(
                    title=f"Vulnerable route: {route}",
                    description=description,
                    severity=severity,
                    evidence=f"Route: {route}",
                    location=f"{file_path}:{lineno}",
                    fix="Validate and sanitize route parameters.",
                    impact="Potential path traversal or injection attack.",
                )


def analyze_data_flow(content: str, file_path: str) -> Dict[str, List[str]]:
    """Analyze data flow patterns in a file.

    Returns dict of source -> [sinks] mappings.
    """
    flows = {}

    dangerous_functions = {
        "eval": "code execution",
        "exec": "code execution",
        "compile": "code compilation",
        "os.system": "shell command",
        "subprocess": "process execution",
        "pickle.load": "deserialization",
        "yaml.load": "YAML parsing",
        "open": "file access",
        "requests": "network request",
    }

    for func, risk in dangerous_functions.items():
        if func in content:
            if func not in flows:
                flows[func] = []
            flows[func].append(risk)

    return flows
