"""
Behavioral Analysis Scanner
Detects anomalous behavior patterns, classifies package intent,
and identifies suspicious runtime characteristics.
"""

from __future__ import annotations
import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Optional

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class BehaviorScanner(BaseScanner):
    name = "behavior"

    SUSPICIOUS_BEHAVIORS = {
        "data_collection": [
            "os.environ",
            "os.getcwd",
            "socket.gethostname",
            "platform.node",
            "platform.machine",
            "uuid.getnode",
            "psutil.cpu_count",
            "psutil.virtual_memory",
            "psutil.disk_usage",
            "keyboard",
            "mouse",
            "screenshot",
            "record",
        ],
        "network_exfiltration": [
            "requests.post",
            "urllib.request.urlopen",
            "httpx.post",
            "aiohttp.ClientSession",
            "socket.send",
            "socket.sendto",
            "ftplib.FTP",
            "smtplib.SMTP",
            "requests.put",
        ],
        "file_exfiltration": [
            "open(path + filename",
            "glob.glob",
            "os.walk",
            "shutil.copy",
            "shutil.move",
            "tempfile",
        ],
        "persistence": [
            "cron",
            "systemd",
            "registry",
            "autostart",
            "launchagent",
            "bashrc",
            "profile",
            "init.d",
            "rc.local",
        ],
        "privilege_escalation": [
            "os.setuid",
            "os.setgid",
            "os.seteuid",
            "os.setegid",
            "pty.spawn",
            "tty.spawn",
        ],
        "crypto_mining": [
            "cryptography",
            "hashlib.scrypt",
            "hashlib.pbkdf2_hmac",
            "pool.nicehash",
            "stratum+tcp",
            "mine",
        ],
    }

    INTENT_PATTERNS = {
        "testing": ["pytest", "unittest", "mock", "fixture", "assert"],
        "data_processing": ["pandas", "numpy", "sklearn", "torch", "tensorflow"],
        "web_framework": ["flask", "django", "fastapi", "bottle", "tornado"],
        "api_client": ["requests", "httpx", "aiohttp", "urllib"],
        "ml_ai": ["transformers", "openai", "anthropic", "cohere"],
        "security": ["cryptography", "passlib", "bcrypt", "hashlib", "secrets"],
        "monitoring": ["logging", "sentry", "prometheus", "statsd"],
    }

    async def scan(self) -> list[ScannerResult]:
        if not self.path:
            return []

        if os.path.isdir(self.path):
            await self._scan_directory()
        elif self.path.endswith(".py"):
            await self._scan_file(self.path)

        return self.findings

    async def _scan_directory(self):
        """Scan all Python files in directory."""
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [
                d
                for d in dirs
                if d not in {".git", "__pycache__", "node_modules", "venv", ".venv"}
            ]

            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    await self._scan_file(file_path)

    async def _scan_file(self, file_path: str):
        """Scan a single file for behavioral patterns."""
        try:
            content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        rel_path = os.path.relpath(file_path, self.path) if self.path else file_path

        self._classify_intent(content, rel_path)
        self._detect_suspicious_behavior(content, rel_path)
        self._detect_anomaly_patterns(content, rel_path)
        self._profile_api_usage(content, rel_path)

    def _classify_intent(self, content: str, file_path: str):
        """Classify the likely intent of the code."""
        scores = {}

        for intent, keywords in self.INTENT_PATTERNS.items():
            score = sum(1 for kw in keywords if kw.lower() in content.lower())
            if score > 0:
                scores[intent] = score

        if scores:
            top_intent = max(scores, key=scores.get)

            if scores[top_intent] >= 3:
                self.add_finding(
                    title=f"Intent classification: {top_intent}",
                    description=f"Code appears to be primarily for: {top_intent}",
                    severity=Severity.INFO,
                    evidence=f"Matched keywords: {scores}",
                    location=file_path,
                    fix="None - informational",
                    impact="Understanding code purpose helps security assessment",
                )

    def _detect_suspicious_behavior(self, content: str, file_path: str):
        """Detect suspicious behavioral patterns."""
        for category, patterns in self.SUSPICIOUS_BEHAVIORS.items():
            for pattern in patterns:
                if pattern.lower() in content.lower():
                    severity = self._get_severity_for_category(category)

                    self.add_finding(
                        title=f"Suspicious behavior: {category}",
                        description=f"Code exhibits {category} behavior - pattern: {pattern}",
                        severity=severity,
                        evidence=f"Found: {pattern}",
                        location=file_path,
                        fix="Verify this behavior is intentional and legitimate",
                        impact=f"Potential {category} - review code purpose",
                    )

    def _detect_anomaly_patterns(self, content: str, file_path: str):
        """Detect anomalous patterns that don't match normal behavior."""
        anomalies = []

        if len(content) > 50000:
            anomalies.append(f"Large file: {len(content)} bytes")

        try:
            tree = ast.parse(content)

            function_count = sum(
                1
                for _ in ast.walk(tree)
                if isinstance(_, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            if function_count > 50:
                anomalies.append(f"Many functions: {function_count}")

            nested_depth = self._get_max_nesting(tree)
            if nested_depth > 6:
                anomalies.append(f"Deep nesting: {nested_depth} levels")

            if anomalies:
                for anomaly in anomalies[:3]:
                    self.add_finding(
                        title="Anomalous code pattern",
                        description=f"Anomalous pattern detected: {anomaly}",
                        severity=Severity.LOW,
                        evidence=anomaly,
                        location=file_path,
                        fix="Review code for unusual characteristics",
                        impact="May indicate obfuscation or complex logic",
                    )

        except SyntaxError:
            pass

    def _profile_api_usage(self, content: str, file_path: str):
        """Profile API usage patterns in the code."""
        api_calls = {
            "file_io": len(re.findall(r"\bopen\s*\(", content)),
            "network": len(
                re.findall(r"(requests\.|httpx\.|urllib\.|socket\.)", content)
            ),
            "subprocess": len(re.findall(r"subprocess\.", content)),
            "crypto": len(re.findall(r"(cryptography\.|hashlib\.|secrets\.)", content)),
            "database": len(
                re.findall(r"(sqlite3\.|psycopg2\.|pymongo\.|redis\.)", content)
            ),
            "os_operations": len(re.findall(r"os\.(system|popen|spawn)", content)),
        }

        high_risk_apis = sum(
            1 for k in ["subprocess", "os_operations"] if api_calls.get(k, 0) > 2
        )

        if high_risk_apis > 0:
            self.add_finding(
                title="High-risk API usage profile",
                description=f"Code uses {high_risk_apis} high-risk API categories extensively",
                severity=Severity.MEDIUM,
                evidence=str({k: v for k, v in api_calls.items() if v > 0}),
                location=file_path,
                fix="Review high-risk API usage for security",
                impact="High-risk APIs can lead to vulnerabilities",
            )

    def _get_severity_for_category(self, category: str) -> Severity:
        """Get severity level for a behavior category."""
        severity_map = {
            "data_collection": Severity.MEDIUM,
            "network_exfiltration": Severity.HIGH,
            "file_exfiltration": Severity.HIGH,
            "persistence": Severity.HIGH,
            "privilege_escalation": Severity.CRITICAL,
            "crypto_mining": Severity.HIGH,
        }
        return severity_map.get(category, Severity.LOW)

    def _get_max_nesting(self, tree: ast.AST) -> int:
        """Calculate maximum nesting depth in AST."""
        max_depth = 0

        class NestingVisitor(ast.NodeVisitor):
            def __init__(self):
                self.depth = 0
                self.max_depth = 0

            def visit(self, node):
                if isinstance(node, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                    self.depth += 1
                    self.max_depth = max(self.max_depth, self.depth)

                self.generic_visit(node)

                if isinstance(node, (ast.If, ast.While, ast.For, ast.With, ast.Try)):
                    self.depth -= 1

        visitor = NestingVisitor()
        visitor.visit(tree)
        return visitor.max_depth


def classify_package_intent(package_path: str) -> Dict[str, float]:
    """Classify a package's intent based on code analysis."""
    scores = {}

    for root, dirs, files in os.walk(package_path):
        for file in files:
            if file.endswith(".py"):
                try:
                    content = Path(os.path.join(root, file)).read_text()

                    for intent, keywords in BehaviorScanner.INTENT_PATTERNS.items():
                        score = sum(
                            1 for kw in keywords if kw.lower() in content.lower()
                        )
                        scores[intent] = scores.get(intent, 0) + score
                except Exception:
                    continue

    return scores
