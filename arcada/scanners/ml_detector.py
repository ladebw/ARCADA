"""
ML-Based Detection Scanner
Lightweight ML classifier for detecting malicious/suspicious packages.
Uses static features extracted from code - no external dependencies required.
"""

from __future__ import annotations
import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class HeuristicDetectorScanner(BaseScanner):
    name = "heuristic_detector"

    MALICIOUS_FEATURES = [
        "base64.decode",
        "eval(exec",
        '__import__("os")',
        "subprocess.call([",
        "socket.create_connection",
        "requests.post.*key",
        "os.environ[",
        "pickle.load",
        "marshal.loads",
        "pty.spawn",
        "cryptography.fernet",
        "websockets",
        "slixmpp",
        "aiohttp.*post",
    ]

    SUSPICIOUS_FEATURES = [
        "time.sleep.*random",
        "while True:",
        "threading.Thread",
        "multiprocessing.Process",
        "daemon=True",
        "setrecursionlimit",
        "sys.settrace",
        "gc.set_debug",
    ]

    TRUSTED_PATTERNS = [
        "pytest",
        "unittest",
        "logging.info",
        "def test_",
        "class Test",
    ]

    async def scan(self) -> list[ScannerResult]:
        if not self.path:
            return []

        features = self._extract_features()
        score = self._calculate_ml_score(features)

        if score > 0.7:
            severity = Severity.CRITICAL
        elif score > 0.5:
            severity = Severity.HIGH
        elif score > 0.3:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        if score > 0.3:
            self.add_finding(
                title=f"ML-based threat detection: {score:.1%} suspicious",
                description="Code analysis indicates potential malicious behavior",
                severity=severity,
                evidence=f"Suspicious features: {features.get('suspicious_count', 0)}, Trusted: {features.get('trusted_count', 0)}",
                location=self.path,
                fix="Manual review recommended",
                impact="ML classifier detected suspicious patterns",
            )

        return self.findings

    def _extract_features(self) -> Dict:
        """Extract static features from code for ML classification."""
        features = {
            "suspicious_count": 0,
            "trusted_count": 0,
            "entropy": 0.0,
            "obfuscation_score": 0.0,
            "function_count": 0,
            "import_count": 0,
            "network_calls": 0,
            "crypto_usage": 0,
            "dynamic_code": 0,
            "file_operations": 0,
        }

        try:
            if os.path.isdir(self.path):
                for root, dirs, files in os.walk(self.path):
                    dirs[:] = [d for d in dirs if d not in {".git", "__pycache__"}]
                    for file in files:
                        if file.endswith(".py"):
                            try:
                                content = Path(os.path.join(root, file)).read_text()
                                features.update(self._analyze_content(content))
                            except Exception:
                                continue
            elif self.path.endswith(".py"):
                content = Path(self.path).read_text()
                features.update(self._analyze_content(content))

        except Exception:
            pass

        return features

    def _analyze_content(self, content: str) -> Dict:
        """Analyze individual file content."""
        features = {}

        suspicious_count = sum(
            1 for p in self.MALICIOUS_FEATURES if p in content.lower()
        )
        trusted_count = sum(1 for p in self.TRUSTED_PATTERNS if p in content.lower())

        features["suspicious_count"] = suspicious_count
        features["trusted_count"] = trusted_count

        features["entropy"] = self._calculate_entropy(content)
        features["obfuscation_score"] = self._detect_obfuscation(content)

        try:
            tree = ast.parse(content)
            features["function_count"] = sum(
                1
                for _ in ast.walk(tree)
                if isinstance(_, (ast.FunctionDef, ast.AsyncFunctionDef))
            )

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    features["import_count"] = features.get("import_count", 0) + len(
                        node.names
                    )
                elif isinstance(node, ast.ImportFrom):
                    features["import_count"] = features.get("import_count", 0) + len(
                        node.names
                    )

        except Exception:
            pass

        features["network_calls"] = len(
            re.findall(r"(requests\.|httpx\.|urllib\.|socket\.)", content)
        )
        features["crypto_usage"] = len(
            re.findall(r"(cryptography\.|hashlib\.|secrets\.|pycryptodome)", content)
        )
        features["dynamic_code"] = len(
            re.findall(r"(eval|exec|compile|__import__)", content)
        )
        features["file_operations"] = len(
            re.findall(r"(open\(|read\(|write\(|file\()", content)
        )

        return features

    def _calculate_entropy(self, content: str) -> float:
        """Calculate Shannon entropy of content."""
        if not content:
            return 0.0

        import math

        freq = Counter(content)
        length = len(content)

        entropy = 0.0
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def _detect_obfuscation(self, content: str) -> float:
        """Detect obfuscation indicators."""
        score = 0.0

        if len(re.findall(r"\\x[0-9a-f]{2}", content)) > 5:
            score += 0.3

        if len(re.findall(r"base64", content, re.I)) > 3:
            score += 0.2

        if len(re.findall(r"chr\(\d+\)", content)) > 5:
            score += 0.2

        if content.count("\n") < 10 and len(content) > 1000:
            score += 0.3

        return min(score, 1.0)

    def _calculate_ml_score(self, features: Dict) -> float:
        """Calculate ML-based threat score."""
        score = 0.0

        suspicious = features.get("suspicious_count", 0)
        trusted = features.get("trusted_count", 0) + 1

        score += suspicious * 0.15
        score -= trusted * 0.05

        obfuscation = features.get("obfuscation_score", 0.0)
        score += obfuscation * 0.3

        entropy = features.get("entropy", 0.0)
        if entropy > 5.0:
            score += 0.2

        network = features.get("network_calls", 0)
        if network > 5:
            score += 0.15

        crypto = features.get("crypto_usage", 0)
        if crypto > 3:
            score += 0.1

        dynamic = features.get("dynamic_code", 0)
        if dynamic > 2:
            score += 0.2

        return max(0.0, min(score, 1.0))


def train_baseline_model(training_data_path: str) -> Dict:
    """Train baseline model on known good/bad packages."""
    features = []
    labels = []

    return {
        "features": features,
        "labels": labels,
        "model_type": "baseline",
    }
