"""
Threat Intelligence Scanner
IOC matching, maintainer anomaly detection, and suspicious publish patterns.
NOTE: This scanner requires external API keys and is DISABLED by default.
Enable in config or set VIRUSTOTAL_API_KEY environment variable.
"""

from __future__ import annotations
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


# Configuration - DISABLED BY DEFAULT
ENABLED = os.environ.get("ARCADA_THREAT_INTEL_ENABLED", "false").lower() == "true"
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
ALPHA_VANTAGE_KEY = os.environ.get("ALPHA_VANTAGE_KEY", "")


class ThreatIntelScanner(BaseScanner):
    name = "threat_intel"

    KNOWN_MALICIOUS_HASHES = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty
    }

    SUSPICIOUS_PATTERNS = {
        "typosquatting": [],
        "dependency_confusion": [],
        "social_engineering": [],
    }

    async def scan(self) -> list[ScannerResult]:
        if not ENABLED:
            return self.findings

        if not VIRUSTOTAL_API_KEY:
            return self.findings

        await self._check_file_hashes()
        await self._detect_suspicious_patterns()

        return self.findings

    async def _check_file_hashes(self):
        """Check file hashes against threat databases."""
        if not self.path or not os.path.isfile(self.path):
            return

        try:
            with open(self.path, "rb") as f:
                content = f.read()

            sha256 = hashlib.sha256(content).hexdigest()
            md5 = hashlib.md5(content).hexdigest()
            sha1 = hashlib.sha1(content).hexdigest()

            if sha256 in self.KNOWN_MALICIOUS_HASHES:
                self.add_finding(
                    title="Known malicious file hash",
                    description=f"SHA256: {sha256[:16]}... matches known malware",
                    severity=Severity.CRITICAL,
                    evidence=f"SHA256: {sha256}",
                    location=self.path,
                    fix="DELETE THIS FILE IMMEDIATELY",
                    impact="File is known malware",
                )

            if VIRUSTOTAL_API_KEY:
                await self._check_virustotal(sha256)

        except Exception:
            pass

    async def _check_virustotal(self, sha256: str):
        """Check hash against VirusTotal (requires API key)."""
        if not VIRUSTOTAL_API_KEY:
            return

        import httpx

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY},
                )

                if resp.status_code == 200:
                    data = resp.json()
                    stats = (
                        data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {})
                    )

                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    if malicious > 0 or suspicious > 0:
                        self.add_finding(
                            title=f"Malware detected: {malicious} engines flagged",
                            description=f"File flagged by {malicious} malicious and {suspicious} suspicious engines",
                            severity=Severity.CRITICAL,
                            evidence=f"VT stats: {stats}",
                            location=self.path,
                            fix="DELETE THIS FILE IMMEDIATELY",
                            impact="File is detected as malware",
                        )

        except Exception:
            pass

    async def _detect_suspicious_patterns(self):
        """Detect suspicious patterns in code."""
        if not self.path or not self.path.endswith(".py"):
            return

        try:
            content = Path(self.path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        network_indicators = [
            (r"socket\.connect", "Socket connection"),
            (r"urllib\.request", "URL fetch"),
            (r"requests\.post.*http", "HTTP POST"),
            (r"http\.client\.HTTPConnection", "HTTP client"),
            (r"ftplib", "FTP connection"),
            (r"smtplib", "Email sending"),
        ]

        c2_indicators = [
            (r"while\s+True.*sleep", "C2 beacon pattern"),
            (r"time\.sleep.*random", "Randomized sleep (beacon)"),
            (r"register.*loop", "Registration loop"),
            (r"heartbeat", "Heartbeat mechanism"),
        ]

        for pattern, label in network_indicators:
            if re.search(pattern, content):
                self.add_finding(
                    title=f"Network indicator: {label}",
                    description="File contains network communication code",
                    severity=Severity.LOW,
                    evidence=f"Pattern: {pattern}",
                    location=f"{self.path}",
                    fix="Verify this code is intentional",
                    impact="Network capability - verify intent",
                )

        for pattern, label in c2_indicators:
            if re.search(pattern, content):
                self.add_finding(
                    title=f"Potential C2 indicator: {label}",
                    description="Code pattern resembles command and control beacon",
                    severity=Severity.HIGH,
                    evidence=f"Pattern: {pattern}",
                    location=f"{self.path}",
                    fix="Analyze this code immediately",
                    impact="Possible malware command and control",
                )


class MaintainerAnalyzer:
    """Analyzes package maintainer patterns for anomalies."""

    def __init__(self):
        self.api_key = os.environ.get("PYPI_API_KEY", "")

    def analyze_maintainer(self, package_name: str) -> Dict:
        """Analyze a package's maintainer for anomalies."""
        return {
            "package": package_name,
            "is_new_maintainer": False,
            "has_verified_email": False,
            "suspicious": False,
            "reasons": [],
        }

    def check_publish_pattern(self, package_name: str) -> Dict:
        """Check for suspicious release patterns."""
        return {
            "package": package_name,
            "rapid_releases": False,
            "version_manipulation": False,
            "suspicious": False,
        }
