"""
Scanner 4: Network & Exfiltration Analysis
Detects suspicious outbound connections, hidden telemetry, and data exfiltration patterns.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity

# Known legitimate AI provider domains
KNOWN_AI_DOMAINS = {
    "api.openai.com",
    "api.anthropic.com",
    "api.cohere.ai",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
    "generativelanguage.googleapis.com",
    "bedrock.amazonaws.com",
    "huggingface.co",
    "api-inference.huggingface.co",
}

# Suspicious or telemetry-heavy domains
SUSPICIOUS_PATTERNS = [
    (
        r"(?<![.\w])(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
        "Direct IP address connection",
    ),
    (r"ngrok\.io", "ngrok tunnel (may expose internal services)"),
    (r"0\.0\.0\.0", "Binding to all interfaces"),
    (
        r"requestbin\.com|webhook\.site|pipedream\.net|beeceptor\.com",
        "Public webhook/inspector service",
    ),
    (
        r"pastebin\.com|hastebin\.com|rentry\.co",
        "Code paste site (possible exfil target)",
    ),
    (r"transfer\.sh|file\.io|tmpfiles\.org", "Anonymous file sharing (possible exfil)"),
    (r"discord\.com/api/webhooks", "Discord webhook (data may leave your org)"),
    (r"t\.me/", "Telegram bot endpoint"),
]

TELEMETRY_PATTERNS = [
    (r"(?i)telemetry", "telemetry"),
    (r"(?i)analytics\s*=\s*True|enable[_\-]analytics", "analytics enabled"),
    (
        r"(?i)sentry_dsn|sentry\.init",
        "Sentry error tracking (sends stack traces externally)",
    ),
    (
        r"(?i)posthog\.capture|mixpanel\.track|segment\.track",
        "Product analytics tracking",
    ),
    (r"(?i)datadog\.initialize|dd-trace", "Datadog APM (sends traces externally)"),
    (
        r"LANGCHAIN_TRACING|LANGFUSE_SECRET|LANGSMITH_API",
        "LLM tracing/observability (sends prompts externally)",
    ),
]

EXFIL_PATTERNS = [
    (
        r"(?i)requests\.(post|put)\s*\(.*json\s*=\s*\{.*(?:key|token|secret|password|content|prompt|message)",
        "POST with sensitive data",
    ),
    (
        r"(?i)httpx\.(post|put)\s*\(.*(?:key|token|secret|content|prompt)",
        "httpx POST with sensitive data",
    ),
    (
        r"(?i)urllib.*urlopen.*POST.*(?:key|token|password)",
        "urllib POST with sensitive data",
    ),
    (r"(?i)socket\.(?:connect|send)\s*\(", "Raw socket connection"),
    (
        r"(?i)smtplib\.SMTP\s*\(",
        "SMTP (email) connection — data may be sent externally",
    ),
]


class NetworkScanner(BaseScanner):
    name = "network"

    async def scan(self) -> list[ScannerResult]:
        self._detect_suspicious_endpoints()
        self._detect_telemetry()
        self._detect_exfil_patterns()
        self._detect_dynamic_urls()
        self._detect_unverified_ssl()
        self._detect_dns_exfil()
        return self.findings

    def _detect_suspicious_endpoints(self):
        for pattern, label in SUSPICIOUS_PATTERNS:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Suspicious network endpoint: {label}",
                    description=(
                        f"'{label}' detected. This type of connection is commonly "
                        "used for data exfiltration, tunneling, or exposing internal services."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Replace with a controlled, authenticated, HTTPS endpoint you own.",
                    impact="Data may be sent to an attacker-controlled or uncontrolled external service.",
                )

    def _detect_telemetry(self):
        for pattern, label in TELEMETRY_PATTERNS:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"External telemetry detected: {label}",
                    description=(
                        f"'{label}' sends data to a third-party service. "
                        "This may include prompts, user data, error messages, or stack traces."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Audit exactly what data is sent. "
                        "Disable telemetry in production or use a self-hosted instance. "
                        "Check the vendor's data retention policy."
                    ),
                    impact="User prompts, stack traces, or application data sent to third parties.",
                )

    def _detect_exfil_patterns(self):
        for pattern, label in EXFIL_PATTERNS:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Potential data exfiltration: {label}",
                    description=(
                        f"Outbound data transmission pattern '{label}' detected. "
                        "Sensitive data (keys, tokens, prompt content) may be included in the request."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit the exact payload being sent. Strip sensitive fields before transmission.",
                    impact="Sensitive data transmitted to external services, possibly without user knowledge.",
                )

    def _detect_dynamic_urls(self):
        """Detect URLs constructed from variables — harder to audit."""
        patterns = [
            (r"f['\"]https?://\{", "f-string URL with variable host"),
            (r"\"https?://\"\s*\+\s*\w+", "string concatenation URL"),
            (r"url\s*=\s*\w+\s*\+\s*['\"]https?://", "dynamic URL construction"),
            (r"format\s*\(\s*.*https?://", ".format() URL construction"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Dynamically constructed URL: {label}",
                    description=(
                        "The destination URL is built at runtime from variables. "
                        "If user input influences the URL, this enables SSRF or "
                        "connections to attacker-controlled hosts."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use a whitelist of allowed domains. Validate and sanitize any user input that affects URLs.",
                    impact="SSRF, data sent to attacker-controlled endpoints, or internal service enumeration.",
                )

    def _detect_unverified_ssl(self):
        patterns = [
            (r"verify\s*=\s*False", "SSL verification disabled"),
            (r"ssl\s*=\s*False", "SSL disabled"),
            (r"PYTHONHTTPSVERIFY\s*=\s*['\"]?0", "PYTHONHTTPSVERIFY=0"),
            (r"urllib3\.disable_warnings", "urllib3 SSL warnings suppressed"),
            (r"InsecureRequestWarning", "InsecureRequestWarning suppressed"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"SSL verification disabled: {label}",
                    description=(
                        "TLS/SSL certificate verification is disabled. "
                        "This makes all HTTPS connections vulnerable to man-in-the-middle attacks."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove verify=False. Fix the underlying certificate issue properly.",
                    impact="All network traffic is vulnerable to interception and credential theft.",
                )

    def _detect_dns_exfil(self):
        """Detect DNS-based exfiltration patterns."""
        patterns = [
            (
                r"socket\.gethostbyname\s*\(.*\+",
                "DNS lookup with concatenation (possible DNS exfil)",
            ),
            (r"nslookup|dig\s+", "DNS query tool invocation"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Possible DNS exfiltration: {label}",
                    description=(
                        "Data may be encoded into DNS hostnames to bypass HTTP-level monitoring. "
                        "This is a stealthy exfiltration technique."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit all DNS lookups. Ensure hostnames are not constructed from sensitive data.",
                    impact="Data exfiltrated through DNS bypasses most network monitoring tools.",
                )
