"""
Scanner 3: Secret Exposure
Detects API keys, credentials, tokens, and unsafe secret handling patterns.
Includes entropy-based generic secret detection.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.advanced_analysis import shannon_entropy, per_class_entropy


# (pattern, label, severity)
SECRET_PATTERNS = [
    # Cloud providers
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", Severity.CRITICAL),
    (
        r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
        "AWS Secret Access Key",
        Severity.CRITICAL,
    ),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", Severity.CRITICAL),
    (r"ya29\.[0-9A-Za-z\-_]+", "Google OAuth Token", Severity.CRITICAL),
    (
        r"(?i)azure[_\-]?(?:client[_\-]?secret|subscription[_\-]?key)\s*[=:]\s*['\"]?[A-Za-z0-9+/=\-]{30,}",
        "Azure Secret",
        Severity.CRITICAL,
    ),
    # AI/LLM keys
    (r"sk-[A-Za-z0-9]{48}", "OpenAI API Key (sk-)", Severity.CRITICAL),
    (r"sk-proj-[A-Za-z0-9\-_]{80,}", "OpenAI Project Key", Severity.CRITICAL),
    (r"sk-ant-[A-Za-z0-9\-_]{80,}", "Anthropic API Key", Severity.CRITICAL),
    (r"gsk_[A-Za-z0-9]{52}", "Groq API Key", Severity.CRITICAL),
    (
        r"(?i)(?:cohere|together)[_\-]?api[_\-]?key\s*[=:]\s*['\"]?[A-Za-z0-9]{40,}",
        "Cohere/Together AI Key",
        Severity.CRITICAL,
    ),
    # Tokens
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity.CRITICAL),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token", Severity.CRITICAL),
    (r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}", "Bearer Token in code", Severity.HIGH),
    (r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}", "Slack Bot Token", Severity.CRITICAL),
    (
        r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}",
        "Slack User Token",
        Severity.CRITICAL,
    ),
    # Database
    (
        r"(?i)mongodb(\+srv)?://[^:]+:[^@]+@",
        "MongoDB connection string with credentials",
        Severity.CRITICAL,
    ),
    (
        r"(?i)postgres(?:ql)?://[^:]+:[^@]+@",
        "PostgreSQL connection string with credentials",
        Severity.CRITICAL,
    ),
    (
        r"(?i)mysql://[^:]+:[^@]+@",
        "MySQL connection string with credentials",
        Severity.CRITICAL,
    ),
    (r"(?i)redis://:[^@]+@", "Redis connection string with password", Severity.HIGH),
    # Private keys
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "Private key material",
        Severity.CRITICAL,
    ),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "PGP Private Key", Severity.CRITICAL),
    # Generic high-entropy secrets
    (
        r"(?i)(?:secret|password|passwd|token|api[_-]?key)\s*[=:]\s*['\"](?!<)[A-Za-z0-9+/\-_]{16,}['\"]",
        "Hardcoded credential",
        Severity.HIGH,
    ),
    (
        r"(?i)(?:access[_-]?key|auth[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9+/\-_]{20,}['\"]",
        "Hardcoded access key",
        Severity.HIGH,
    ),
    # Wallets
    (
        r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
        "Possible Bitcoin address (verify)",
        Severity.INFO,
    ),
    (r"0x[a-fA-F0-9]{40}", "Ethereum address", Severity.INFO),
]

UNSAFE_PATTERNS = [
    (
        r"os\.environ\.get\s*\(\s*['\"].*['\"].*\)\s*or\s*['\"][^'\"]+['\"]",
        "Env var with hardcoded fallback",
        Severity.MEDIUM,
    ),
    (
        r"(?i)print\s*\(.*(?:key|secret|token|password|cred)",
        "Printing potential secret",
        Severity.HIGH,
    ),
    (
        r"(?i)logging\.(info|debug|warning|error)\s*\(.*(?:key|secret|token|password)",
        "Logging potential secret",
        Severity.HIGH,
    ),
    (
        r"(?i)logger\.(info|debug)\s*\(.*(?:key|secret|token|password)",
        "Logger printing potential secret",
        Severity.HIGH,
    ),
    (r"\.env", ".env file reference (may contain secrets)", Severity.LOW),
    (r"load_dotenv\s*\(", "dotenv in use — ensure .env is in .gitignore", Severity.LOW),
]


class SecretScanner(BaseScanner):
    name = "secrets"

    async def scan(self) -> list[ScannerResult]:
        self._scan_secret_patterns()
        self._scan_unsafe_patterns()
        self._scan_env_exposure()
        self._scan_entropy_secrets()
        return self.findings

    def _scan_secret_patterns(self):
        for pattern, label, severity in SECRET_PATTERNS:
            for lineno, line in self.grep_lines(pattern):
                # Skip if this looks like a test/example/placeholder
                if re.search(
                    r"(?i)(example|placeholder|your[_-]?key|xxx|test|dummy|fake|insert)",
                    line,
                ):
                    continue
                self.add_finding(
                    title=f"Hardcoded secret: {label}",
                    description=(
                        f"A '{label}' was found directly in the code. "
                        "Hardcoded secrets in source code are exposed to anyone "
                        "with read access to the repo, logs, or build artifacts."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {self._redact(line)}",
                    fix=(
                        "Remove the secret from code immediately. "
                        "Rotate the credential. "
                        "Use environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.)."
                    ),
                    impact="Attacker gains full access to the service this credential controls.",
                )

    def _scan_unsafe_patterns(self):
        for pattern, label, severity in UNSAFE_PATTERNS:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Unsafe secret handling: {label}",
                    description=f"Unsafe secret handling pattern detected: {label}.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove secret values from logs and outputs. Never use hardcoded fallbacks for secrets.",
                    impact="Secrets may appear in logs, stdout, or error outputs accessible to attackers.",
                )

    def _scan_env_exposure(self):
        """Detect patterns that dump entire environment."""
        for lineno, line in self.grep_lines(r"os\.environ\b(?!\.(get|setdefault))"):
            if re.search(r"os\.environ\s*\[", line) or re.search(
                r"os\.environ\s*=", line
            ):
                continue  # Direct key access is fine
            self.add_finding(
                title="Full environment dump: os.environ",
                description=(
                    "Accessing os.environ directly (not os.environ.get('KEY')) "
                    "may expose all environment variables including secrets."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Line {lineno}: {line}",
                fix="Use os.environ.get('SPECIFIC_KEY') instead of passing the full environ dict.",
                impact="All env vars — including cloud credentials and API keys — could be exposed.",
            )

    def _scan_entropy_secrets(self):
        """Detect high-entropy strings in secret-like variable assignments."""
        # Context words that suggest a secret
        secret_contexts = (
            "secret",
            "password",
            "passwd",
            "pwd",
            "token",
            "api_key",
            "apikey",
            "api-key",
            "access_key",
            "auth_key",
            "auth_token",
            "private_key",
            "privatekey",
            "credential",
            "cred",
            "bearer",
            "authorization",
            "jwt",
            "session_key",
            "encryption_key",
            "signing_key",
            "hmac",
            "salt",
            "nonce",
        )

        lines = self.content.splitlines()
        for lineno, line in enumerate(lines, 1):
            # Check if line contains a secret-like variable assignment
            # Pattern: var_name = "high_entropy_value"
            match = re.match(
                r"""^\s*(\w+)\s*[=:]\s*['"]([A-Za-z0-9+/\-_=]{20,})['"]""",
                line.strip(),
            )
            if not match:
                continue

            var_name = match.group(1).lower()
            value = match.group(2)

            # Check if variable name suggests a secret
            is_secret_context = any(ctx in var_name for ctx in secret_contexts)
            if not is_secret_context:
                continue

            # Skip test/example values
            if re.search(
                r"(?i)(example|placeholder|your_|xxx|test|dummy|fake|changeme|insert|replace)",
                line,
            ):
                continue

            # Calculate entropy
            entropy = shannon_entropy(value)
            class_ent = per_class_entropy(value)

            # Threshold: >4.5 with mixed character classes
            has_mixed_classes = len(class_ent) >= 2
            if entropy > 4.5 and has_mixed_classes and len(value) >= 20:
                severity = Severity.HIGH
                if entropy > 5.5:
                    severity = Severity.CRITICAL

                self.add_finding(
                    title=f"Entropy-based secret detection: {var_name}",
                    description=(
                        f"Variable '{var_name}' has a high-entropy value "
                        f"(entropy={entropy:.2f}, length={len(value)}). "
                        f"Character classes: {', '.join(f'{k}={v:.2f}' for k, v in class_ent.items())}. "
                        "This is likely a hardcoded secret that was missed by pattern-based detection."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {var_name} = {value[:8]}<redacted>{value[-4:]}",
                    fix="Use environment variables or a secrets manager. Never commit secrets to source control.",
                    impact="Hardcoded secret exposed in source code.",
                )

    def _redact(self, line: str) -> str:
        """Partially redact secrets in evidence strings."""
        return re.sub(
            r"(['\"])[A-Za-z0-9+/\-_]{8}([A-Za-z0-9+/\-_]{8,}['\"])",
            r"\1<redacted>\2",
            line,
        )
