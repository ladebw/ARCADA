"""
Scanner 10: Trust Model Analysis
Detects zero-trust violations and implicit trust assumptions.
"""

from __future__ import annotations
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class TrustModelScanner(BaseScanner):
    name = "trust_model"

    async def scan(self) -> list[ScannerResult]:
        self._detect_implicit_trust_headers()
        self._detect_trust_user_id()
        self._detect_missing_input_validation()
        self._detect_cors_wildcard()
        self._detect_jwt_none()
        self._detect_debug_mode()
        return self.findings

    def _detect_implicit_trust_headers(self):
        patterns = [
            (
                r"(?i)request\.headers\.get\s*\(\s*['\"]X-Forwarded-For['\"]",
                "Trusting X-Forwarded-For header",
            ),
            (
                r"(?i)request\.headers\.get\s*\(\s*['\"]X-Real-IP['\"]",
                "Trusting X-Real-IP header",
            ),
            (
                r"(?i)request\.headers\.get\s*\(\s*['\"]X-User-Id['\"]",
                "Trusting X-User-Id header",
            ),
            (
                r"(?i)request\.headers\.get\s*\(\s*['\"]X-Admin['\"]",
                "Trusting X-Admin header (privilege via header)",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Implicit trust in HTTP header: {label}",
                    description=(
                        f"'{label}' — HTTP headers can be spoofed by any client. "
                        "Using them for authentication or IP allowlisting is a zero-trust violation."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Never trust client-supplied headers for auth or IP determination. "
                        "Use authenticated sessions or JWTs. "
                        "Validate X-Forwarded-For only from known trusted proxies."
                    ),
                    impact="Attacker spoofs admin headers to gain elevated privileges.",
                )

    def _detect_trust_user_id(self):
        patterns = [
            (
                r"(?i)user_id\s*=\s*request\.(args|form|json|data|params)\[",
                "User ID from request body (easily spoofed)",
            ),
            (r"(?i)admin\s*=\s*request\.(args|form|json)\.", "Admin flag from request"),
            (r"(?i)role\s*=\s*request\.(args|form|json)\.", "Role from request body"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Trust violation — user-controlled privilege: {label}",
                    description=(
                        f"'{label}' — roles, user IDs, and admin flags must never come "
                        "from the request body. Users can set these to anything."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Derive user identity from server-validated session tokens (JWT, cookie). Never from request parameters.",
                    impact="Privilege escalation — any user can claim any role or user ID.",
                )

    def _detect_missing_input_validation(self):
        """Detect DB queries without parameterization (SQL injection)."""
        patterns = [
            (
                r"(?i)execute\s*\(\s*f['\"].*SELECT|execute\s*\(\s*['\"].*SELECT.*%s.*%",
                "SQL f-string injection",
            ),
            (
                r"(?i)cursor\.execute\s*\(\s*['\"].*\+\s*(?:user|input|request|query)",
                "SQL concatenation injection",
            ),
            (
                r"(?i)\.filter\s*\(\s*f['\"]",
                "ORM filter with f-string (possible injection)",
            ),
            (
                r"(?i)Model\.objects\.raw\s*\(.*\+",
                "Django raw query with concatenation",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"SQL injection risk: {label}",
                    description=(
                        f"'{label}' — SQL queries built with string concatenation or f-strings "
                        "are vulnerable to SQL injection attacks."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,))",
                    impact="Attacker dumps entire database, bypasses auth, or deletes all data.",
                )

    def _detect_cors_wildcard(self):
        patterns = [
            (
                r"(?i)(?:allow_origins|CORS_ORIGINS)\s*=\s*\[?\s*['\"]?\*",
                "CORS wildcard — all origins allowed",
            ),
            (
                r"(?i)Access-Control-Allow-Origin['\"]?\s*:\s*['\"]?\*",
                "CORS header wildcard",
            ),
            (
                r"(?i)CORSMiddleware.*allow_origins.*\*",
                "FastAPI CORS middleware wildcard",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"CORS wildcard misconfiguration: {label}",
                    description=(
                        f"'{label}' allows any website to make cross-origin requests. "
                        "Combined with cookies or API keys, this enables CSRF attacks."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Restrict CORS to your specific frontend domain(s). Never use * in production.",
                    impact="Any website can make authenticated requests on behalf of your users.",
                )

    def _detect_jwt_none(self):
        patterns = [
            (r"(?i)algorithms\s*=\s*\[['\"]none['\"]", "JWT algorithm: none"),
            (
                r"(?i)verify\s*=\s*False.*jwt|jwt.*verify\s*=\s*False",
                "JWT verification disabled",
            ),
            (
                r"(?i)options\s*=\s*\{.*['\"]verify_signature['\"]:\s*False",
                "JWT signature verification disabled",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"JWT vulnerability: {label}",
                    description=(
                        f"'{label}' — the 'none' algorithm allows forging valid tokens without a secret. "
                        "Disabling JWT verification means any token is accepted."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Always verify JWT signatures. Whitelist only HS256/RS256. Reject 'none' algorithm.",
                    impact="Attacker forges tokens for any user, including admins — full auth bypass.",
                )

    def _detect_debug_mode(self):
        patterns = [
            (r"(?i)debug\s*=\s*True\b", "debug=True in production"),
            (r"(?i)FLASK_ENV\s*=\s*['\"]?development", "Flask development mode"),
            (r"(?i)DJANGO_DEBUG\s*=\s*True|DEBUG\s*=\s*True", "Django DEBUG=True"),
            (
                r"(?i)reload\s*=\s*True.*uvicorn|uvicorn.*reload\s*=\s*True",
                "uvicorn reload mode (dev)",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Debug mode in production: {label}",
                    description=(
                        f"'{label}' enables debug mode which exposes stack traces, "
                        "internal variable values, and sometimes an interactive debugger."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Set DEBUG=False in production. Use environment-specific config files.",
                    impact="Full stack traces with variable values exposed to any user on error pages.",
                )
