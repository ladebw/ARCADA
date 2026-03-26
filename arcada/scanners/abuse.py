"""
Scanner 9: Abuse & Cost Risks
"""

from __future__ import annotations
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class AbuseScanner(BaseScanner):
    name = "abuse"

    async def scan(self) -> list[ScannerResult]:
        self._detect_missing_rate_limits()
        self._detect_missing_auth()
        self._detect_replay_attack()
        self._detect_missing_quotas()
        return self.findings

    def _detect_missing_rate_limits(self):
        has_rate_limit = bool(
            self.grep_lines(
                r"(?i)rate.?limit|slowapi|flask.?limiter|throttle|RateLimiter|Throttle|429"
            )
        )
        has_api_routes = bool(
            self.grep_lines(r"@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(")
        )
        if has_api_routes and not has_rate_limit:
            self.add_finding(
                title="No rate limiting on API endpoints",
                description=(
                    "API routes were found but no rate limiting middleware is present. "
                    "Attackers can spam endpoints to rack up LLM API costs or cause DoS."
                ),
                severity=Severity.HIGH,
                evidence="API routes found, no rate limiting detected.",
                fix=(
                    "Add rate limiting: slowapi (FastAPI), Flask-Limiter (Flask), "
                    "or an API gateway (Kong, Nginx rate_limit module)."
                ),
                impact="Attacker sends millions of requests, bankrupts LLM API budget, causes outage.",
            )

    def _detect_missing_auth(self):
        has_auth = bool(
            self.grep_lines(
                r"(?i)Depends\s*\(.*auth|api.?key|bearer|jwt|oauth|verify.?token|get_current_user"
            )
        )
        has_api_routes = bool(
            self.grep_lines(r"@(?:app|router)\.(?:get|post|put|delete)\s*\(")
        )
        if has_api_routes and not has_auth:
            self.add_finding(
                title="No authentication on API endpoints",
                description=(
                    "API routes found without any authentication dependency. "
                    "Anyone on the internet can call these endpoints."
                ),
                severity=Severity.CRITICAL,
                evidence="API routes found, no auth dependency detected.",
                fix="Add authentication to all endpoints. Use API keys or JWT with proper validation.",
                impact="Unauthenticated access to all API functionality and LLM calls.",
            )

    def _detect_replay_attack(self):
        has_replay_protection = bool(
            self.grep_lines(r"(?i)nonce|idempotency.?key|request.?id.*uuid")
        )
        has_financial_ops = bool(
            self.grep_lines(r"(?i)charge|payment|stripe|transaction|debit|withdraw")
        )
        if has_financial_ops and not has_replay_protection:
            self.add_finding(
                title="Financial operations without replay protection",
                description=(
                    "Financial/payment operations were found without nonce or idempotency keys. "
                    "Replay attacks can duplicate charges."
                ),
                severity=Severity.HIGH,
                evidence="Payment operations found, no idempotency protection detected.",
                fix="Use idempotency keys for all financial operations. Store processed request IDs.",
                impact="Duplicate charges, double withdrawals, financial fraud via request replay.",
            )

    def _detect_missing_quotas(self):
        has_user_quotas = bool(
            self.grep_lines(r"(?i)per.?user|user.*quota|user.*budget|user.*limit")
        )
        has_llm_calls = bool(
            self.grep_lines(
                r"(?i)openai\.|anthropic\.|client\.messages|completions\.create"
            )
        )
        if has_llm_calls and not has_user_quotas:
            self.add_finding(
                title="No per-user LLM usage quotas",
                description=(
                    "LLM API calls found but no per-user quotas or budget controls detected. "
                    "A single user can exhaust the entire API budget."
                ),
                severity=Severity.HIGH,
                evidence="LLM API calls found, no user-level quota detected.",
                fix=(
                    "Implement per-user daily/monthly token limits. "
                    "Track usage in a database. "
                    "Alert when approaching budget thresholds."
                ),
                impact="Single malicious user bankrupts entire LLM API budget.",
            )
