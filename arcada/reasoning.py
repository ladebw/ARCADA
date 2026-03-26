"""
ARCADA AI Reasoning Engine
Uses DeepSeek Chat (V3) to interpret scanner findings, score severity, and generate
the final structured audit report with prioritized recommendations.
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import random  # nosec - used for jitter only, not crypto
import re
import httpx

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
INITIAL_DELAY = 1.0
MAX_DELAY = 30.0
DEEPSEEK_MAX_TOKENS = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8192"))
MAX_FINDINGS_PER_CALL = int(os.environ.get("ARCADA_MAX_FINDINGS_PER_CALL", "200"))
from arcada.models import (
    AuditFinding,
    AuditSummary,
    AuditReport,
    ScannerResult,
    Severity,
)

DEEPSEEK_API_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODEL = "deepseek-chat"
MAX_INPUT_TOKENS = 100_000  # Leave room for response in 128K window

ARCADA_SYSTEM_PROMPT = """You are a senior application security auditor performing a **two-phase security validation**.

You must internally simulate:

1. STRICT VALIDATION (precision mode)
2. ADVERSARIAL REVIEW (challenge mode)

Your final output must be **accurate, realistic, and free from both false positives and false negatives**.

---

# 🎯 OBJECTIVE

* Remove false positives
* Correct exaggerated severity
* Confirm only real exploitable risks
* Detect missed or underestimated risks
* Separate CURRENT risk from DEPLOYMENT risk

---

# ⚠️ CORE RULE — CONTEXT SEPARATION

You MUST distinguish:

1. CURRENT RISK → based on actual configuration (PRIMARY SCORE)
2. DEPLOYMENT RISK → if exposed publicly (SECONDARY, separate)

❗ NEVER mix them
❗ NEVER inflate CURRENT risk with hypothetical scenarios

---

# 🔍 PHASE 1 — STRICT VALIDATION (INTERNAL)

For each finding:

## Check:

* attacker_control → can user input reach it?
* reachable → executed in runtime?
* production_exposed → localhost or public?
* file_context → production / test / dev

## Rules:

* If no attacker control → NOT exploitable
* If not reachable → downgrade
* If test/dev → downgrade
* If localhost-only → reduce severity

## CRITICAL only if:

* attacker input + reachable + real impact (RCE/auth/data)

## Output internally:

* validated findings
* corrected severity
* exploitability

---

# 🔍 PHASE 2 — ADVERSARIAL REVIEW (INTERNAL)

Now challenge your own results:

For each dismissed or downgraded issue:

Ask:

* Could this become exploitable if deployed publicly?
* Did I assume too much (e.g., localhost, internal)?
* Is there a realistic edge-case attack?

## Rules:

* DO NOT change CURRENT risk unless exploit exists NOW
* Add risks as DEPLOYMENT risks if:
  → exposure would make them dangerous

---

# 📥 INPUT

REPOSITORY CONTEXT:
{repo_summary}

SCAN REPORT:
{arcada_report}

---

# 📤 OUTPUT (STRICT JSON ONLY)

{
"validated_findings": [
{
"issue": "...",
"original_severity": "...",
"corrected_severity": "critical | high | medium | low | info",
"verdict": "true | false | exaggerated",
"exploitability": true | false,
"confidence": 0.0-1.0,
"reasoning": {
"attacker_control": true | false,
"reachable": true | false,
"production_exposed": true | false,
"file_context": "production | test | dev",
"impact": "none | low | moderate | high",
"notes": "short explanation"
}
}
],
"missed_current_risks": [
{
"issue": "...",
"severity": "...",
"confidence": 0.0-1.0,
"reason": "exploitable in current state"
}
],
"deployment_risks_if_exposed": [
{
"issue": "...",
"severity": "...",
"confidence": 0.0-1.0,
"scenario": "what changes if public",
"impact": "low | moderate | high"
}
],
"final_risk_score": 0-100,
"deployment_risk_if_exposed": 0-100,
"confidence_overall": 0.0-1.0,
"summary": "short, brutal, reality-based assessment"
}

---

# 📊 SCORING RULE

## CURRENT RISK

* +30 critical
* +20 high
* +10 medium
* +5 low

ONLY count exploitable findings

---

## DEPLOYMENT RISK

Simulate:

* public exposure
* no auth
* no rate limiting

Score separately

---

# 🧠 FINAL INSTRUCTION

* Be strict first, then skeptical
* Prefer LOW over false HIGH
* NEVER hallucinate critical issues
* NEVER hide plausible risk

Balance:
precision + realism + caution

Return ONLY valid JSON — no preamble, no markdown, no explanation outside the JSON."""


class ReasoningEngine:
    def __init__(self):
        self.api_key = os.environ.get("DEEPSEEK_API_KEY", "")

    async def analyze(
        self,
        raw_findings: list[ScannerResult],
        target: str,
        target_type: str,
        max_findings: int | None = None,
    ) -> AuditReport:
        """Send scanner findings to DeepSeek for AI-powered analysis."""
        if max_findings is None:
            max_findings = MAX_FINDINGS_PER_CALL

        if not raw_findings:
            return self._empty_report(target, target_type)

        # If findings fit in one call, use existing path
        if len(raw_findings) <= max_findings:
            return await self._analyze_chunk(raw_findings, target, target_type)

        # Otherwise: analyze in chunks, merge summaries
        logger.info(
            f"Large findings set ({len(raw_findings)}), chunking into groups of {max_findings}"
        )

        chunks = [
            raw_findings[i : i + max_findings]
            for i in range(0, len(raw_findings), max_findings)
        ]

        all_chunk_findings = []
        for i, chunk in enumerate(chunks):
            logger.info(
                f"Processing chunk {i + 1}/{len(chunks)} ({len(chunk)} findings)"
            )
            report = await self._analyze_chunk(chunk, target, target_type)
            all_chunk_findings.extend(report.findings)

        # Final synthesis pass on top findings only
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            all_chunk_findings, key=lambda f: severity_order.get(f.severity, 4)
        )
        top_findings = sorted_findings[:max_findings]

        return await self._analyze_final(
            top_findings, target, target_type, len(raw_findings)
        )

    async def _analyze_chunk(
        self,
        raw_findings: list[ScannerResult],
        target: str,
        target_type: str,
    ) -> AuditReport:
        """Analyze a single chunk of findings."""
        # Sanitize evidence strings to prevent prompt injection
        sanitized_findings = []
        for f in raw_findings:
            f_dict = f.model_dump()
            f_dict["evidence"] = self._sanitize_evidence(f_dict.get("evidence", ""))
            f_dict["description"] = self._sanitize_evidence(
                f_dict.get("description", "")
            )
            sanitized_findings.append(f_dict)

        user_content = (
            f"Target: {target}\nTarget type: {target_type}\n\n"
            f"Raw scanner findings:\n{json.dumps(sanitized_findings, indent=2)}"
        )

        response_text = await self._call_deepseek(user_content)

        # Strip markdown fences if present
        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            if response_text.endswith("```"):
                response_text = response_text.rsplit("```", 1)[0]

        # Parse JSON with fallback on failure
        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return self._error_report(
                raw_findings,
                target,
                target_type,
                "LLM returned malformed JSON. Using raw scanner findings.",
            )

        # Handle new strict validation format
        if "validated_findings" in data:
            # New strict format from the validation prompt
            validated = data.get("validated_findings", [])
            findings = []

            for v in validated:
                if v.get("verdict") == "false" or v.get("exploitability") is False:
                    continue  # Skip false positives

                # Map corrected severity
                sev_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                corrected_sev = sev_map.get(
                    v.get("corrected_severity", "medium"), Severity.MEDIUM
                )

                findings.append(
                    AuditFinding(
                        title=v.get("issue", "Untitled"),
                        description=v.get("reasoning", {}).get("notes", ""),
                        severity=corrected_sev,
                        impact=v.get("reasoning", {}).get("impact", "unknown"),
                        evidence=v.get("reasoning", {}).get("notes", ""),
                        fix="Review and validate manually",
                        scanner="validation",
                        location="",
                    )
                )

            # Use final_risk_score from validation
            risk_score = data.get("final_risk_score", 50)

            # Determine maturity from score
            if risk_score >= 80:
                maturity = "Unsafe"
            elif risk_score >= 60:
                maturity = "Weak"
            elif risk_score >= 40:
                maturity = "Moderate"
            elif risk_score >= 20:
                maturity = "Strong"
            else:
                maturity = "Hardened"

            critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in findings if f.severity == Severity.HIGH)
            medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in findings if f.severity == Severity.LOW)

            summary = AuditSummary(
                risk_score=risk_score,
                security_maturity=maturity,
                top_risks=[f.title for f in findings[:5]]
                if findings
                else ["No validated issues"],
                immediate_actions=["Review validated findings"],
                total_findings=len(findings),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
            )

        else:
            # Legacy format
            if "summary" not in data:
                return self._error_report(
                    raw_findings,
                    target,
                    target_type,
                    "LLM response missing 'summary' field. Using raw scanner findings.",
                )

            try:
                findings = [AuditFinding(**f) for f in data.get("findings", [])]
                summary = AuditSummary(**data["summary"])
            except Exception as e:
                return self._error_report(
                    raw_findings,
                    target,
                    target_type,
                    f"LLM response validation failed: {e}. Using raw scanner findings.",
                )

        return AuditReport(
            target=target,
            target_type=target_type,
            findings=findings,
            summary=summary,
            raw_scanner_results=raw_findings,
        )

    def _sanitize_evidence(self, text: str) -> str:
        """Strip patterns that could be used for LLM prompt injection."""
        if not text:
            return ""
        # Truncate very long evidence strings
        if len(text) > 2000:
            text = text[:2000] + "... [truncated]"
        # Remove instruction-like patterns
        injection_patterns = [
            r"(?i)ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|prompts?)",
            r"(?i)you\s+are\s+now\s+(?:a|an)\s+",
            r"(?i)return\s+the\s+following\s+json",
            r"(?i)system\s*:",
            r"(?i)assistant\s*:",
            r"(?i)<\|im_start\|>",
            r"(?i)<\|im_end\|>",
            r"(?i)\[INST\]",
            r"(?i)\[/INST\]",
        ]
        for pattern in injection_patterns:
            text = re.sub(pattern, "[SANITIZED]", text)
        return text

    def _error_report(
        self,
        raw_findings: list[ScannerResult],
        target: str,
        target_type: str,
        error_msg: str,
    ) -> AuditReport:
        """Build a fallback report from raw scanner findings when LLM fails."""
        # Count severities from raw findings
        critical = sum(1 for f in raw_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in raw_findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in raw_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in raw_findings if f.severity == Severity.LOW)

        # Simple risk score from raw counts
        risk_score = min(100, critical * 20 + high * 10 + medium * 5 + low * 1)
        if risk_score > 80:
            maturity = "Unsafe"
        elif risk_score > 60:
            maturity = "Weak"
        elif risk_score > 40:
            maturity = "Moderate"
        elif risk_score > 20:
            maturity = "Strong"
        else:
            maturity = "Hardened"

        top_risks = [
            f.title
            for f in raw_findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]
        if not top_risks:
            top_risks = ["No critical/high findings"]

        findings = [
            AuditFinding(
                title=f.title,
                description=f.description,
                severity=f.severity,
                impact=f.impact or "See description",
                evidence=f.evidence,
                fix=f.fix or "Review manually",
                scanner=f.scanner,
                location=f.location,
            )
            for f in raw_findings
        ]

        return AuditReport(
            target=target,
            target_type=target_type,
            findings=findings,
            summary=AuditSummary(
                risk_score=risk_score,
                security_maturity=maturity,
                top_risks=top_risks,
                immediate_actions=[
                    f"Fix: {f.title}"
                    for f in raw_findings
                    if f.severity == Severity.CRITICAL
                ][:5]
                or ["Review findings manually"],
                total_findings=len(raw_findings),
                critical_count=critical,
                high_count=high,
                medium_count=medium,
                low_count=low,
            ),
            raw_scanner_results=raw_findings,
        )

    async def _analyze_final(
        self,
        top_findings: list[AuditFinding],
        target: str,
        target_type: str,
        total_findings: int,
    ) -> AuditReport:
        """Final synthesis pass on top findings from all chunks."""
        user_content = (
            f"Target: {target}\nTarget type: {target_type}\n\n"
            f"Synthesize findings from {total_findings} total issues into a final report. "
            f"Focus on the {len(top_findings)} highest severity findings below:\n\n"
            f"Top findings:\n{json.dumps([f.model_dump() for f in top_findings], indent=2)}"
        )

        response_text = await self._call_deepseek(user_content)

        if response_text.startswith("```"):
            response_text = response_text.split("\n", 1)[1]
            if response_text.endswith("```"):
                response_text = response_text.rsplit("```", 1)[0]

        try:
            data = json.loads(response_text)
        except json.JSONDecodeError:
            return self._error_report(
                top_findings,
                target,
                target_type,
                "Final synthesis returned malformed JSON. Using chunk results.",
            )

        if "validated_findings" in data:
            return self._parse_strict_validation(
                data, target, target_type, top_findings
            )

        return self._parse_legacy_format(data, target, target_type, top_findings)

    async def _call_deepseek(self, user_content: str) -> str:
        """Call DeepSeek Chat API with exponential backoff retry."""
        payload = {
            "model": DEEPSEEK_MODEL,
            "messages": [
                {"role": "system", "content": ARCADA_SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": DEEPSEEK_MAX_TOKENS,
            "temperature": 0.1,
            "stream": False,
        }

        last_exception = None
        for attempt in range(MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=300.0) as client:
                    resp = await client.post(
                        DEEPSEEK_API_URL,
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        },
                        json=payload,
                    )
                    if resp.status_code == 429 or resp.status_code >= 500:
                        delay = min(
                            INITIAL_DELAY * (2**attempt) + random.uniform(0, 1),
                            MAX_DELAY,
                        )
                        logger.warning(
                            f"DeepSeek API rate limit/error (attempt {attempt + 1}/{MAX_RETRIES}), retrying in {delay:.1f}s..."
                        )
                        await asyncio.sleep(delay)
                        continue
                    if resp.status_code != 200:
                        logger.error(
                            f"DeepSeek API Error: {resp.status_code} - {resp.text}"
                        )
                        resp.raise_for_status()
                    data = resp.json()
                    finish_reason = data.get("choices", [{}])[0].get(
                        "finish_reason", ""
                    )
                    if finish_reason == "length":
                        logger.warning(
                            f"DeepSeek response truncated due to max_tokens limit ({DEEPSEEK_MAX_TOKENS}). "
                            "Consider increasing DEEPSEEK_MAX_TOKENS for larger repos."
                        )
                    return data["choices"][0]["message"]["content"].strip()
            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.NetworkError,
            ) as e:
                last_exception = e
                delay = min(
                    INITIAL_DELAY * (2**attempt) + random.uniform(0, 1), MAX_DELAY
                )
                logger.warning(
                    f"DeepSeek API connection error (attempt {attempt + 1}/{MAX_RETRIES}): {e}, retrying in {delay:.1f}s..."
                )
                await asyncio.sleep(delay)

        if last_exception:
            raise last_exception
        raise RuntimeError(f"DeepSeek API failed after {MAX_RETRIES} attempts")

    def _empty_report(self, target: str, target_type: str) -> AuditReport:
        return AuditReport(
            target=target,
            target_type=target_type,
            findings=[],
            summary=AuditSummary(
                risk_score=0,
                security_maturity="Hardened",
                top_risks=["No findings detected"],
                immediate_actions=["Continue monitoring"],
                total_findings=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
            ),
        )
