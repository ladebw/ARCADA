"""
ARCADA Report Formatter
Converts AuditReport to JSON, Markdown, or SARIF output formats.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from arcada.models import AuditReport, AuditFinding, Severity

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "ℹ️",
}

MATURITY_EMOJI = {
    "Unsafe": "💀",
    "Weak": "⚠️",
    "Moderate": "🟡",
    "Strong": "🟢",
    "Hardened": "🛡️",
}


def to_json(report: AuditReport, indent: int = 2) -> str:
    return json.dumps(report.model_dump(), indent=indent, default=str)


def to_markdown(report: AuditReport) -> str:
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    s = report.summary
    maturity_icon = MATURITY_EMOJI.get(s.security_maturity, "")

    lines += [
        f"# ARCADA Security Audit Report",
        f"",
        f"**Target:** `{report.target}`  ",
        f"**Type:** {report.target_type}  ",
        f"**Date:** {now}  ",
        f"**ARCADA version:** {report.arcada_version}",
        f"",
        f"---",
        f"",
        f"## 📊 Executive Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Overall Risk Score | **{s.risk_score}/100** |",
        f"| Security Maturity | {maturity_icon} **{s.security_maturity}** |",
        f"| Total Findings | {s.total_findings} |",
        f"| 🔴 Critical | {s.critical_count} |",
        f"| 🟠 High | {s.high_count} |",
        f"| 🟡 Medium | {s.medium_count} |",
        f"| 🟢 Low | {s.low_count} |",
        f"",
        f"### 🏆 Top 5 Critical Risks",
        f"",
    ]
    for i, risk in enumerate(s.top_risks[:5], 1):
        lines.append(f"{i}. {risk}")

    lines += [
        f"",
        f"### ⚡ Immediate Actions (Fix Now)",
        f"",
    ]
    for i, action in enumerate(s.immediate_actions[:5], 1):
        lines.append(f"{i}. {action}")

    lines += ["", "---", ""]

    # Group by severity
    severity_order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    severity_headers = {
        Severity.CRITICAL: "🔴 CRITICAL",
        Severity.HIGH: "🟠 HIGH",
        Severity.MEDIUM: "🟡 MEDIUM",
        Severity.LOW: "🟢 LOW",
        Severity.INFO: "ℹ️ INFO",
    }

    for sev in severity_order:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        lines += [f"## {severity_headers[sev]}", ""]
        for finding in group:
            lines += [
                f"### {finding.title}",
                f"",
                f"**Scanner:** `{finding.scanner}`  ",
                f"**Location:** `{finding.location or 'N/A'}`",
                f"",
                f"**Description:** {finding.description}",
                f"",
                f"**Impact:** {finding.impact}",
                f"",
                f"**Evidence:**",
                f"```",
                finding.evidence,
                f"```",
                f"",
                f"**Fix:** {finding.fix}",
                f"",
                f"---",
                f"",
            ]

    return "\n".join(lines)


def to_sarif(report: AuditReport) -> str:
    """Produce SARIF 2.1.0 output for IDE/CI integration."""
    severity_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    severity_scores = {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.0",
        "low": "2.0",
    }

    rules = {}
    results = []

    for finding in report.findings:
        rule_id = finding.title.lower().replace(" ", "_").replace(":", "")[:50]
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "helpUri": "https://github.com/your-org/arcada",
                "properties": {
                    "tags": [finding.scanner, finding.severity],
                    "security-severity": severity_scores.get(finding.severity, "0"),
                },
            }

        results.append(
            {
                "ruleId": rule_id,
                "level": severity_map.get(finding.severity, "note"),
                "message": {
                    "text": f"{finding.description}\n\nFix: {finding.fix}\n\nImpact: {finding.impact}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.location or report.target
                            },
                            "region": {
                                "startLine": 1,
                            },
                        }
                    }
                ],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ARCADA",
                        "version": report.arcada_version,
                        "informationUri": "https://github.com/your-org/arcada",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_report(report: AuditReport, output_format: str = "json") -> str:
    if output_format == "markdown":
        return to_markdown(report)
    if output_format == "sarif":
        return to_sarif(report)
    return to_json(report)
