"""
Shared data models for ARCADA audit pipeline.
"""

from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScannerResult(BaseModel):
    """Raw finding from a scanner module."""

    scanner: str
    title: str
    description: str
    severity: Severity
    evidence: str = ""
    location: str = ""
    fix: str = ""
    impact: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditFinding(BaseModel):
    """Enriched finding after AI reasoning."""

    title: str
    description: str
    severity: Severity
    impact: str
    evidence: str
    fix: str
    scanner: str
    location: str = ""


class AuditSummary(BaseModel):
    risk_score: int = Field(ge=0, le=100)
    security_maturity: str  # Unsafe | Weak | Moderate | Strong | Hardened
    top_risks: list[str]
    immediate_actions: list[str]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int


class AuditReport(BaseModel):
    """Full ARCADA audit report."""

    target: str
    target_type: str
    arcada_version: str = "0.1.0"
    findings: list[AuditFinding]
    summary: AuditSummary
    raw_scanner_results: list[ScannerResult] = Field(default_factory=list)


class PackageFinding(ScannerResult):
    """Finding from a deep dependency source scan."""

    package_name: str = ""
    package_version: str = ""
    package_file: str = ""


class DepTreeNode(BaseModel):
    """A node in the transitive dependency tree."""

    name: str
    version: str = ""
    direct: bool = True
    transitive_deps: list[str] = Field(default_factory=list)
    is_installed: bool = True


class AuditRequest(BaseModel):
    """API request body."""

    target: str = Field(description="Path, URL, or inline content to audit")
    target_type: str = Field(
        default="auto",
        description="Type: auto | code | dependencies | docker | config | url",
    )
    scanners: list[str] = Field(
        default_factory=list, description="Specific scanners to run. Empty = all."
    )
    output_format: str = Field(
        default="json", description="Output format: json | markdown | sarif"
    )
    deep: bool = Field(
        default=False,
        description="Enable deep dependency scanning (installed source + metadata + behavior)",
    )
    packages: list[str] = Field(
        default_factory=list,
        description="Specific packages to scan in deep mode. Empty = all installed.",
    )
    max_findings_per_call: int = Field(
        default=0,
        description="Max findings per LLM call. 0 = use server default (ARCADA_MAX_FINDINGS_PER_CALL).",
    )
