"""Base class for all ARCADA scanner modules."""

from __future__ import annotations
import re
from abc import ABC, abstractmethod
from pathlib import Path
from arcada.models import ScannerResult, Severity


class BaseScanner(ABC):
    name: str = "base"

    def __init__(self, content: str, path: str = "", metadata: dict = None):
        self.content = content
        self.path = path
        self.metadata = metadata or {}
        self.findings: list[ScannerResult] = []

    @abstractmethod
    async def scan(self) -> list[ScannerResult]:
        """Run the scanner and return findings."""
        ...

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: str = "",
        location: str = "",
        fix: str = "",
        impact: str = "",
    ):
        self.findings.append(
            ScannerResult(
                scanner=self.name,
                title=title,
                description=description,
                severity=severity,
                evidence=evidence,
                location=location or self.path,
                fix=fix,
                impact=impact,
            )
        )

    def grep(self, pattern: str, flags: int = re.IGNORECASE) -> list[re.Match]:
        """Helper: regex search across content."""
        return list(re.finditer(pattern, self.content, flags))

    def grep_lines(self, pattern: str) -> list[tuple[int, str]]:
        """Return (line_number, line_text) for each matching line."""
        results = []
        for i, line in enumerate(self.content.splitlines(), 1):
            if re.search(pattern, line, re.IGNORECASE):
                results.append((i, line.strip()))
        return results

    def grep_multiline(
        self, pattern: str, flags: int = re.IGNORECASE | re.DOTALL
    ) -> list[re.Match]:
        """Search across the entire content as one string (multi-line mode)."""
        return list(re.finditer(pattern, self.content, flags))

    def grep_context(self, pattern: str, window: int = 5) -> list[tuple[int, str, str]]:
        """Return (line_no, matched_line, context_block) for each match.
        context_block contains window lines after the match for multi-line analysis."""
        results = []
        lines = self.content.splitlines()
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                context_block = "\n".join(lines[i : i + window])
                results.append((i, line.strip(), context_block))
        return results

    def is_target_language(self, *extensions: str) -> bool:
        """Check if current file matches one of the given extensions."""
        if not self.path:
            return True  # inline content, scan everything
        path_lower = self.path.lower()
        return any(path_lower.endswith(ext) for ext in extensions)

    def lines_around(self, line_no: int, context: int = 2) -> str:
        """Extract lines around a finding for evidence."""
        lines = self.content.splitlines()
        start = max(0, line_no - context - 1)
        end = min(len(lines), line_no + context)
        return "\n".join(
            f"{'→' if i + 1 == line_no else ' '} {i + 1}: {lines[i]}"
            for i in range(start, end)
        )
