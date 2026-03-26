"""
Homoglyph & Steganography Scanner
Detects Unicode homoglyphs (Trojan Source attacks), zero-width characters,
and non-ASCII in identifiers - designed to catch supply chain attacks.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class HomoglyphScanner(BaseScanner):
    name = "homoglyph"

    CYRILLIC_HOMOGLYPHS = {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0443": "y",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u0423": "Y",
    }

    GREEK_HOMOGLYPHS = {
        "\u03b1": "a",
        "\u03b2": "b",
        "\u03b5": "e",
        "\u03b7": "n",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c2": "c",
        "\u03c4": "t",
        "\u03c7": "x",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a7": "X",
    }

    LOOKALIKE_CHARS = {
        "\u0030": "0",
        "\u0031": "1",
        "\u0033": "3",
        "\u0037": "7",
        "\u0039": "9",
        "\u004f": "O",
        "\u0069": "l",
        "\u006c": "l",
        "\u0076": "v",
        "\u0077": "w",
        "\u039f": "O",
        "\u03bf": "o",
    }

    ZERO_WIDTH_CHARS = {
        "\u200b": "ZWSP",
        "\u200c": "ZWNJ",
        "\u200d": "ZWJ",
        "\ufeff": "BOM",
        "\u180e": "MVS",
        "\u200e": "LRM",
        "\u200f": "RLM",
    }

    async def scan(self) -> list[ScannerResult]:
        self._detect_cyrillic_homoglyphs()
        self._detect_greek_homoglyphs()
        self._detect_zero_width_chars()
        self._detect_lookalike_chars()
        self._detect_non_ascii_in_code()
        self._check_for_mixed_scripts()
        return self.findings

    def _detect_cyrillic_homoglyphs(self):
        """Detect Cyrillic characters that look like Latin in identifiers."""
        code_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
        }

        if not any(self.path.endswith(ext) for ext in code_exts):
            return

        pattern = r"[\u0400-\u04FF]"
        matches = self.grep(pattern)

        for match in matches:
            char = match.group()
            latin_equiv = self.CYRILLIC_HOMOGLYPHS.get(char, "?")

            line_no = self.content[: match.start()].count("\n") + 1

            context_start = max(0, match.start() - 30)
            context_end = min(len(self.content), match.end() + 30)
            context = self.content[context_start:context_end]

            self.add_finding(
                title="Cyrillic homoglyph in identifier (Trojan Source attack)",
                description=(
                    f"Found Cyrillic character U+{ord(char):04X} ({char}) which looks like Latin '{latin_equiv}'. "
                    "This is a documented supply chain attack vector (Trojan Source). "
                    "Human reviewers see Latin letters but the compiler sees different characters."
                ),
                severity=Severity.CRITICAL,
                evidence=f"...{context}...",
                location=f"{self.path}:{line_no}",
                fix="Replace Cyrillic characters with ASCII equivalents. Add Unicode validation.",
                impact="Code with invisible differences can pass code review and introduce backdoors.",
            )

    def _detect_greek_homoglyphs(self):
        """Detect Greek characters that look like Latin in identifiers."""
        code_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
        }

        if not any(self.path.endswith(ext) for ext in code_exts):
            return

        pattern = r"[\u0370-\u03FF]"
        matches = self.grep(pattern)

        for match in matches:
            char = match.group()
            latin_equiv = self.GREEK_HOMOGLYPHS.get(char, "?")

            line_no = self.content[: match.start()].count("\n") + 1

            context_start = max(0, match.start() - 30)
            context_end = min(len(self.content), match.end() + 30)
            context = self.content[context_start:context_end]

            self.add_finding(
                title="Greek homoglyph in identifier",
                description=(
                    f"Found Greek character U+{ord(char):04X} ({char}) which looks like Latin '{latin_equiv}'. "
                    "This can be used for visual confusion attacks."
                ),
                severity=Severity.HIGH,
                evidence=f"...{context}...",
                location=f"{self.path}:{line_no}",
                fix="Replace Greek characters with ASCII equivalents.",
                impact="Homoglyph attacks can bypass code review.",
            )

    def _detect_zero_width_chars(self):
        """Detect zero-width characters that can hide code."""
        pattern = r"[\u200B\u200C\u200D\uFEFF\u180E\u200E\u200F]"
        matches = self.grep(pattern)

        for match in matches:
            char = match.group()
            char_name = self.ZERO_WIDTH_CHARS.get(char, f"U+{ord(char):04X}")

            line_no = self.content[: match.start()].count("\n") + 1

            context_start = max(0, match.start() - 30)
            context_end = min(len(self.content), match.end() + 30)
            context = self.content[context_start:context_end]

            self.add_finding(
                title=f"Zero-width character: {char_name}",
                description=(
                    f"Found zero-width character {char_name} (U+{ord(char):04X}). "
                    "These invisible characters can hide strings, comments, or tokens in code."
                ),
                severity=Severity.HIGH,
                evidence=f"...{context}...",
                location=f"{self.path}:{line_no}",
                fix="Remove zero-width characters. Add pre-commit validation.",
                impact="Can hide malicious strings from human review.",
            )

    def _detect_lookalike_chars(self):
        """Detect look-alike Unicode characters that confuse humans."""
        pattern = r"[\u0030\u0031\u0033\u0037\u0039\u004F\u0069\u006C\u0076\u0077]"
        matches = self.grep(pattern)

        identifiers_found = set()

        identifier_pattern = (
            r"[a-zA-Z_][a-zA-Z0-9_\u0030-\u0039\u004F\u0069\u006C\u0076\u0077]*"
        )
        for match in re.finditer(identifier_pattern, self.content):
            if any(
                c in match.group()
                for c in "\u0030\u0031\u0033\u0037\u0039\u004f\u0069\u006c\u0076\u0077"
            ):
                identifiers_found.add((match.group(), match.start()))

        for identifier, pos in identifiers_found:
            has_confusable = False
            for c in identifier:
                if c in self.LOOKALIKE_CHARS:
                    has_confusable = True
                    break

            if has_confusable and len(identifier) > 2:
                line_no = self.content[:pos].count("\n") + 1
                self.add_finding(
                    title="Look-alike Unicode in identifier",
                    description=(
                        f"Identifier '{identifier}' contains confusable Unicode characters (0/O, 1/l/I). "
                        "This can be used for visual deception in variable/function names."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Found in: {identifier}",
                    location=f"{self.path}:{line_no}",
                    fix="Use only ASCII characters in identifiers.",
                    impact="Confusable identifiers can mislead developers.",
                )

    def _detect_non_ascii_in_code(self):
        """Detect non-ASCII characters in source code files."""
        code_exts = {
            ".py",
            ".js",
            ".ts",
            ".jsx",
            ".tsx",
            ".java",
            ".go",
            ".rb",
            ".php",
            ".c",
            ".cpp",
            ".h",
            ".cs",
            ".swift",
            ".kt",
        }

        if not any(self.path.endswith(ext) for ext in code_exts):
            return

        ascii_printable = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}

        lines = self.content.splitlines()
        for i, line in enumerate(lines, 1):
            for char in line:
                char_code = ord(char)
                if char_code > 127 and char_code not in ascii_printable:
                    if (
                        char not in self.ZERO_WIDTH_CHARS
                        and char not in self.CYRILLIC_HOMOGLYPHS
                    ):
                        self.add_finding(
                            title="Non-ASCII character in source code",
                            description=(
                                f"Found non-ASCII character U+{char_code:04X} ('{char}') in source file. "
                                "This may indicate encoded content or obfuscation."
                            ),
                            severity=Severity.MEDIUM,
                            evidence=line[:100],
                            location=f"{self.path}:{i}",
                            fix="Replace non-ASCII characters with ASCII equivalents.",
                            impact="Non-ASCII can hide malicious code or cause encoding issues.",
                        )
                    break

    def _check_for_mixed_scripts(self):
        """Detect mixed scripts in identifiers (Cyrillic + Latin)."""
        identifier_pattern = r"[a-zA-Z_\u0400-\u04FF][a-zA-Z0-9_\u0400-\u04FF]*"
        matches = re.finditer(identifier_pattern, self.content)

        for match in matches:
            identifier = match.group()
            has_latin = any(c.isascii() and c.isalpha() for c in identifier)
            has_cyrillic = any("\u0400" <= c <= "\u04ff" for c in identifier)

            if has_latin and has_cyrillic:
                line_no = self.content[: match.start()].count("\n") + 1
                self.add_finding(
                    title="Mixed script in identifier",
                    description=(
                        f"Identifier '{identifier}' contains both Latin and Cyrillic characters. "
                        "This is a strong indicator of homoglyph attack."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=identifier,
                    location=f"{self.path}:{line_no}",
                    fix="Use only one script per identifier (preferably ASCII).",
                    impact="Mixed scripts enable Trojan Source attacks.",
                )
