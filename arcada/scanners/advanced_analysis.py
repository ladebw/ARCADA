"""
Advanced Analysis Utilities
- Adaptive entropy analysis per encoding type
- ReDoS (Regular Expression Denial of Service) detection
- Expanded Unicode homoglyph detection
"""

from __future__ import annotations
import re
import math
from collections import Counter
from arcada.models import ScannerResult, Severity


# ---------------------------------------------------------------------------
# Adaptive Entropy Analysis
# ---------------------------------------------------------------------------

# Entropy thresholds per encoding type
ENTROPY_THRESHOLDS = {
    "base64": 5.5,  # Base64 has ~6.0 entropy
    "base32": 5.0,  # Base32 has ~5.0 entropy
    "hex": 4.0,  # Hex has ~4.0 entropy
    "english": 4.2,  # English text ~4.0-4.5
    "obfuscated": 5.8,  # General obfuscation
}

# Minimum string lengths for analysis
MIN_LENGTH_FOR_ENTROPY = 20


def classify_encoding(s: str) -> str:
    """Guess the encoding type of a string based on character distribution."""
    if not s:
        return "unknown"

    # Base64: A-Z, a-z, 0-9, +, /, =
    base64_chars = sum(1 for c in s if c.isalnum() or c in "+/=")
    if len(s) > 0 and base64_chars / len(s) > 0.95:
        return "base64"

    # Base32: A-Z, 2-7, =
    base32_chars = sum(1 for c in s if c.isupper() or c in "234567=")
    if len(s) > 0 and base32_chars / len(s) > 0.95:
        return "base32"

    # Hex: 0-9, a-f, A-F
    hex_chars = sum(1 for c in s if c in "0123456789abcdefABCDEF")
    if len(s) > 0 and hex_chars / len(s) > 0.95:
        return "hex"

    # English: check for common English letter distribution
    alpha_chars = sum(1 for c in s if c.isalpha())
    if len(s) > 0 and alpha_chars / len(s) > 0.7:
        # Check common English letters
        common = set("etaoinshrdlu")
        common_count = sum(1 for c in s.lower() if c in common)
        if alpha_chars > 0 and common_count / alpha_chars > 0.4:
            return "english"

    return "obfuscated"


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    if length == 0:
        return 0.0
    return -sum(
        (count / length) * math.log2(count / length) for count in counter.values()
    )


def per_class_entropy(data: str) -> dict[str, float]:
    """Calculate entropy per character class (digits, alpha, symbols)."""
    classes = {
        "digits": "",
        "lowercase": "",
        "uppercase": "",
        "symbols": "",
    }
    for c in data:
        if c.isdigit():
            classes["digits"] += c
        elif c.islower():
            classes["lowercase"] += c
        elif c.isupper():
            classes["uppercase"] += c
        else:
            classes["symbols"] += c

    return {k: shannon_entropy(v) for k, v in classes.items() if v}


def analyze_string_entropy(s: str, line_no: int = 0) -> ScannerResult | None:
    """Analyze a single string for suspicious entropy. Returns a finding or None."""
    if len(s) < MIN_LENGTH_FOR_ENTROPY:
        return None

    encoding = classify_encoding(s)
    threshold = ENTROPY_THRESHOLDS.get(encoding, 5.8)
    entropy = shannon_entropy(s)

    if entropy <= threshold:
        return None

    # Check per-class entropy for more context
    class_ent = per_class_entropy(s)
    class_detail = ", ".join(f"{k}={v:.2f}" for k, v in class_ent.items())

    severity = Severity.HIGH
    if entropy > 6.5:
        severity = Severity.CRITICAL

    loc = f"Line {line_no}: " if line_no else ""
    return ScannerResult(
        scanner="entropy_analysis",
        title=f"High-entropy string ({encoding} encoding, {entropy:.2f} bits/char)",
        description=(
            f"A string with Shannon entropy {entropy:.2f} was detected "
            f"(classified as {encoding}, threshold={threshold}). "
            f"Per-class entropy: {class_detail}. "
            "High-entropy strings may contain base64-encoded payloads, "
            "encrypted data, or obfuscated malicious code."
        ),
        severity=severity,
        evidence=f"{loc}entropy={entropy:.2f}, encoding={encoding}, length={len(s)}, preview={s[:50]}...",
        fix="Decode the string and audit its contents. If it contains executable code, remove it.",
        impact="Obfuscated malicious payload hidden from signature-based detection.",
    )


# ---------------------------------------------------------------------------
# ReDoS (Regular Expression Denial of Service) Detection
# ---------------------------------------------------------------------------

# Patterns that indicate potential ReDoS
REDOS_PATTERNS = [
    # Nested quantifiers: (a+)+, (a*)*, (a+)*, (a{1,5})+
    (
        r"\((?:[^)]*[+*][^)]*)\)[+*\{]",
        "Nested quantifiers in regex (catastrophic backtracking)",
        Severity.CRITICAL,
    ),
    # Overlapping alternation: (a|a)+, (ab|a)+
    (
        r"\((\w+)\|\1\)[+*]",
        "Alternation with overlapping branches",
        Severity.HIGH,
    ),
    # Exponential patterns: (\w+\s+)+
    (
        r"\(\\w\+[\\s\\S].*?\)[+*]",
        "Quantified group containing \\w+ or \\s+ (exponential backtracking)",
        Severity.HIGH,
    ),
    # .* or .+ followed by another .* or .+
    (
        r"\.\*.*\.\*|\.\+.*\.\+",
        "Multiple .* or .+ in sequence (exponential matching)",
        Severity.HIGH,
    ),
    # (\d+)+ pattern
    (
        r"\(\\d\+\)[+*]",
        "Nested \\d+ quantifier",
        Severity.HIGH,
    ),
    # ([^x]+)+ pattern
    (
        r"\(\[\^[^\]]+\]\+[+*]",
        "Negated character class with nested quantifier",
        Severity.CRITICAL,
    ),
    # Backreference with quantifier: (\1)+
    (
        r"\\(\d+)[+*]",
        "Backreference with quantifier",
        Severity.HIGH,
    ),
]


def detect_redos_in_pattern(
    pattern_str: str, line_no: int = 0, context: str = ""
) -> ScannerResult | None:
    """Check a regex pattern string for ReDoS vulnerabilities."""
    for redos_pattern, label, severity in REDOS_PATTERNS:
        try:
            if re.search(redos_pattern, pattern_str):
                loc = f"Line {line_no}: " if line_no else ""
                return ScannerResult(
                    scanner="redos_detection",
                    title=f"ReDoS risk: {label}",
                    description=(
                        f"The regex pattern contains '{label}'. "
                        "An attacker can craft input that causes catastrophic backtracking, "
                        "leading to denial of service (CPU exhaustion)."
                    ),
                    severity=severity,
                    evidence=f"{loc}Pattern: {pattern_str[:100]}... {context}",
                    fix=(
                        "Rewrite the regex to avoid nested quantifiers. "
                        "Use atomic groups or possessive quantifiers if supported. "
                        "Set a timeout on regex execution. "
                        "Consider using RE2 or re2go which guarantee linear time."
                    ),
                    impact="DoS — attacker sends crafted input that causes regex to hang indefinitely.",
                )
        except re.error:
            continue
    return None


def scan_content_for_redos(content: str) -> list[ScannerResult]:
    """Scan source code for regex patterns with ReDoS risk."""
    findings = []

    # Find re.compile() calls and regex literals
    patterns_to_check = []

    # Python: re.compile, re.match, re.search, re.findall, re.sub
    for m in re.finditer(r"""re\.\w+\s*\(\s*['"](.+?)['"]""", content):
        patterns_to_check.append((m.group(1), m.start()))

    # Python: r"..." or r'...' patterns
    for m in re.finditer(r"""r['"](.+?)['"]""", content):
        patterns_to_check.append((m.group(1), m.start()))

    # JavaScript: /pattern/flags
    for m in re.finditer(r"/(?![/*])([^/]+)/(?:[gimsuy]+)?", content):
        pat = m.group(1)
        if len(pat) > 5:  # Skip very short patterns
            patterns_to_check.append((pat, m.start()))

    for pattern_str, offset in patterns_to_check:
        # Calculate line number
        line_no = content[:offset].count("\n") + 1
        finding = detect_redos_in_pattern(pattern_str, line_no)
        if finding:
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Expanded Unicode Homoglyph Detection
# ---------------------------------------------------------------------------

# Comprehensive homoglyph map: confusable Unicode characters -> Latin equivalents
HOMOGLYPH_MAP = {
    # Cyrillic (U+0400-U+04FF)
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0443": "y",
    "\u0445": "x",
    "\u0410": "A",
    "\u0415": "E",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0425": "X",
    "\u0412": "B",
    "\u0421": "C",
    "\u041d": "H",
    "\u041a": "K",
    "\u041c": "M",
    "\u0422": "T",
    "\u041e": "O",
    # Greek (U+0370-U+03FF)
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c3": "s",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u03b2": "B",
    "\u03b3": "y",
    # Armenian (U+0530-U+058F)
    "\u0561": "a",
    "\u0565": "e",
    "\u056f": "k",
    "\u0570": "h",
    "\u0574": "m",
    "\u0576": "n",
    "\u0578": "o",
    "\u057d": "s",
    "\u0580": "r",
    "\u0585": "o",
    "\u0587": "ou",
    "\u0531": "A",
    "\u0532": "B",
    "\u053d": "K",
    "\u0544": "M",
    "\u0546": "N",
    "\u0555": "O",
    "\u0550": "P",
    # Cherokee (U+13A0-U+13FF) — subset that look like Latin
    "\u13a0": "D",
    "\u13a3": "G",
    "\u13a7": "H",
    "\u13a9": "J",
    "\u13aa": "K",
    "\u13ab": "L",
    "\u13ac": "M",
    "\u13b0": "Q",
    "\u13b3": "T",
    "\u13b7": "W",
    # Fullwidth Latin (U+FF00-U+FFEF)
    "\uff41": "a",
    "\uff42": "b",
    "\uff43": "c",
    "\uff44": "d",
    "\uff45": "e",
    "\uff21": "A",
    "\uff22": "B",
    "\uff23": "C",
    "\uff24": "D",
    "\uff25": "E",
    # Mathematical Alphanumeric Symbols
    "\U0001d400": "A",
    "\U0001d401": "B",
    "\U0001d402": "C",
    "\U0001d41a": "a",
    "\U0001d41b": "b",
    "\U0001d41c": "c",
    # Common confusables
    "\u0131": "i",
    "\u0130": "I",
    "\u017f": "s",
    "\u0261": "g",
    "\u212a": "K",
    "\u212b": "A",
}

HOMOGLYPH_RANGES = [
    (0x0370, 0x03FF, "Greek"),
    (0x0400, 0x04FF, "Cyrillic"),
    (0x0530, 0x058F, "Armenian"),
    (0x13A0, 0x13FF, "Cherokee"),
    (0xFF00, 0xFFEF, "Fullwidth"),
    (0x1D400, 0x1D7FF, "Mathematical"),
]


def detect_homoglyphs(content: str) -> list[ScannerResult]:
    """Detect Unicode homoglyph characters across all known script ranges."""
    findings = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        # Skip comments
        stripped = line.split("#")[0]

        found_chars = []
        found_scripts = set()

        for c in stripped:
            cp = ord(c)
            for start, end, script_name in HOMOGLYPH_RANGES:
                if start <= cp <= end:
                    found_chars.append(c)
                    found_scripts.add(script_name)
                    break

        if found_chars:
            # Only flag if mixed with Latin text (otherwise it's just a foreign language file)
            has_latin = any(c.isascii() and c.isalpha() for c in stripped)
            if not has_latin:
                continue

            scripts_str = ", ".join(sorted(found_scripts))
            preview = line.strip()[:80]
            hex_repr = " ".join(f"U+{ord(c):04X}" for c in found_chars[:8])

            findings.append(
                ScannerResult(
                    scanner="homoglyph_detection",
                    title=f"Unicode homoglyph in code ({scripts_str} mixed with Latin)",
                    description=(
                        f"Line {lineno} contains non-Latin Unicode characters ({scripts_str}) "
                        f"mixed with Latin text. This is a known technique for hiding backdoors: "
                        f"identifiers that look identical to legitimate code but are actually different "
                        f"Unicode codepoints. "
                        f"Characters found: {hex_repr}"
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {preview}... (scripts: {scripts_str})",
                    fix="Replace the Unicode characters with their Latin equivalents. This is almost never legitimate in source code.",
                    impact="Two functions with visually identical names can have completely different behavior — hidden backdoor.",
                )
            )

    return findings


def detect_homoglyphs_js(content: str) -> list[ScannerResult]:
    """Detect homoglyphs specifically in JS/TS identifiers."""
    findings = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, 1):
        stripped = line.split("//")[0]  # Remove JS comments

        found_chars = []
        found_scripts = set()

        for c in stripped:
            cp = ord(c)
            for start, end, script_name in HOMOGLYPH_RANGES:
                if start <= cp <= end:
                    found_chars.append(c)
                    found_scripts.add(script_name)
                    break

        if found_chars:
            has_latin = any(c.isascii() and c.isalpha() for c in stripped)
            if not has_latin:
                continue

            scripts_str = ", ".join(sorted(found_scripts))
            findings.append(
                ScannerResult(
                    scanner="homoglyph_detection",
                    title=f"JS/TS Unicode homoglyph ({scripts_str})",
                    description=(
                        f"Line {lineno} contains {scripts_str} characters mixed with Latin text. "
                        "In JavaScript, this can create identifiers that look identical but are different."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line.strip()[:80]}...",
                    fix="Replace with ASCII equivalents.",
                    impact="Hidden backdoor via visually identical but different variable names.",
                )
            )

    return findings
