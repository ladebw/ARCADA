"""
Scanner 15: Binary File Analysis
Scans compiled binaries (.so/.dll/.pyd/.dylib/.wasm) for embedded
URLs, IPs, shellcode signatures, and high-entropy sections.
"""

from __future__ import annotations
import math
import re
from collections import Counter
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity

BINARY_EXTENSIONS = {
    ".so",
    ".so.1",
    ".so.2",
    ".dll",
    ".exe",
    ".pyd",
    ".dylib",
    ".wasm",
    ".o",
    ".obj",
    ".a",
    ".lib",
}

MIN_STRING_LENGTH = 12


def _byte_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counter.values()
    )


def _extract_strings(data: bytes, min_len: int = MIN_STRING_LENGTH) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    # ASCII strings
    ascii_pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    ascii_strings = [
        m.decode("ascii", errors="replace") for m in re.findall(ascii_pattern, data)
    ]
    # UTF-16LE strings (common in Windows DLLs)
    utf16_pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
    utf16_strings = [
        m.decode("utf-16-le", errors="replace") for m in re.findall(utf16_pattern, data)
    ]
    return ascii_strings + utf16_strings


# Known shellcode byte patterns
SHELLCODE_SIGNATURES = [
    (rb"\x31\xc0\x50\x68", "Linux x86 shellcode (xor eax; push; push)"),
    (rb"\x6a\x00\x6a\x00\x6a\x00", "Windows shellcode (push 0 chains)"),
    (rb"\x31\xc9\xf7\xe1", "Linux shellcode (xor ecx; mul ecx)"),
    (rb"\xfc\xe8[\x00-\xff]{4}", "Metasploit-style shellcode stub"),
    (rb"\x64\xa1\x30\x00\x00\x00", "FS:[0x30] — PEB access (Windows shellcode)"),
    (rb"\x64\x8b\x15\x30\x00\x00\x00", "FS:[0x30] — PEB access variant"),
]


class BinaryScanner(BaseScanner):
    name = "binary"

    async def scan(self) -> list[ScannerResult]:
        # Only scan binary files
        if not self._is_binary():
            return self.findings

        data = (
            self.content.encode("utf-8", errors="replace")
            if isinstance(self.content, str)
            else self.content
        )
        if not data:
            return self.findings

        self._scan_strings(data)
        self._scan_entropy(data)
        self._scan_shellcode(data)
        self._scan_embedded_python(data)
        return self.findings

    def _is_binary(self) -> bool:
        if not self.path:
            return False
        path_lower = self.path.lower()
        return any(path_lower.endswith(ext) for ext in BINARY_EXTENSIONS)

    def _scan_strings(self, data: bytes):
        """Extract and analyze strings embedded in the binary."""
        strings = _extract_strings(data)

        for s in strings:
            # Check for URLs
            if re.search(r"https?://[^\s]{5,}", s):
                # Skip common legitimate URLs
                if not re.search(
                    r"(?i)(microsoft|github|python|pypi|mozilla|google|cloudflare)", s
                ):
                    self.add_finding(
                        title="URL embedded in compiled binary",
                        description=(
                            f"A URL was found embedded in the compiled binary. "
                            "This could be a C2 (command and control) server, exfiltration endpoint, "
                            "or a payload download URL."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"Embedded URL: {s[:100]}",
                        fix="Verify this URL is expected. If it's a C2 or exfil endpoint, the binary is malicious.",
                        impact="Binary may communicate with an attacker-controlled server.",
                    )

            # Check for IP addresses
            ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", s)
            for ip in ip_matches:
                # Skip common localhost/metadata IPs
                if ip.startswith(("127.", "0.0.0.", "10.", "192.168.", "172.")):
                    if ip != "169.254.169.254":  # AWS metadata endpoint is suspicious
                        continue
                self.add_finding(
                    title="IP address embedded in compiled binary",
                    description=(
                        f"IP address {ip} was found in the binary. "
                        "This could be a hardcoded C2 server or data exfiltration endpoint."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Embedded IP: {ip}",
                    fix="Verify this IP is expected. Hardcoded IPs in binaries are a backdoor indicator.",
                    impact="Binary may connect to an attacker-controlled server.",
                )

            # Check for AWS metadata endpoint (SSRF indicator)
            if "169.254.169.254" in s:
                self.add_finding(
                    title="AWS metadata endpoint in compiled binary (SSRF indicator)",
                    description=(
                        "The AWS EC2 metadata endpoint (169.254.169.254) was found in the binary. "
                        "This is a strong indicator of a cloud credential theft payload."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Found: {s[:100]}",
                    fix="This binary contains a cloud credential theft payload. Remove it immediately.",
                    impact="Steals IAM credentials from EC2 instance metadata service.",
                )

            # Check for Python marshal bytecode
            if re.search(r"import marshal|marshal\.loads|cPickle", s):
                self.add_finding(
                    title="Python marshal/pickle reference in compiled binary",
                    description=(
                        "References to Python's marshal or pickle module were found in a compiled binary. "
                        "This could indicate embedded Python bytecode that gets executed."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Reference: {s[:80]}",
                    fix="Decode and audit the embedded Python bytecode.",
                    impact="Hidden Python code executing from within a compiled binary.",
                )

    def _scan_entropy(self, data: bytes):
        """Check overall binary entropy for packed/encrypted indicators."""
        if len(data) < 1000:
            return

        entropy = _byte_entropy(data)

        if entropy > 7.5:
            self.add_finding(
                title="Very high entropy binary (packed/encrypted)",
                description=(
                    f"This binary has Shannon entropy of {entropy:.2f} (max 8.0). "
                    "Normal compiled code has entropy 5.5-7.0. Values above 7.5 indicate "
                    "the binary is packed, encrypted, or contains large amounts of random data — "
                    "common in malware to evade signature detection."
                ),
                severity=Severity.HIGH,
                evidence=f"Entropy: {entropy:.2f}/8.0, Size: {len(data)} bytes",
                fix="Analyze with a disassembler (IDA, Ghidra). Packed binaries are a strong malware indicator.",
                impact="Packed binary evades signature-based antivirus detection.",
            )
        elif entropy > 7.0:
            self.add_finding(
                title="High entropy binary (possibly compressed)",
                description=(
                    f"This binary has entropy of {entropy:.2f}, which is higher than normal. "
                    "This may indicate compression, encryption, or obfuscation."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Entropy: {entropy:.2f}/8.0",
                fix="Verify the entropy is expected (e.g., compressed data section).",
                impact="Higher than normal entropy may hide malicious content.",
            )

    def _scan_shellcode(self, data: bytes):
        """Check for known shellcode byte patterns."""
        for pattern, label in SHELLCODE_SIGNATURES:
            if re.search(pattern, data):
                self.add_finding(
                    title=f"Shellcode signature detected: {label}",
                    description=(
                        f"A known shellcode byte pattern was found in the binary: {label}. "
                        "This is a strong indicator that the binary contains exploit code."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Signature: {label}",
                    fix="This binary contains shellcode. Remove it and audit the supply chain.",
                    impact="Binary contains exploit code that can compromise the host system.",
                )

    def _scan_embedded_python(self, data: bytes):
        """Check for embedded Python interpreter calls."""
        patterns = [
            (rb"Py_Initialize", "Embedded Python interpreter initialization"),
            (rb"PyRun_SimpleString", "Embedded Python code execution"),
            (rb"Py_CompileString", "Embedded Python compilation"),
            (rb"PyEval_EvalCode", "Embedded Python code evaluation"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, data):
                self.add_finding(
                    title=f"Embedded Python interpreter: {label}",
                    description=(
                        f"The binary contains '{label}', indicating it embeds a Python interpreter. "
                        "While this is normal for Python extensions (.pyd, .so), it can also be used "
                        "to execute hidden Python code from within a compiled binary."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Found: {label}",
                    fix="Verify the Python interpreter usage is expected for this binary type.",
                    impact="Hidden Python code can execute from within the compiled binary.",
                )
