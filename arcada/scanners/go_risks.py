"""
Scanner 15: Go Security Analysis
Detects Go-specific code execution, unsafe operations, injection,
and framework-specific vulnerabilities.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class GoRisksScanner(BaseScanner):
    name = "go_risks"

    async def scan(self) -> list[ScannerResult]:
        if not self._is_go_file():
            return self.findings
        self._detect_os_exec()
        self._detect_unsafe_package()
        self._detect_sql_injection()
        self._detect_command_injection()
        self._detect_cgo_usage()
        self._detect_net_http_risks()
        self._detect_crypto_weaknesses_go()
        self._detect_hardcoded_secrets_go()
        self._detect_filesystem_risks()
        self._detect_yaml_deserialization()
        return self.findings

    def _is_go_file(self) -> bool:
        if not self.path:
            return True
        return self.path.lower().endswith(".go")

    def _detect_os_exec(self):
        """Detect os/exec command execution."""
        patterns = [
            (
                r"exec\.Command\s*\(",
                "exec.Command() — command execution",
                Severity.CRITICAL,
            ),
            (
                r"exec\.CommandContext\s*\(",
                "exec.CommandContext() — command execution with context",
                Severity.HIGH,
            ),
            (
                r"""cmd\.Run\s*\(""",
                "cmd.Run() — executes command",
                Severity.HIGH,
            ),
            (
                r"""cmd\.Start\s*\(""",
                "cmd.Start() — starts command asynchronously",
                Severity.HIGH,
            ),
            (
                r"""cmd\.Output\s*\(""",
                "cmd.Output() — executes and captures output",
                Severity.HIGH,
            ),
            (
                r"\.Shell\s*=\s*true",
                "Shell=true — runs through system shell",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go command execution: {label}",
                    description=(
                        f"'{label}' executes external commands. "
                        "If any argument comes from user input, this is command injection."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Validate all arguments. Avoid Shell=true. Use exec.Command with argument lists, not string concatenation.",
                    impact="Arbitrary command execution on the server.",
                )

    def _detect_unsafe_package(self):
        """Detect unsafe package usage — bypasses Go's type safety."""
        patterns = [
            (
                r'"unsafe"',
                "unsafe package imported",
            ),
            (
                r"unsafe\.Pointer\s*\(",
                "unsafe.Pointer — type-unsafe memory access",
            ),
            (
                r"unsafe\.Sizeof\s*\(",
                "unsafe.Sizeof — memory layout inspection",
            ),
            (
                r"unsafe\.Offsetof\s*\(",
                "unsafe.Offsetof — memory offset calculation",
            ),
            (
                r"reflect\.ValueOf\(.*\)\.(?:Set|SetString|SetInt)\s*\(",
                "reflect — runtime value mutation",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go unsafe operation: {label}",
                    description=(
                        f"'{label}' bypasses Go's memory safety guarantees. "
                        "This can lead to memory corruption, crashes, or security vulnerabilities."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Avoid unsafe package. If necessary, ensure pointer arithmetic is bounds-checked.",
                    impact="Memory corruption, segmentation faults, potential code execution.",
                )

    def _detect_sql_injection(self):
        """Detect SQL injection via string concatenation in Go."""
        patterns = [
            (
                r"(?:fmt\.Sprintf|fmt\.Fprintf)\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)",
                "SQL query built with fmt.Sprintf",
                Severity.CRITICAL,
            ),
            (
                r"""db\.(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf|"[^"]*\+|`)""",
                "db.Query/Exec with string concatenation",
                Severity.CRITICAL,
            ),
            (
                r"""(?:strings\.Join|"\s*\+\s*).*(?:SELECT|INSERT|UPDATE|DELETE)""",
                "SQL query via string join/concatenation",
                Severity.CRITICAL,
            ),
            (
                r"gorm\.(?:Where|Raw)\s*\(\s*fmt\.Sprintf",
                "GORM query with fmt.Sprintf",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go SQL injection: {label}",
                    description=(
                        f"'{label}' builds SQL queries using string formatting. "
                        "User input interpolated into queries enables SQL injection."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use parameterized queries: db.Query('SELECT ... WHERE id = ?', userID)",
                    impact="Full database compromise — data exfiltration, modification, or deletion.",
                )

    def _detect_command_injection(self):
        """Detect command injection via string interpolation."""
        patterns = [
            (
                r"""exec\.Command\s*\(\s*"sh"\s*,\s*"-c"\s*,""",
                "exec.Command with sh -c (shell injection)",
                Severity.CRITICAL,
            ),
            (
                r"""exec\.Command\s*\(\s*"bash"\s*,""",
                "exec.Command with bash",
                Severity.CRITICAL,
            ),
            (
                r"""exec\.Command\s*\(\s*fmt\.Sprintf""",
                "exec.Command with fmt.Sprintf (command injection)",
                Severity.CRITICAL,
            ),
            (
                r"""os\.System\s*\(""",
                "os.System (deprecated) — shell command execution",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go command injection: {label}",
                    description=(
                        f"'{label}' passes commands through a shell or uses string formatting. "
                        "This enables full command injection."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Never use sh -c with user input. Use exec.Command with explicit argument lists.",
                    impact="Arbitrary command execution with the application's privileges.",
                )

    def _detect_cgo_usage(self):
        """Detect CGo usage — bridges to C code, bypasses Go safety."""
        patterns = [
            (
                r'import\s+"C"',
                "CGo import — C code bridge",
            ),
            (
                r"//export\s+",
                "CGo export — function exposed to C",
            ),
            (
                r"C\.(?:malloc|free|CBytes|GoBytes|CString)\s*\(",
                "CGo memory operations",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"CGo usage: {label}",
                    description=(
                        f"'{label}' bridges Go to C code, bypassing Go's memory safety. "
                        "C code is subject to buffer overflows, use-after-free, and other memory bugs."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Avoid CGo where possible. If necessary, audit C code for memory safety.",
                    impact="Memory corruption vulnerabilities inherited from C code.",
                )

    def _detect_net_http_risks(self):
        """Detect net/http security issues."""
        patterns = [
            (
                r"tls\.Config\{[^}]*InsecureSkipVerify\s*:\s*true",
                "TLS InsecureSkipVerify — certificate validation disabled",
                Severity.CRITICAL,
            ),
            (
                r"http\.ListenAndServe\s*\(",
                "http.ListenAndServe — unencrypted HTTP",
                Severity.MEDIUM,
            ),
            (
                r"http\.HandleFunc\s*\(.*\b(?:DELETE|PUT|POST)\b",
                "HTTP handler for mutating operations",
                Severity.LOW,
            ),
            (
                r"net/http/pprof",
                "pprof debug endpoint exposed",
                Severity.HIGH,
            ),
            (
                r'"expvar"',
                "expvar — exposes internal metrics",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go HTTP risk: {label}",
                    description=f"'{label}' — review for security implications.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use HTTPS in production. Remove debug endpoints. Enable TLS certificate verification.",
                    impact="Man-in-the-middle attacks, information disclosure, or unauthorized access.",
                )

    def _detect_crypto_weaknesses_go(self):
        """Detect weak cryptographic usage in Go."""
        patterns = [
            (
                r'"crypto/md5"',
                "crypto/md5 imported — MD5 is broken",
                Severity.HIGH,
            ),
            (
                r'"crypto/sha1"',
                "crypto/sha1 imported — SHA1 deprecated",
                Severity.MEDIUM,
            ),
            (
                r'"crypto/des"',
                "crypto/des imported — DES is broken",
                Severity.HIGH,
            ),
            (
                r'"crypto/rc4"',
                "crypto/rc4 imported — RC4 is broken",
                Severity.HIGH,
            ),
            (
                r"md5\.New\s*\(",
                "md5.New — MD5 hash creation",
                Severity.HIGH,
            ),
            (
                r"sha1\.New\s*\(",
                "sha1.New — SHA1 hash creation",
                Severity.MEDIUM,
            ),
            (
                r"rand\.(?:Int|Float|Intn)\s*\(",
                "math/rand used for random numbers (not crypto/rand)",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Weak cryptography in Go: {label}",
                    description=f"'{label}' uses weak or deprecated cryptographic primitives.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use crypto/sha256, crypto/aes, crypto/rand instead.",
                    impact="Hash collisions, predictable randomness, or ciphertext manipulation.",
                )

    def _detect_hardcoded_secrets_go(self):
        """Detect hardcoded secrets in Go code."""
        patterns = [
            (
                r'(?:apiKey|api_key|API_KEY|ApiKey)\s*=\s*"[A-Za-z0-9_\-]{20,}"',
                "Hardcoded API key",
                Severity.CRITICAL,
            ),
            (
                r'(?:secret|Secret|SECRET|password|Password|PASSWORD)\s*=\s*"[^"]{8,}"',
                "Hardcoded secret/password",
                Severity.CRITICAL,
            ),
            (
                r'(?:token|Token|TOKEN)\s*=\s*"[A-Za-z0-9_\-]{20,}"',
                "Hardcoded token",
                Severity.HIGH,
            ),
            (
                r'dsn\s*=\s*"(?:postgres|mysql|mongodb)://[^"]+@',
                "Database connection string with credentials",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(
                    r"(?i)(example|placeholder|your_|xxx|test|dummy|fake)", line
                ):
                    continue
                self.add_finding(
                    title=f"Go hardcoded secret: {label}",
                    description=f"'{label}' found in Go source code.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use environment variables or a secrets manager (Vault, AWS SSM).",
                    impact="Full access to the service this credential controls.",
                )

    def _detect_filesystem_risks(self):
        """Detect dangerous filesystem operations."""
        patterns = [
            (
                r"os\.RemoveAll\s*\(",
                "os.RemoveAll — recursive deletion",
            ),
            (
                r"os\.Remove\s*\(",
                "os.Remove — file deletion",
            ),
            (
                r"os\.MkdirAll\s*\(.*0777",
                "os.MkdirAll with 0777 permissions",
            ),
            (
                r"os\.(?:WriteFile|Create)\s*\(",
                "os.WriteFile/Create — file write",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go filesystem risk: {label}",
                    description=f"'{label}' — verify the path is not user-controlled.",
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix="Validate and sanitize file paths. Use filepath.Clean and check prefix.",
                    impact="Path traversal, file deletion, or arbitrary file write.",
                )

    def _detect_yaml_deserialization(self):
        """Detect unsafe YAML deserialization in Go."""
        patterns = [
            (
                r"yaml\.Unmarshal\s*\(",
                "yaml.Unmarshal — may allow arbitrary object creation",
            ),
            (
                r"gopkg\.in/yaml\.v2.*Unmarshal",
                "yaml.v2 Unmarshal",
            ),
            (
                r"json\.Unmarshal\s*\(.*(?:json\.RawMessage|interface\{\})",
                "json.Unmarshal into raw interface — type confusion",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Go deserialization risk: {label}",
                    description=(
                        f"'{label}' deserializes data into Go types. "
                        "If the schema is not strictly validated, this can lead to unexpected behavior."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use strict struct types for deserialization. Validate schema after unmarshaling.",
                    impact="Type confusion, denial of service, or unexpected behavior from crafted payloads.",
                )
