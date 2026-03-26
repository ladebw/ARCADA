"""
Scanner 2: Supply Chain Risk
Detects install-time code execution, dynamic imports, remote code downloads,
CI/CD secret leakage, obfuscated payloads, and compromised maintainer indicators.
"""

from __future__ import annotations
import math
import re
from collections import Counter
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity
from arcada.scanners.advanced_analysis import (
    shannon_entropy,
    classify_encoding,
    ENTROPY_THRESHOLDS,
    analyze_string_entropy,
    detect_homoglyphs,
    detect_homoglyphs_js,
    scan_content_for_redos,
)

# Cyrillic characters that look like Latin (homoglyphs)
CYRILLIC_HOMOGLYPHS = {
    "\u0430": "a",  # а
    "\u0435": "e",  # е
    "\u043e": "o",  # о
    "\u0440": "p",  # р
    "\u0441": "c",  # с
    "\u0443": "y",  # у
    "\u0445": "x",  # х
    "\u0410": "A",  # А
    "\u0415": "E",  # Е
    "\u041e": "O",  # О
    "\u0420": "P",  # Р
    "\u0421": "C",  # С
    "\u0425": "X",  # Х
}


class SupplyChainScanner(BaseScanner):
    name = "supply_chain"

    async def scan(self) -> list[ScannerResult]:
        self._detect_setup_hooks()
        self._detect_dynamic_imports()
        self._detect_remote_code_fetch()
        self._detect_ci_secret_leakage()
        self._detect_postinstall_scripts()
        self._detect_inline_base64()
        self._detect_obfuscation()
        self._detect_unicode_homoglyphs()
        self._detect_sys_module_manipulation()
        self._detect_setattr_abuse()
        self._detect_ctypes_usage()
        self._detect_js_module_hijacking()
        self._detect_js_dependency_confusion()
        self._detect_redos()
        return self.findings

    def _detect_setup_hooks(self):
        """Detect install-time code execution in setup.py / pyproject."""
        dangerous_hooks = [
            (r"cmdclass\s*=", "Custom cmdclass in setup.py"),
            (r"def\s+run\s*\(self\)", "Custom run() in setup command"),
            (r"subprocess\.(call|run|Popen|check_output)", "subprocess in setup"),
            (r"os\.system\s*\(", "os.system() in setup"),
        ]
        for pattern, label in dangerous_hooks:
            matches = self.grep_lines(pattern)
            for lineno, line in matches:
                self.add_finding(
                    title=f"Install-time code execution: {label}",
                    description=(
                        f"Code matching '{label}' was found. This executes automatically "
                        "when someone installs the package via pip. "
                        "Malicious packages commonly use this to steal credentials."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Remove install hooks. Use pyproject.toml declarative config. "
                        "If hooks are required, sandbox the install environment."
                    ),
                    impact="Arbitrary code runs on the developer or CI machine at install time.",
                )

    def _detect_dynamic_imports(self):
        patterns = [
            (r"importlib\.import_module\s*\(", "importlib.import_module()"),
            (r"__import__\s*\(", "__import__()"),
            (r"exec\s*\(\s*compile\s*\(", "exec(compile(...))"),
            (r"exec\s*\(\s*open\s*\(", "exec(open(...))"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Dynamic import detected: {label}",
                    description=(
                        f"Dynamic import via '{label}' can load arbitrary code at runtime. "
                        "If the import source is attacker-controlled, this is RCE."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Replace with explicit static imports. If dynamic loading is required, whitelist allowed module names.",
                    impact="Attacker can inject arbitrary module names to execute malicious code.",
                )

    def _detect_remote_code_fetch(self):
        patterns = [
            (r"urllib\.request\.urlopen", "urllib fetch"),
            (r"requests\.get.*exec|exec.*requests\.get", "fetch + exec"),
            (r"httpx\.(get|post).*eval|eval.*httpx", "fetch + eval"),
            (r"curl\s+-[sL].*\|\s*(bash|sh|python)", "curl pipe to shell"),
            (r"wget\s+.*\|\s*(bash|sh|python)", "wget pipe to shell"),
            (r"exec\s*\(\s*(requests|urllib|httpx|aiohttp)", "exec fetched content"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Remote code execution via fetch: {label}",
                    description=(
                        f"Pattern '{label}' fetches content from a remote URL and executes it. "
                        "This is a classic supply-chain backdoor technique."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Never execute remotely fetched content. Vendor all dependencies locally.",
                    impact="Full remote code execution — attacker controls the fetched URL.",
                )

    def _detect_ci_secret_leakage(self):
        """Detect patterns in CI config that may leak secrets."""
        patterns = [
            (
                r"echo\s+\$\{?\w*(TOKEN|KEY|SECRET|PASSWORD|PASS|PWD|API)\}?",
                "echo of secret env var",
            ),
            (r"env\s*\|", "env dump via pipe"),
            (r"printenv", "printenv (dumps all env vars)"),
            (r"set\s+-x\b", "set -x (traces secrets in bash)"),
            (r"curl.*-H.*Authorization.*\$", "Authorization header with variable"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"CI/CD secret leakage risk: {label}",
                    description=(
                        f"'{label}' found in CI config. This may print secrets "
                        "to CI logs which are often publicly accessible."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove secret values from CI logs. Use masked variables. Never echo secrets.",
                    impact="Secrets exposed in CI logs can be harvested by anyone with log access.",
                )

    def _detect_postinstall_scripts(self):
        """Detect npm-style postinstall or prepare hooks."""
        patterns = [
            (r'"postinstall"\s*:', "npm postinstall hook"),
            (r'"prepare"\s*:', "npm prepare hook"),
            (r'"preinstall"\s*:', "npm preinstall hook"),
            (r'"install"\s*:\s*"[^"]*sh\b', "npm install shell script"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Package lifecycle hook: {label}",
                    description=(
                        f"'{label}' executes automatically during npm install. "
                        "Malicious packages use this to run backdoors."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Audit every lifecycle hook. Use 'npm install --ignore-scripts' "
                        "to disable them. Consider removing the hook entirely."
                    ),
                    impact="Arbitrary shell code executes on every developer machine that installs this.",
                )

    def _detect_inline_base64(self):
        """Detect large base64 blobs that may hide malicious payloads."""
        patterns = [
            (r"base64\.b64decode\s*\(", "base64 decode"),
            (r'Buffer\.from\s*\(.*,\s*[\'"]base64[\'"]\)', "Node base64 decode"),
            (r"atob\s*\(", "atob() browser decode"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Base64 encoded payload: {label}",
                    description=(
                        f"Base64 decoding found at line {lineno}. Malicious packages "
                        "often hide payloads in base64 to evade static analysis."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Decode and audit all base64 blobs. Remove any that contain code or executable content.",
                    impact="Hidden malicious payload that evades signature-based detection.",
                )

    def _detect_obfuscation(self):
        """Detect obfuscated payloads using adaptive entropy thresholds."""
        # 1. High-entropy string literals with adaptive thresholds
        for lineno, line in enumerate(self.content.splitlines(), 1):
            strings = re.findall(r"""['"](.*?)['"]""", line)
            for s in strings:
                finding = analyze_string_entropy(s, lineno)
                if finding:
                    self.findings.append(finding)

        # 2. Hex/octal escape density
        for lineno, line in enumerate(self.content.splitlines(), 1):
            if len(line) < 20:
                continue
            hex_chars = len(re.findall(r"\\x[0-9a-fA-F]{2}", line))
            octal_chars = len(re.findall(r"\\[0-7]{3}", line))
            unicode_escapes = len(re.findall(r"\\u[0-9a-fA-F]{4}", line))
            total_escapes = hex_chars + octal_chars + unicode_escapes
            if total_escapes > 10 and total_escapes / len(line) > 0.3:
                self.add_finding(
                    title="High escape sequence density (possible encoded payload)",
                    description=(
                        f"Line {lineno} has {total_escapes} escape sequences "
                        f"({hex_chars} hex, {octal_chars} octal, {unicode_escapes} unicode). "
                        "This is commonly used to obfuscate malicious payloads."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {total_escapes} escape sequences in {len(line)} chars",
                    fix="Decode the escape sequences and audit the resulting content.",
                    impact="Encrypted or encoded payload hidden from static analysis.",
                )

        # 3. Exec at module level with non-literal argument
        for lineno, line in self.grep_lines(r"^\s*(?:exec|eval)\s*\("):
            if not re.search(r"""(?:exec|eval)\s*\(\s*['"][^'"]+['"]\s*\)""", line):
                self.add_finding(
                    title="Module-level exec/eval with dynamic argument",
                    description=(
                        "exec() or eval() at module level with a non-literal argument. "
                        "This executes arbitrary code when the module is imported."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Replace with explicit, static code. Never exec dynamic content.",
                    impact="Arbitrary code execution on import — classic backdoor technique.",
                )

    def _detect_unicode_homoglyphs(self):
        """Detect Unicode homoglyphs across Cyrillic, Greek, Armenian, Cherokee, and other scripts."""
        # Determine if this is a JS/TS file
        is_js = self.path and self.path.lower().endswith(
            (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
        )
        if is_js:
            results = detect_homoglyphs_js(self.content)
        else:
            results = detect_homoglyphs(self.content)
        self.findings.extend(results)

    def _detect_sys_module_manipulation(self):
        """Detect patches to sys.modules, sys.meta_path, or sys.path_hooks."""
        patterns = [
            (r"sys\.modules\[", "sys.modules direct index"),
            (r"sys\.modules\.get\(", "sys.modules probing"),
            (r"sys\.modules\.pop\(", "sys.modules removal"),
            (r"sys\.meta_path\.append", "custom import hook (meta_path)"),
            (r"sys\.meta_path\.insert", "custom import hook (meta_path)"),
            (r"sys\.path_hooks\.append", "custom path hook"),
            (r"sys\.path_hooks\.insert", "custom path hook"),
            (r"sys\.path\.insert", "sys.path manipulation"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Python import system manipulation: {label}",
                    description=(
                        f"'{label}' modifies Python's import system. This is commonly used "
                        "to intercept imports, patch modules after loading, or inject malicious "
                        "code into otherwise legitimate packages."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit why this code modifies the import system. This is almost never needed in production code.",
                    impact="Attacker can intercept any import in the entire Python process.",
                )

    def _detect_setattr_abuse(self):
        """Detect setattr with dynamic attribute names — patches methods at runtime."""
        for lineno, line in self.grep_lines(r"setattr\s*\("):
            # Check if the attribute name is a variable (not a string literal)
            if not re.search(r"""setattr\s*\([^,]+,\s*['"][^'"]+['"]""", line):
                self.add_finding(
                    title="setattr with dynamic attribute name (runtime patching)",
                    description=(
                        "setattr() is called with a dynamic (non-literal) attribute name. "
                        "This can replace methods on objects at runtime — a technique used "
                        "to inject backdoors into existing functionality."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use explicit attribute assignment. Audit why dynamic attribute names are needed.",
                    impact="Methods can be silently replaced with malicious versions at runtime.",
                )

    def _detect_ctypes_usage(self):
        """Detect ctypes usage in pure-Python packages — unexpected native code loading."""
        patterns = [
            (r"ctypes\.cdll\.LoadLibrary", "ctypes dynamic library load"),
            (r"ctypes\.CDLL\(", "ctypes CDLL load"),
            (r"ctypes\.windll\.", "ctypes Windows DLL load"),
            (r"ctypes\.POINTER\(", "ctypes pointer manipulation"),
            (r"ctypes\.cast\(", "ctypes cast"),
            (r"ctypes\.memmove\(", "ctypes memory copy"),
            (r"ctypes\.memset\(", "ctypes memory write"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Native code loading via ctypes: {label}",
                    description=(
                        f"'{label}' loads or manipulates native code from a Python package. "
                        "While sometimes legitimate (performance), it can also be used to "
                        "hide malicious behavior in compiled code that evades Python-level analysis."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Verify the library being loaded is expected and safe. Check if the native code is open source.",
                    impact="Native code can bypass all Python-level security checks and logging.",
                )

    def _detect_js_module_hijacking(self):
        """Detect JS/TS module hijacking patterns."""
        if not self.path:
            return
        path_lower = self.path.lower()
        if not any(
            path_lower.endswith(ext)
            for ext in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
        ):
            return

        patterns = [
            (
                r"require\.resolve\s*\(",
                "require.resolve — may probe module paths",
                Severity.MEDIUM,
            ),
            (
                r"Module\._load\s*\(",
                "Module._load — internal Node.js module loading bypass",
                Severity.CRITICAL,
            ),
            (
                r"module\.constructor\._resolveFilename",
                "Module resolution hijacking",
                Severity.CRITICAL,
            ),
            (
                r"process\.binding\s*\(",
                "process.binding — internal Node.js API access",
                Severity.HIGH,
            ),
            (
                r"""require\.cache\s*\[.*delete""",
                "Module cache manipulation (hot-reload hijack)",
                Severity.HIGH,
            ),
            (
                r"""(?:import|require)\s*\(.*\)\s*\.then""",
                "Dynamic import with .then (potential code loading)",
                Severity.LOW,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"JS module hijacking: {label}",
                    description=(
                        f"'{label}' manipulates the Node.js module system. "
                        "This can intercept or replace any required module at runtime."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Avoid internal Node.js APIs. Use standard import/require patterns.",
                    impact="Any module in the application can be silently replaced with malicious code.",
                )

    def _detect_js_dependency_confusion(self):
        """Detect potential dependency confusion in JS/TS projects."""
        if not self.path:
            return
        path_lower = self.path.lower()
        if not any(path_lower.endswith(ext) for ext in (".json", ".js", ".ts")):
            return

        # Check for private registry config without strict scope
        patterns = [
            (
                r'"registry"\s*:\s*"https?://(?!registry\.npmjs\.org)',
                "Custom npm registry configured",
                Severity.MEDIUM,
            ),
            (
                r'"publishConfig"\s*:\s*\{[^}]*"registry"',
                "publishConfig with custom registry",
                Severity.LOW,
            ),
            (
                r"\.npmrc.*registry\s*=",
                ".npmrc custom registry",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"JS dependency confusion risk: {label}",
                    description=(
                        f"'{label}' — when private packages share names with public npm packages, "
                        "attackers can publish malicious packages with the same name to the public registry."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use scoped packages (@org/pkg). Configure registry priority. Use package-lock.json with integrity hashes.",
                    impact="Malicious public package installed instead of private one.",
                )

    def _detect_redos(self):
        """Detect regex patterns vulnerable to ReDoS."""
        redos_findings = scan_content_for_redos(self.content)
        self.findings.extend(redos_findings)
