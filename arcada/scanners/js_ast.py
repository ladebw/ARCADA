"""
Scanner 14: JavaScript/TypeScript Security Analysis
Detects JS/TS-specific code execution, supply chain risks, AI/LLM misuse,
and framework-specific vulnerabilities (React, Next.js, Express, etc.).
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class JsAstScanner(BaseScanner):
    name = "js_ast"

    async def scan(self) -> list[ScannerResult]:
        if not self._is_js_file():
            return self.findings
        self._detect_eval_function()
        self._detect_innerhtml_xss()
        self._detect_react_dangerous()
        self._detect_npm_supply_chain()
        self._detect_nodejs_dangerous_apis()
        self._detect_fetch_exfil()
        self._detect_env_exposure()
        self._detect_template_literal_injection()
        self._detect_prototype_pollution()
        self._detect_hardcoded_secrets_js()
        self._detect_crypto_weaknesses()
        self._detect_nextjs_risks()
        return self.findings

    def _is_js_file(self) -> bool:
        if not self.path:
            return True
        js_exts = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
        return self.path.lower().endswith(js_exts)

    def _detect_eval_function(self):
        """Detect eval(), Function(), setTimeout/setInterval with string args."""
        patterns = [
            (r"\beval\s*\(", "eval() — arbitrary code execution", Severity.CRITICAL),
            (
                r"\bnew\s+Function\s*\(",
                "new Function() — code generation",
                Severity.CRITICAL,
            ),
            (
                r"setTimeout\s*\(\s*['\"].*['\"]",
                "setTimeout with string arg (implicit eval)",
                Severity.HIGH,
            ),
            (
                r"setInterval\s*\(\s*['\"].*['\"]",
                "setInterval with string arg (implicit eval)",
                Severity.HIGH,
            ),
            (
                r"document\.write\s*\(",
                "document.write() — DOM injection",
                Severity.HIGH,
            ),
            (
                r"\.execScript\s*\(",
                "execScript() — legacy code execution",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(r"""eval\s*\(\s*['"][^'"]+['"]\s*\)""", line):
                    continue  # Skip obviously static eval
                self.add_finding(
                    title=f"Dangerous JS code execution: {label}",
                    description=(
                        f"'{label}' can execute arbitrary JavaScript. "
                        "If the argument includes user-controlled data, this is Remote Code Execution."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove eval/Function. Use JSON.parse for data. Use structured APIs instead of string execution.",
                    impact="Full client or server-side code execution depending on runtime.",
                )

    def _detect_innerhtml_xss(self):
        """Detect innerHTML, outerHTML, insertAdjacentHTML with dynamic content."""
        patterns = [
            (r"\.innerHTML\s*=", "innerHTML assignment", Severity.CRITICAL),
            (r"\.outerHTML\s*=", "outerHTML assignment", Severity.HIGH),
            (
                r"\.insertAdjacentHTML\s*\(",
                "insertAdjacentHTML()",
                Severity.HIGH,
            ),
            (
                r"document\.write\s*\(",
                "document.write()",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"DOM XSS risk: {label}",
                    description=(
                        f"'{label}' injects HTML into the DOM. "
                        "If the source includes user-controlled data, this is Cross-Site Scripting (XSS)."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use textContent or innerText instead. If HTML is needed, sanitize with DOMPurify.sanitize().",
                    impact="Attacker executes JavaScript in victim's browser — session hijacking, data theft.",
                )

    def _detect_react_dangerous(self):
        """Detect React dangerouslySetInnerHTML."""
        patterns = [
            (
                r"dangerouslySetInnerHTML\s*[=:]\s*\{",
                "dangerouslySetInnerHTML — React XSS",
                Severity.CRITICAL,
            ),
            (
                r"dangerouslySetInnerHTML\s*=\s*\{\{",
                "dangerouslySetInnerHTML (legacy JSX)",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"React XSS: {label}",
                    description=(
                        f"'{label}' bypasses React's built-in XSS protection. "
                        "Any unsanitized user input rendered this way enables XSS."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML. Prefer React elements.",
                    impact="Stored XSS — attacker injects persistent JavaScript that executes for all users.",
                )

    def _detect_npm_supply_chain(self):
        """Detect npm-specific supply chain risks."""
        # Detect preinstall/postinstall scripts in package.json
        if "package.json" in (self.path or ""):
            patterns = [
                (r'"preinstall"\s*:', "preinstall script — runs before npm install"),
                (r'"postinstall"\s*:', "postinstall script — runs after npm install"),
                (r'"install"\s*:', "install script — runs on npm install"),
                (r'"preprepare"\s*:', "preprepare script"),
                (r'"prepare"\s*:', "prepare script — runs on npm install from source"),
            ]
            for pattern, label in patterns:
                for lineno, line in self.grep_lines(pattern):
                    self.add_finding(
                        title=f"npm lifecycle script: {label}",
                        description=(
                            f"'{label}' executes automatically during npm install. "
                            "Malicious packages use these to exfiltrate credentials or install backdoors."
                        ),
                        severity=Severity.CRITICAL
                        if "postinstall" in label or "preinstall" in label
                        else Severity.HIGH,
                        evidence=f"Line {lineno}: {line}",
                        fix="Audit the script content. Use 'npm install --ignore-scripts' for untrusted packages.",
                        impact="Arbitrary shell code execution on every developer/CI machine.",
                    )

        # Detect require of remote URLs
        patterns = [
            (r"""require\s*\(\s*['"]https?://""", "require() with remote URL"),
            (r"""import\s+.*from\s+['"]https?://""", "ES module import from URL (CDN)"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Remote code load: {label}",
                    description=(
                        f"'{label}' loads and executes code from a remote server. "
                        "If the URL is compromised, malicious code executes automatically."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Vendor all dependencies locally. Use npm lockfiles with integrity hashes.",
                    impact="Supply chain attack — attacker controls the remote URL.",
                )

    def _detect_nodejs_dangerous_apis(self):
        """Detect Node.js-specific dangerous APIs."""
        patterns = [
            (
                r"child_process\.(?:exec|execSync|spawn)\s*\(",
                "child_process execution",
                Severity.CRITICAL,
            ),
            (
                r"child_process\.(?:execFile|execFileSync)\s*\(",
                "child_process execFile",
                Severity.HIGH,
            ),
            (
                r"\bprocess\.mainModule\.require\s*\(",
                "process.mainModule.require — runtime module loading",
                Severity.CRITICAL,
            ),
            (
                r"\brequire\s*\(\s*child_process\s*\)",
                "child_process module loaded",
                Severity.HIGH,
            ),
            (
                r"\bvm\.runIn(?:New)?Context\s*\(",
                "vm.runInContext — sandboxed code execution",
                Severity.HIGH,
            ),
            (
                r"\bfs\.(?:write|append)(?:File|FileSync)\s*\(",
                "fs.writeFile — filesystem write",
                Severity.MEDIUM,
            ),
            (
                r"\bfs\.(?:rm|rmdir|unlink|unlinkSync)\s*\(",
                "fs deletion — file removal",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Node.js dangerous API: {label}",
                    description=(
                        f"'{label}' is a powerful Node.js API. "
                        "Verify it is not influenced by user-controlled input."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Validate and sanitize all inputs to these APIs. Prefer higher-level abstractions.",
                    impact="Command injection, file manipulation, or sandbox escape depending on context.",
                )

    def _detect_fetch_exfil(self):
        """Detect data exfiltration via fetch/XMLHttpRequest."""
        patterns = [
            (
                r"""fetch\s*\(\s*['"]https?://.*['"].*""",
                "fetch() to external URL",
            ),
            (
                r"XMLHttpRequest|new\s+XMLHttpRequest",
                "XMLHttpRequest — raw HTTP request",
            ),
            (
                r"navigator\.sendBeacon\s*\(",
                "navigator.sendBeacon — background data send",
            ),
            (
                r"WebSocket\s*\(\s*['\"]wss?://",
                "WebSocket connection",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Outbound data transfer: {label}",
                    description=(
                        f"'{label}' sends data to an external endpoint. "
                        "Verify no sensitive data (tokens, PII, API keys) is included in requests."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix="Audit what data is sent. Strip sensitive fields before transmission. Use CORS and CSP headers.",
                    impact="Data exfiltration to attacker-controlled endpoints.",
                )

    def _detect_env_exposure(self):
        """Detect Next.js/Node.js environment variable exposure."""
        patterns = [
            (
                r"process\.env\.(?!NEXT_PUBLIC_)",
                "process.env access (server-side, may be safe)",
                Severity.LOW,
            ),
            (
                r"NEXT_PUBLIC_.*=.*(?:key|secret|token|password)",
                "NEXT_PUBLIC_ env var with sensitive name",
                Severity.HIGH,
            ),
            (
                r"""(?:console\.log|debug)\s*\(.*process\.env""",
                "Logging process.env (exposes all secrets)",
                Severity.HIGH,
            ),
            (
                r"""JSON\.stringify\s*\(.*process\.env""",
                "Serializing process.env (exposes all secrets)",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Environment variable risk: {label}",
                    description=(
                        f"'{label}' — environment variables may contain secrets. "
                        "NEXT_PUBLIC_ variables are exposed to the browser."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Never prefix secrets with NEXT_PUBLIC_. Never log or serialize process.env.",
                    impact="API keys, database credentials, or secrets exposed to clients.",
                )

    def _detect_template_literal_injection(self):
        """Detect template literal injection (JS equivalent of f-string injection)."""
        patterns = [
            (
                r"""[`].*\$\{.*(?:req\.|request\.|user|input|params|query).*\}[`].*(?:query|sql|command|cmd)""",
                "Template literal with user input in query/command",
            ),
            (
                r"""[`].*\$\{.*(?:req\.body|req\.params|req\.query).*\}[`].*""",
                "Template literal with request data",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Template literal injection: {label}",
                    description=(
                        f"'{label}' embeds user input directly into a template string "
                        "used for queries or commands. This enables injection attacks."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use parameterized queries. Use prepared statements. Never interpolate user input into queries.",
                    impact="SQL injection, NoSQL injection, or command injection.",
                )

    def _detect_prototype_pollution(self):
        """Detect prototype pollution vulnerabilities."""
        patterns = [
            (
                r"__proto__\s*\[",
                "__proto__ bracket access",
                Severity.HIGH,
            ),
            (
                r"""(?:Object|_)\.(?:assign|merge|extend|defaults)\s*\(.*(?:req\.|user|input)""",
                "Object merge with user input (prototype pollution)",
                Severity.HIGH,
            ),
            (
                r"constructor\s*\[",
                "constructor bracket access",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Prototype pollution risk: {label}",
                    description=(
                        f"'{label}' — prototype pollution allows attackers to inject properties "
                        "into all JavaScript objects, leading to RCE or privilege escalation."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use Object.create(null) for data objects. Validate input keys. Freeze prototypes in production.",
                    impact="RCE via property injection, privilege escalation, DoS.",
                )

    def _detect_hardcoded_secrets_js(self):
        """Detect JS-specific hardcoded secrets."""
        patterns = [
            (
                r"""(?:apiKey|api_key|API_KEY)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]""",
                "Hardcoded API key",
                Severity.CRITICAL,
            ),
            (
                r"""(?:secret|SECRET)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]""",
                "Hardcoded secret",
                Severity.CRITICAL,
            ),
            (
                r"""(?:token|TOKEN)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]""",
                "Hardcoded token",
                Severity.HIGH,
            ),
            (
                r"""(?:password|PASSWORD|passwd)\s*[:=]\s*['"][^'"]{8,}['"]""",
                "Hardcoded password",
                Severity.CRITICAL,
            ),
            (
                r"""(?:private_key|privateKey|PRIVATE_KEY)\s*[:=]\s*['"][^'"]+['"]""",
                "Hardcoded private key",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(
                    r"(?i)(example|placeholder|your_|xxx|test|dummy|fake|changeme)",
                    line,
                ):
                    continue
                self.add_finding(
                    title=f"JS hardcoded secret: {label}",
                    description=(
                        f"'{label}' found in JavaScript source. "
                        "These values are visible to anyone who can access the source code or browser devtools."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use environment variables or a secrets manager. Never commit secrets to source control.",
                    impact="Full access to the service this credential controls.",
                )

    def _detect_crypto_weaknesses(self):
        """Detect weak cryptographic usage in JS."""
        patterns = [
            (
                r"createHash\s*\(\s*['\"]md5['\"]",
                "MD5 hash — cryptographically broken",
            ),
            (
                r"createHash\s*\(\s*['\"]sha1['\"]",
                "SHA1 hash — deprecated for security",
            ),
            (
                r"Math\.random\s*\(",
                "Math.random() — not cryptographically secure",
            ),
            (
                r"createCipher\s*\(",
                "createCipher (deprecated) — no authentication",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                severity = (
                    Severity.HIGH
                    if "md5" in label.lower() or "sha1" in label.lower()
                    else Severity.MEDIUM
                )
                self.add_finding(
                    title=f"Weak cryptography: {label}",
                    description=f"'{label}' uses weak or deprecated cryptographic primitives.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Use SHA-256+ for hashing, crypto.randomBytes for randomness, createCipherGCM for encryption.",
                    impact="Predictable randomness, hash collisions, or ciphertext manipulation.",
                )

    def _detect_nextjs_risks(self):
        """Detect Next.js-specific security issues."""
        patterns = [
            (
                r"getServerSideProps\s*\(\s*\{[^}]*req\s*\}",
                "getServerSideProps accessing request object",
                Severity.LOW,
            ),
            (
                r"unstable_allowDynamic\s*",
                "unstable_allowDynamic — bypasses middleware",
                Severity.MEDIUM,
            ),
            (
                r"middleware\s*\.\s*(?:next|rewrite)\s*\(",
                "Middleware rewrite — potential open redirect",
                Severity.MEDIUM,
            ),
            (
                r"headers\s*\(\s*\)\s*\.\s*get\s*\(\s*['\"]x-forwarded-for['\"]",
                "Trusting X-Forwarded-For in Next.js",
                Severity.HIGH,
            ),
            (
                r"revalidate\s*[:=]\s*0",
                "revalidate: 0 — no caching, potential DoS",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Next.js risk: {label}",
                    description=f"'{label}' — review for security implications in your Next.js application.",
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Review the Next.js security documentation. Validate all inputs in server-side functions.",
                    impact="Varies — may include SSRF, open redirect, or DoS.",
                )
