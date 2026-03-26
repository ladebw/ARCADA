"""
Scanner 5: Code Execution Risks
Detects eval/exec, shell injection, subprocess misuse, and unsafe deserialization.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class CodeExecScanner(BaseScanner):
    name = "code_exec"

    async def scan(self) -> list[ScannerResult]:
        self._detect_eval_exec()
        self._detect_shell_injection()
        self._detect_subprocess_misuse()
        self._detect_unsafe_deserialization()
        self._detect_template_injection()
        self._detect_path_traversal()
        self._detect_unsafe_yaml()
        self._detect_xxe()
        self._detect_js_eval()
        self._detect_string_evasion()
        self._detect_trigger_backdoors()
        return self.findings

    def _detect_eval_exec(self):
        patterns = [
            (r"\beval\s*\(", "eval()", Severity.CRITICAL),
            (r"\bexec\s*\(", "exec()", Severity.CRITICAL),
            (r"\bcompile\s*\(.*exec", "compile() for exec", Severity.HIGH),
            (
                r"getattr\s*\(.*,\s*['\"]__\w+__['\"]",
                "getattr with dunder (possible magic method abuse)",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                # Reduce noise: skip if argument is obviously static
                if re.search(r'eval\s*\(\s*[\'"][^\'"]+[\'"]\s*\)', line):
                    continue
                self.add_finding(
                    title=f"Dangerous code execution: {label}",
                    description=(
                        f"'{label}' executes arbitrary Python code at runtime. "
                        "If any part of the argument comes from user input or an "
                        "external source, this is Remote Code Execution (RCE)."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Replace eval/exec with safe alternatives. "
                        "Use ast.literal_eval() for data parsing. "
                        "Use explicit function dispatch instead of eval for logic."
                    ),
                    impact="Full server compromise — attacker runs any code with the process's privileges.",
                )

    def _detect_shell_injection(self):
        patterns = [
            (r"os\.system\s*\(", "os.system()", Severity.CRITICAL),
            (r"os\.popen\s*\(", "os.popen()", Severity.CRITICAL),
            (r"commands\.getoutput\s*\(", "commands.getoutput()", Severity.CRITICAL),
            (
                r"subprocess\.[A-Za-z]+\s*\(.*shell\s*=\s*True",
                "subprocess with shell=True",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Shell injection risk: {label}",
                    description=(
                        f"'{label}' passes commands to the OS shell. "
                        "If any part of the command is user-controlled, "
                        "this is a shell injection vulnerability."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Use subprocess.run() with a list of arguments (not a string). "
                        "Never set shell=True with user input. "
                        "Use shlex.quote() if string args are unavoidable."
                    ),
                    impact="Attacker can run any shell command with the web server's privileges.",
                )

    def _detect_subprocess_misuse(self):
        """Detect subprocess calls that may run with insufficient control."""
        patterns = [
            (r"subprocess\.run\s*\(", "subprocess.run"),
            (r"subprocess\.Popen\s*\(", "subprocess.Popen"),
            (r"subprocess\.call\s*\(", "subprocess.call"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(r"shell\s*=\s*True", line):
                    continue  # Already caught above
                self.add_finding(
                    title=f"Subprocess execution: {label}",
                    description=(
                        f"'{label}' invokes an external process. "
                        "Verify the command and arguments are not influenced by untrusted input."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line}",
                    fix="Ensure all arguments are hardcoded or validated. Use shlex.quote() if needed.",
                    impact="Command injection if arguments include user-controlled data.",
                )

    def _detect_unsafe_deserialization(self):
        patterns = [
            (
                r"\bpickle\.loads?\s*\(",
                "pickle.load() — unsafe deserialization",
                Severity.CRITICAL,
            ),
            (
                r"\bpickle\.Unpickler\s*\(",
                "pickle.Unpickler — unsafe deserialization",
                Severity.CRITICAL,
            ),
            (
                r"\byaml\.load\s*\([^,)]+\)",
                "yaml.load() without Loader (unsafe)",
                Severity.HIGH,
            ),
            (
                r"\bjsonpickle\.decode\s*\(",
                "jsonpickle.decode() — unsafe",
                Severity.HIGH,
            ),
            (
                r"\bdill\.loads?\s*\(",
                "dill.load() — unsafe deserialization",
                Severity.HIGH,
            ),
            (
                r"\bcobra\.load\s*\(",
                "cobra.load() — unsafe deserialization",
                Severity.HIGH,
            ),
            (
                r"\bmarshal\.loads?\s*\(",
                "marshal.load() — unsafe deserialization",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Unsafe deserialization: {label}",
                    description=(
                        f"'{label}' can execute arbitrary code when deserializing "
                        "attacker-controlled data. This is one of the most critical "
                        "vulnerability classes."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Replace pickle with JSON or msgpack. "
                        "Use yaml.safe_load() instead of yaml.load(). "
                        "Never deserialize data from untrusted sources."
                    ),
                    impact="Full RCE — attacker crafts a payload that executes code upon deserialization.",
                )

    def _detect_template_injection(self):
        patterns = [
            (
                r"Template\s*\(\s*(?:request|user|input|f['\"])",
                "Jinja2 Template from user input",
                Severity.CRITICAL,
            ),
            (
                r"render_template_string\s*\(\s*(?:request|user|input)",
                "render_template_string with user data",
                Severity.CRITICAL,
            ),
            (
                r"\.format\s*\(\s*\*\*request\.",
                ".format(**request.XXX) — template injection",
                Severity.HIGH,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Server-side template injection: {label}",
                    description=(
                        f"'{label}' renders a template from user-controlled input. "
                        "Template injection allows attackers to execute code on the server."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Never pass user input directly to template engines. Use static template strings with safe variable substitution.",
                    impact="Full server compromise via template expressions like {{7*7}} → exec().",
                )

    def _detect_path_traversal(self):
        patterns = [
            (
                r"open\s*\(\s*(?:request|user|input|f['\"].*\{)",
                "open() with user input (path traversal)",
                Severity.HIGH,
            ),
            (
                r"os\.path\.join\s*\(.*(?:request|user_input|form\[)",
                "os.path.join with user input",
                Severity.HIGH,
            ),
            (r"\.\./\.\./", "Path traversal sequence in string", Severity.HIGH),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Path traversal risk: {label}",
                    description=(
                        f"'{label}' constructs file paths using untrusted input. "
                        "Attackers can use '../' sequences to read arbitrary files."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Use pathlib.Path.resolve() and verify the result starts with your base directory. "
                        "Whitelist allowed filenames. Never join user input to file paths directly."
                    ),
                    impact="Attacker reads /etc/passwd, .env, private keys, or any file on the server.",
                )

    def _detect_unsafe_yaml(self):
        """yaml.load without explicit Loader is a code exec vector."""
        for lineno, line in self.grep_lines(r"yaml\.load\s*\("):
            if re.search(r"Loader\s*=\s*yaml\.(?:Safe|Base)Loader", line):
                continue
            self.add_finding(
                title="Unsafe YAML loading: yaml.load() without SafeLoader",
                description=(
                    "yaml.load() without an explicit Loader can deserialize Python objects, "
                    "which executes arbitrary code in attacker-controlled YAML files."
                ),
                severity=Severity.HIGH,
                evidence=f"Line {lineno}: {line}",
                fix="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) instead.",
                impact="RCE via crafted YAML payload containing !!python/object/apply tags.",
            )

    def _detect_xxe(self):
        """Detect XML External Entity (XXE) vulnerabilities."""
        patterns = [
            (
                r"xml\.etree\.ElementTree\.parse\s*\(",
                "ElementTree.parse — no XXE protection by default",
                Severity.HIGH,
            ),
            (
                r"xml\.etree\.ElementTree\.fromstring\s*\(",
                "ElementTree.fromstring — no XXE protection by default",
                Severity.HIGH,
            ),
            (
                r"lxml\.etree\.parse\s*\(",
                "lxml.etree.parse — may resolve external entities",
                Severity.CRITICAL,
            ),
            (
                r"lxml\.etree\.fromstring\s*\(",
                "lxml.etree.fromstring — may resolve external entities",
                Severity.CRITICAL,
            ),
            (
                r"xml\.sax\.parse\s*\(",
                "SAX parser — may resolve external entities",
                Severity.HIGH,
            ),
            (
                r"minidom\.parse\s*\(",
                "minidom.parse — may resolve external entities",
                Severity.HIGH,
            ),
            (
                r"expat\s*.*parse\s*\(",
                "expat parser — check for entity resolution",
                Severity.MEDIUM,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"XXE risk: {label}",
                    description=(
                        f"'{label}' parses XML that may contain external entity references. "
                        "Attackers can use XXE to read local files, perform SSRF, or cause DoS."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Use defusedxml instead of standard XML libraries. "
                        "For ElementTree: set parser.resolve_entities = False. "
                        "For lxml: use parser = etree.XMLParser(resolve_entities=False)."
                    ),
                    impact="File disclosure (/etc/passwd), SSRF, or denial of service via entity expansion.",
                )

    def _detect_js_eval(self):
        """Detect JS-specific dangerous patterns when scanning .js/.ts files."""
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
                r"\beval\s*\(",
                "eval() — JS arbitrary code execution",
                Severity.CRITICAL,
            ),
            (
                r"\bnew\s+Function\s*\(",
                "new Function() — JS code generation",
                Severity.CRITICAL,
            ),
            (
                r"child_process\.(?:exec|execSync)\s*\(",
                "child_process.exec — Node.js command injection",
                Severity.CRITICAL,
            ),
            (
                r"vm\.runIn(?:New)?Context\s*\(",
                "vm.runInContext — sandboxed code execution",
                Severity.HIGH,
            ),
            (
                r"setTimeout\s*\(\s*['\"]",
                "setTimeout with string arg (implicit eval)",
                Severity.HIGH,
            ),
            (
                r"setInterval\s*\(\s*['\"]",
                "setInterval with string arg (implicit eval)",
                Severity.HIGH,
            ),
            (
                r"dangerouslySetInnerHTML",
                "React dangerouslySetInnerHTML — XSS",
                Severity.CRITICAL,
            ),
            (
                r"\.innerHTML\s*=",
                "innerHTML assignment — DOM XSS",
                Severity.CRITICAL,
            ),
        ]
        for pattern, label, severity in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(r"""eval\s*\(\s*['"][^'"]+['"]\s*\)""", line):
                    continue
                self.add_finding(
                    title=f"JS dangerous code: {label}",
                    description=(
                        f"'{label}' can execute arbitrary code or inject HTML. "
                        "If any argument includes user-controlled data, this is exploitable."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove eval/Function. Use JSON.parse for data. Sanitize HTML with DOMPurify.",
                    impact="Code execution or XSS depending on context.",
                )

    def _detect_string_evasion(self):
        """Detect dynamically constructed dangerous function names — evasion technique."""
        patterns = [
            (
                r"""globals\(\)\s*\[\s*['"](?:eval|exec|system|popen)['"]""",
                "Dynamic function lookup via globals()",
            ),
            (
                r"""locals\(\)\s*\[\s*['"](?:eval|exec|system|popen)['"]""",
                "Dynamic function lookup via locals()",
            ),
            (
                r"getattr\s*\(\s*os\s*,\s*['\"](?:system|popen|exec)['\"]",
                "getattr() to call os.system/popen dynamically",
            ),
            (
                r"getattr\s*\(\s*\w+\s*,\s*['\"][^'\"]+['\"]\s*\+\s*['\"]",
                "getattr with concatenated attribute name",
            ),
            (
                r"""__import__\s*\(\s*['"](?:os|subprocess|commands)['"]""",
                "Dynamic import of dangerous module via __import__()",
            ),
            (
                r"importlib\.import_module\s*\(\s*['\"](?:os|subprocess)['\"]",
                "Dynamic import of os/subprocess via importlib",
            ),
            (
                r"""(?:eval|exec)\s*\(\s*\w+\s*\+\s*['"]""",
                "eval/exec with concatenated string argument",
            ),
            (
                r"""(?:eval|exec)\s*\(\s*['"][^'"]+['"]\s*\+\s*\w+""",
                "eval/exec with string + variable concatenation",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Evasion technique detected: {label}",
                    description=(
                        f"'{label}' uses dynamic construction to call dangerous functions. "
                        "This is a deliberate evasion technique to bypass static analysis tools. "
                        "The attacker constructs function or module names at runtime to avoid regex detection."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="This is a deliberate evasion technique — treat it as malicious. Audit the full code path.",
                    impact="Attacker bypasses static analysis to execute arbitrary code.",
                )

    def _detect_trigger_backdoors(self):
        """Detect conditional/triggered backdoors that activate on specific conditions."""
        # Pattern: if os.environ.get(...): followed by dangerous call within 5 lines
        for lineno, context_block in self.grep_context(
            r"if\s+os\.environ\.get\s*\(|if\s+os\.getenv\s*\(", window=5
        ):
            # Check if the context block contains a dangerous call
            dangerous = [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"os\.system\s*\(",
                r"subprocess\.",
                r"requests\.(get|post)",
                r"urllib\.request\.urlopen",
                r"__import__\s*\(",
                r"importlib",
            ]
            for dp in dangerous:
                if re.search(dp, context_block):
                    self.add_finding(
                        title="Environment-triggered backdoor",
                        description=(
                            "A dangerous function call is inside a conditional block that checks "
                            "an environment variable. This is a classic trigger-based backdoor — "
                            "it only activates when a specific env var is set (e.g., PROD=true, DEBUG=1). "
                            "The backdoor stays dormant during testing and only activates in production."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=f"Line {lineno}: trigger condition with dangerous call in block",
                        fix="Audit this conditional block. Environment-triggered code execution is almost never legitimate.",
                        impact="Backdoor activates silently in production while staying dormant in dev/test.",
                    )
                    break

        # Pattern: if datetime.now() > ... followed by dangerous call (time bomb)
        for lineno, context_block in self.grep_context(
            r"if\s+(?:datetime|time)\.(?:now|time)\s*\(?\s*\)?\s*[><]", window=5
        ):
            dangerous = [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"os\.system\s*\(",
                r"subprocess\.",
                r"requests\.(get|post)",
            ]
            for dp in dangerous:
                if re.search(dp, context_block):
                    self.add_finding(
                        title="Time-bombed backdoor",
                        description=(
                            "A dangerous function call is inside a time-based conditional. "
                            "This is a time bomb — the backdoor only activates after a specific date/time. "
                            "It stays dormant during initial security review and activates later."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=f"Line {lineno}: time-based trigger with dangerous call",
                        fix="Audit this time-based conditional. Time-bombed code execution is a backdoor technique.",
                        impact="Backdoor activates on a specific date, evading initial security review.",
                    )
                    break
