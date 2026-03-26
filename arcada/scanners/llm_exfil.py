"""
LLM Exfiltration Channel Scanner
Detects patterns where sensitive data could leak through LLM tool calls,
agent loops writing env vars to tools, and unsanitized fine-tuning data writes.
Targets LangChain, AutoGen, CrewAI, and similar frameworks.
"""

from __future__ import annotations
import re
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class LLMExfilScanner(BaseScanner):
    name = "llm_exfil"

    async def scan(self) -> list[ScannerResult]:
        self._detect_env_in_tool_calls()
        self._detect_secrets_in_tool_args()
        self._detect_unsanitized_file_read()
        self._detect_finetune_data_leak()
        self._detect_agent_env_exfil()
        self._detect_credentials_in_tool_call()
        self._detect_database_exfil()
        self._detect_langchain_exfil()
        self._detect_autogen_exfil()
        self._detect_crewai_exfil()
        return self.findings

    def _detect_env_in_tool_calls(self):
        """Detect os.environ or env vars passed to tool/function calls."""
        patterns = [
            (r"os\.environ\[[^\]]+\]", "os.environ[...] in function call"),
            (r"os\.getenv\([^\)]+\)", "os.getenv() in function call"),
            (r"environ\[[^\]]+\]", "environ[...] in function call"),
            (r"process\.env\.", "process.env in function call"),
        ]

        tool_call_patterns = [
            r"\.run\(",
            r"\.invoke\(",
            r"\.execute\(",
            r"\.call\(",
            r"tool\(",
            r"function\(",
            r"\.apply\(",
            r"agent\.run",
            r"\.send\(",
            r"\.complete\(",
            r"\.generate\(",
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                context_lines = self.content.splitlines()
                context = ""
                for i in range(max(0, lineno - 3), min(len(context_lines), lineno + 2)):
                    context += context_lines[i] + "\n"

                is_tool_call = any(re.search(tp, context) for tp in tool_call_patterns)
                if is_tool_call:
                    self.add_finding(
                        title=f"Environment variable in tool call: {label}",
                        description=(
                            f"Environment variable detected in tool/function call. "
                            "Sensitive env vars (API keys, secrets) can leak to LLM as arguments."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=line,
                        location=f"{self.path}:{lineno}",
                        fix="Pass sanitized/filtered values instead of direct env vars",
                        impact="API keys and secrets can leak through tool call arguments to LLM.",
                    )

    def _detect_secrets_in_tool_args(self):
        """Detect API keys or secrets passed as tool parameters."""
        patterns = [
            (r"api[_-]?key\s*=\s*.*secrets", "API key from secrets module"),
            (r"api[_-]?key\s*=\s*os\.environ", "API key from environ"),
            (r"api[_-]?key\s*=\s*['\"][A-Za-z0-9_-]{20,}", "Hardcoded API key"),
            (r"password\s*=\s*.*environ", "Password from environ"),
            (r"token\s*=\s*.*getenv", "Token from getenv"),
            (r"secret\s*=\s*.*environ", "Secret from environ"),
            (r"apikey\s*=\s*process\.env", "API key from process.env"),
            (r"Bearer\s+\$", "Bearer token exposed"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Secret in tool arguments: {label}",
                    description=(
                        f"Secret detected in tool/function parameters. "
                        "Credentials passed to LLM tools can be logged or exfiltrated."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=line,
                    location=f"{self.path}:{lineno}",
                    fix="Use reference-based auth, environment variables on server side",
                    impact="Credentials exposed to LLM can be logged or stolen.",
                )

    def _detect_unsanitized_file_read(self):
        """Detect file.read() passed to LLM without sanitization."""
        patterns = [
            (
                r"\.read\(\).*(?:prompt|llm|chat|complete|generate)",
                "file.read() to LLM",
            ),
            (r"(?:prompt|llm|chat).*\.read\(", "LLM reads file directly"),
            (r"\.read_text\(\).*(?:prompt|llm)", "read_text() to LLM"),
            (r"open\([^)]+\)\.read\(\).*(?:llm|prompt)", "open().read() to LLM"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if (
                    "sanitize" not in context.lower()
                    and "filter" not in context.lower()
                ):
                    self.add_finding(
                        title=f"Unsanitized file read to LLM: {label}",
                        description=(
                            "File contents passed to LLM without sanitization. "
                            "Sensitive file data (credentials, PII) can leak."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Sanitize file contents before passing to LLM",
                        impact="Sensitive file contents exposed to LLM.",
                    )

    def _detect_finetune_data_leak(self):
        """Detect unsanitized writes to fine-tuning datasets."""
        patterns = [
            (
                r"(?:train|training|finetune|fine[_-]tune).*\.write",
                "Write to training data",
            ),
            (r"\.write.*(?:train|training|finetune)", "Write to training data"),
            (r"dataset.*\.append\(", "Append to dataset"),
            (r"\.push.*(?:train|example)", "Push to training examples"),
            (r"to_json\(\).*(?:train|example)", "Export to training JSON"),
            (r"json\.dump.*(?:train|example)", "Dump to training JSON"),
            (r"(?:prompt|completion).*\.save", "Save prompt/completion"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if (
                    "sanitize" not in context.lower()
                    and "filter" not in context.lower()
                ):
                    self.add_finding(
                        title=f"Unsanitized fine-tuning data write: {label}",
                        description=(
                            "Writing to fine-tuning dataset without sanitization. "
                            "Sensitive data could be baked into model weights."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Sanitize PII/secrets before adding to training data",
                        impact="Secrets baked into model are unrevocable.",
                    )

    def _detect_agent_env_exfil(self):
        """Detect agent loops writing env vars to tool parameters."""
        patterns = [
            (r"(?:agent|agent_executor).*for.*in.*:.*env", "Agent loop with env"),
            (r"env.*=.*os\.environ.*for.*in", "Env in loop for agent"),
            (r"\.update\(.*environ", "Update with environ in loop"),
            (r"\{.*environ.*\}.*tool", "Dict with environ passed to tool"),
            (r"kwargs.*environ", "Kwargs with environ"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=5):
                self.add_finding(
                    title=f"Agent env exfiltration: {label}",
                    description=(
                        "Agent loop appears to pass environment variables to tools. "
                        "This can leak all env vars (including secrets) to LLM calls."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=context,
                    location=f"{self.path}:{lineno}",
                    fix="Explicitly pass only needed config, not all env vars",
                    impact="All environment variables exposed to LLM in agent loop.",
                )

    def _detect_credentials_in_tool_call(self):
        """Detect credentials passed in tool_call.arguments."""
        patterns = [
            (r"tool[_-]?call.*arguments.*=", "tool_call.arguments assignment"),
            (r"\.arguments\[.*key", "arguments dict with key"),
            (
                r"function[_-]?call.*\{.*:.*(?:key|token|secret)",
                "Function call with secret key",
            ),
            (r"\.call.*\{.*(?:api[_-]?key|token|secret)", "Call with secret in dict"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Credentials in tool_call.arguments: {label}",
                    description=(
                        "Credentials detected in tool call arguments structure. "
                        "These may be logged or accessible to the LLM."
                    ),
                    severity=Severity.HIGH,
                    evidence=line,
                    location=f"{self.path}:{lineno}",
                    fix="Use server-side config, not arguments",
                    impact="Credentials exposed in tool call structure.",
                )

    def _detect_database_exfil(self):
        """Detect sensitive data written to logs or vector stores."""
        patterns = [
            (r"\.log\(.*(?:token|key|secret|password)", "Log with credentials"),
            (r"logger\..*(?:token|key|secret)", "Logger with secrets"),
            (r"chroma.*\.add\(", "ChromaDB add"),
            (r"faiss.*\.add\(", "FAISS add"),
            (r"pinecone\..*upsert", "Pinecone upsert"),
            (r"(?:prompt|message).*\.save\(", "Save prompt to vector store"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                if "sanitize" not in line.lower():
                    self.add_finding(
                        title=f"Data exfiltration to storage: {label}",
                        description=(
                            f"Detected: {label}. "
                            "Sensitive data being written to logs or vector stores."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=line,
                        location=f"{self.path}:{lineno}",
                        fix="Sanitize sensitive fields before storage",
                        impact="Secrets persisted in logs/vector databases.",
                    )

    def _detect_langchain_exfil(self):
        """LangChain-specific exfiltration patterns."""
        patterns = [
            (r"Chain\.run\(.*\{.*:.*environ", "LangChain run with env"),
            (r"LLMChain\(.*\{", "LLMChain with dict"),
            (r"\.bind\(.*api[_-]?key", "bind() with API key"),
            (r"ConversationChain\(.*\{", "ConversationChain with config"),
            (r"load_qa_chain\(.*", "load_qa_chain with secrets"),
            (r"RetrievalQA.*\.run", "RetrievalQA run"),
            (r"ConversationalRetrievalChain", "ConversationalRetrievalChain"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if "environ" in context.lower() or "api" in context.lower():
                    self.add_finding(
                        title=f"LangChain exfiltration: {label}",
                        description=(
                            f"LangChain pattern: {label}. "
                            "May leak credentials or sensitive data to LLM."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use environment variables on server, not in chain config",
                        impact="API keys exposed in LangChain configuration.",
                    )

    def _detect_autogen_exfil(self):
        """AutoGen-specific exfiltration patterns."""
        patterns = [
            (r"AssistantAgent\(.*", "AutoGen AssistantAgent"),
            (r"UserProxyAgent\(.*", "AutoGen UserProxyAgent"),
            (r"\.initiate_chat\(.*\{", "AutoGen initiate_chat"),
            (r"generate_init_message.*environ", "init_message with environ"),
            (r"register_function.*api[_-]?key", "register_function with API key"),
            (r"ConversableAgent\(.*", "AutoGen ConversableAgent"),
            (r"\.send\(.*{", "AutoGen send with dict"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if (
                    "api" in context.lower()
                    or "secret" in context.lower()
                    or "key" in context.lower()
                ):
                    self.add_finding(
                        title=f"AutoGen exfiltration: {label}",
                        description=(
                            f"AutoGen pattern: {label}. "
                            "May expose credentials to agents."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use environment-based config for agents",
                        impact="Credentials exposed to AutoGen agents.",
                    )

    def _detect_crewai_exfil(self):
        """CrewAI-specific exfiltration patterns."""
        patterns = [
            (r"Crew\(.*agents", "CrewAI Crew"),
            (r"Agent\(.*api[_-]?key", "CrewAI Agent with API key"),
            (r"Task\(.*\.output", "Task output"),
            (r"\.kickoff\(.*\{", "CrewAI kickoff with dict"),
            (r"llm\s*=\s*.*environ", "LLM from environ"),
            (r"from.*crewai.*import", "CrewAI import"),
        ]

        for pattern, label in patterns:
            for lineno, line, context in self.grep_context(pattern, window=3):
                if (
                    "api" in context.lower()
                    or "key" in context.lower()
                    or "secret" in context.lower()
                ):
                    self.add_finding(
                        title=f"CrewAI exfiltration: {label}",
                        description=(
                            f"CrewAI pattern: {label}. "
                            "May expose credentials in crew configuration."
                        ),
                        severity=Severity.HIGH,
                        evidence=context,
                        location=f"{self.path}:{lineno}",
                        fix="Use environment variables for crew config",
                        impact="API keys exposed in CrewAI configuration.",
                    )

    def _detect_llm_logging_exfil(self):
        """Detect LLM inputs being logged."""
        patterns = [
            (r"log.*(?:prompt|message|chat).*", "Log LLM prompts"),
            (r"print\(.*(?:prompt|llm|message)", "Print LLM data"),
            (r"logging\.info.*(?:prompt|llm)", "Logging LLM prompts"),
            (r"callback.*prompt", "Callback with prompt"),
        ]

        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"LLM input logging: {label}",
                    description=(
                        f"LLM input being logged: {label}. "
                        "Prompts may contain sensitive data."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=line,
                    location=f"{self.path}:{lineno}",
                    fix="Disable logging of LLM prompts or sanitize first",
                    impact="LLM inputs with secrets logged.",
                )
