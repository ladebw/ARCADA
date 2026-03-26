"""
Scanner 7: Agent / Workflow Risks
Detects excessive permissions, unrestricted tool use, and uncontrolled agent loops.
"""

from __future__ import annotations
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class AgentRisksScanner(BaseScanner):
    name = "agent_risks"

    async def scan(self) -> list[ScannerResult]:
        self._detect_excessive_tools()
        self._detect_unguarded_tool_calls()
        self._detect_agent_loops()
        self._detect_mcp_risks()
        self._detect_missing_human_in_loop()
        return self.findings

    def _detect_excessive_tools(self):
        patterns = [
            (
                r"tools\s*=\s*\[.*\b(?:ShellTool|BashProcess|terminal|shell_exec)\b",
                "Shell tool in agent",
            ),
            (r"(?i)allow_dangerous_tools\s*=\s*True", "allow_dangerous_tools=True"),
            (r"(?i)ShellTool\s*\(\s*\)|BashTool\s*\(\s*\)", "Unrestricted shell tool"),
            (
                r"(?i)FileManagementToolkit|filesystem.*agent",
                "Filesystem toolkit in agent",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Agent with excessive tool permissions: {label}",
                    description=(
                        f"'{label}' grants the agent unrestricted access to the shell or filesystem. "
                        "A prompt injection attack can hijack the agent to run arbitrary commands."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Remove dangerous tools or replace with sandboxed alternatives. "
                        "Apply a tool whitelist. "
                        "Run agents in isolated containers with minimal permissions."
                    ),
                    impact="Prompt injection → agent runs shell commands → full server compromise.",
                )

    def _detect_unguarded_tool_calls(self):
        patterns = [
            (
                r"(?i)confirm\s*=\s*False|human_approval\s*=\s*False",
                "Human approval disabled",
            ),
            (r"(?i)autonomous\s*=\s*True|fully_autonomous", "Fully autonomous mode"),
            (
                r"(?i)AgentExecutor.*handle_parsing_errors\s*=\s*True.*max_iterations\s*=\s*None",
                "Unlimited agent iterations",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Unguarded agent tool execution: {label}",
                    description=(
                        f"'{label}' allows the agent to call tools without human confirmation. "
                        "This is dangerous for irreversible actions (delete, send, deploy)."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Require human-in-the-loop confirmation for irreversible actions. "
                        "Implement a tool call approval workflow."
                    ),
                    impact="Agent executes destructive or irreversible actions without oversight.",
                )

    def _detect_agent_loops(self):
        patterns = [
            (
                r"max_iterations\s*=\s*(?:None|99999|10000|1000)\b",
                "Unlimited agent iterations",
            ),
            (
                r"max_execution_time\s*=\s*(?:None|99999|86400)",
                "Unlimited agent execution time",
            ),
            (r"while.*agent.*run|while.*chain.*invoke", "Unbounded agent loop"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Agent infinite loop risk: {label}",
                    description=(
                        f"'{label}' allows agents to run indefinitely, consuming API tokens "
                        "and resources without bound."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Set max_iterations and max_execution_time. Implement circuit breakers.",
                    impact="Runaway agent consumes unlimited API credits and server resources.",
                )

    def _detect_mcp_risks(self):
        patterns = [
            (
                r"(?i)mcp.*server.*stdio|StdioServerParameters",
                "MCP over stdio (injection via stdin)",
            ),
            (r"(?i)mcp\.tool\s*\(\s*\)", "MCP tool with no description/schema"),
            (r"(?i)allow_all_tools\s*=\s*True", "MCP allow all tools"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"MCP (Model Context Protocol) risk: {label}",
                    description=(
                        f"'{label}' — MCP servers can expand the attack surface significantly. "
                        "Malicious MCP servers can steal tool call arguments or inject fake results."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix=(
                        "Audit all connected MCP servers. "
                        "Only use MCP servers you control. "
                        "Validate tool schemas. "
                        "Run MCP servers in sandboxed environments."
                    ),
                    impact="Malicious MCP server intercepts tool calls or injects false data into agent context.",
                )

    def _detect_missing_human_in_loop(self):
        patterns = [
            (
                r"(?i)\.(?:run|invoke|execute)\s*\(.*(?:delete|drop|send|deploy|publish|rm\b|destroy)",
                "Agent action: destructive operation without guard",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Destructive action without human approval: {label}",
                    description=(
                        f"'{label}' appears to perform a destructive/irreversible operation "
                        "without explicit human confirmation."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Gate all irreversible actions behind explicit human confirmation steps.",
                    impact="Agent deletes data, sends emails, or deploys code without oversight.",
                )
