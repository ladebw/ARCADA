"""
Scanner 8: Runtime & Infrastructure Risks
"""

from __future__ import annotations
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity


class RuntimeScanner(BaseScanner):
    name = "runtime"

    async def scan(self) -> list[ScannerResult]:
        self._detect_root_execution()
        self._detect_privileged_container()
        self._detect_writable_filesystem()
        self._detect_exposed_ports()
        self._detect_missing_resource_limits()
        return self.findings

    def _detect_root_execution(self):
        patterns = [
            (r"USER\s+root\b", "Dockerfile: USER root"),
            (r"(?i)run.*--user\s+root", "running as root"),
            (r"os\.getuid\s*\(\s*\)\s*==\s*0", "checking for root uid == 0"),
            (
                r"sudo\s+python|sudo\s+uvicorn|sudo\s+gunicorn",
                "running app server with sudo",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Root execution detected: {label}",
                    description=(
                        f"'{label}' — running processes as root inside containers "
                        "gives any exploit full control over the host if container escape occurs."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Create a non-root user in Dockerfile (USER appuser). Never run app servers as root.",
                    impact="Container escape → root on the host machine.",
                )

    def _detect_privileged_container(self):
        patterns = [
            (r"privileged:\s*true", "Docker Compose: privileged: true"),
            (r"--privileged\b", "docker run --privileged"),
            (
                r"securityContext:.*privileged:\s*true",
                "Kubernetes: privileged container",
            ),
            (
                r"hostPID:\s*true|hostNetwork:\s*true",
                "Kubernetes: host PID/network sharing",
            ),
            (r"SYS_ADMIN|NET_ADMIN|ALL\s*capabilities", "Dangerous Linux capabilities"),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Privileged container: {label}",
                    description=(
                        f"'{label}' gives the container near-root access to the host. "
                        "This completely defeats container isolation."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line}",
                    fix="Remove privileged mode. Drop all capabilities and add only what's needed.",
                    impact="Container escape trivially leads to full host compromise.",
                )

    def _detect_writable_filesystem(self):
        patterns = [
            (
                r"readOnlyRootFilesystem:\s*false",
                "Kubernetes: writable root filesystem",
            ),
            (r"tmpfs.*exec|noexec\s*off", "tmpfs with exec (noexec disabled)"),
            (
                r"volumes:.*hostPath.*path:\s*/(?:etc|proc|sys|var/run/docker\.sock)",
                "Dangerous host path volume mount",
            ),
            (
                r"/var/run/docker\.sock",
                "Docker socket mounted (full Docker API access)",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                severity = Severity.CRITICAL if "docker.sock" in line else Severity.HIGH
                self.add_finding(
                    title=f"Dangerous filesystem access: {label}",
                    description=(
                        f"'{label}' — mounting the Docker socket or sensitive host paths "
                        "inside a container gives it full control over the host Docker daemon."
                    ),
                    severity=severity,
                    evidence=f"Line {lineno}: {line}",
                    fix="Never mount /var/run/docker.sock. Use read-only mounts where possible.",
                    impact="Container with Docker socket access = full host root via docker run --privileged.",
                )

    def _detect_exposed_ports(self):
        patterns = [
            (
                r"EXPOSE\s+(?:22|23|3306|5432|6379|27017|9200|8080|8443)\b",
                "Dockerfile: sensitive port exposed",
            ),
            (r"host:\s*0\.0\.0\.0|bind.*0\.0\.0\.0", "Binding to all interfaces"),
            (
                r"ports:.*['\"]?(?:22|3306|5432|6379|27017|9200):['\"]?",
                "Sensitive DB/SSH port exposed in compose",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                self.add_finding(
                    title=f"Sensitive port exposed: {label}",
                    description=(
                        f"'{label}' exposes a sensitive service port to the network. "
                        "Database and SSH ports should never be publicly accessible."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line}",
                    fix="Bind to 127.0.0.1 only. Use private networks. Put databases behind the app layer.",
                    impact="Direct database/SSH access from the internet enables credential brute-force.",
                )

    def _detect_missing_resource_limits(self):
        has_limits = bool(
            self.grep_lines(r"(?i)memory:\s*['\"]?\d|cpu:\s*['\"]?\d|resources:")
        )
        if not has_limits and (
            "kind: Deployment" in self.content or "services:" in self.content
        ):
            self.add_finding(
                title="Missing container resource limits",
                description=(
                    "No CPU or memory limits found for containers. "
                    "A single misbehaving container can starve all others."
                ),
                severity=Severity.MEDIUM,
                evidence="No 'resources.limits' block found in deployment config.",
                fix="Add resources.limits.cpu and resources.limits.memory to all containers.",
                impact="Resource exhaustion / denial of service across the whole cluster.",
            )
