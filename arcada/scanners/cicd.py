"""
Scanner 14: CI/CD Pipeline Security Analysis
Detects GitHub Actions, GitLab CI, and other CI/CD pipeline misconfigurations
that enable supply-chain attacks, secret leakage, and code injection.
"""

from __future__ import annotations
import re
import yaml
from arcada.scanners.base import BaseScanner
from arcada.models import ScannerResult, Severity

CI_FILE_PATTERNS = {
    ".github/workflows",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    ".circleci/config.yml",
    "bitbucket-pipelines.yml",
    ".buildkite/",
    "azure-pipelines.yml",
    "Dockerfile",
    "docker-compose",
}


class CICDScanner(BaseScanner):
    name = "cicd"

    async def scan(self) -> list[ScannerResult]:
        if not self._is_ci_file():
            return self.findings

        self._detect_github_actions_risks()
        self._detect_gitlab_ci_risks()
        self._detect_dockerfile_risks()
        self._detect_secret_exposure_in_ci()
        self._detect_unpinned_actions()
        return self.findings

    def _is_ci_file(self) -> bool:
        if not self.path:
            return False
        path_lower = self.path.lower()
        return any(p in path_lower for p in CI_FILE_PATTERNS)

    def _detect_github_actions_risks(self):
        """Detect GitHub Actions workflow misconfigurations."""
        if ".github/workflows" not in (self.path or "").lower():
            return

        # 1. pull_request_target with checkout — fork PR can inject code
        has_pr_target = bool(self.grep_lines(r"pull_request_target"))
        has_checkout = bool(self.grep_lines(r"uses:\s*actions/checkout"))
        if has_pr_target and has_checkout:
            self.add_finding(
                title="GitHub Actions: pull_request_target with checkout (code injection from forks)",
                description=(
                    "This workflow uses 'pull_request_target' AND 'actions/checkout'. "
                    "This is a critical vulnerability: fork PRs can execute code in the context "
                    "of the base repository, with access to all secrets. Attackers can steal "
                    "GITHUB_TOKEN, npm tokens, PyPI tokens, etc."
                ),
                severity=Severity.CRITICAL,
                evidence="pull_request_target trigger with actions/checkout",
                fix=(
                    "Never use pull_request_target with checkout of PR code. "
                    "Use pull_request instead, or explicitly check out the base branch only."
                ),
                impact="Any fork PR can steal all repository secrets.",
            )

        # 2. secrets.* used in run: blocks
        for lineno, line in self.grep_lines(r"\$\{\{\s*secrets\."):
            # Check if this is inside a `run:` block (heuristic: next few lines are shell)
            self.add_finding(
                title="GitHub Actions: secret used in shell command",
                description=(
                    "A secret is referenced in a shell command (run: block). "
                    "If the command output or error messages are visible, the secret may leak. "
                    "Also, if the step uses PR-controlled input, it's vulnerable to injection."
                ),
                severity=Severity.HIGH,
                evidence=f"Line {lineno}: {line.strip()[:80]}",
                fix="Use secrets in env: blocks, not directly in run:. Never echo secrets.",
                impact="Secrets may leak in CI logs or through command injection.",
            )

        # 3. ${{ github.event.* }} in run: blocks (script injection)
        for lineno, line in self.grep_lines(r"\$\{\{\s*github\.event\."):
            if re.search(r"run:", line) or "run:" in line:
                self.add_finding(
                    title="GitHub Actions: script injection via github.event",
                    description=(
                        "GitHub event data is interpolated into a shell command. "
                        "An attacker can craft a PR title, branch name, or commit message "
                        "that contains shell commands, which will execute in the CI environment."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: {line.strip()[:80]}",
                    fix=(
                        "Never interpolate github.event data into run: blocks. "
                        "Use environment variables instead: env: TITLE: ${{ github.event.pull_request.title }}"
                    ),
                    impact="Arbitrary code execution in CI via crafted PR metadata.",
                )

        # 4. GITHUB_TOKEN permissions too broad
        if self.grep_lines(r"permissions:\s*$") or self.grep_lines(
            r"permissions:\s*write"
        ):
            for lineno, line in self.grep_lines(
                r"contents:\s*write|packages:\s*write|actions:\s*write"
            ):
                self.add_finding(
                    title="GitHub Actions: broad GITHUB_TOKEN permissions",
                    description=(
                        f"Line {lineno} grants write access to a sensitive resource. "
                        "If this workflow is compromised (via injection or unpinned action), "
                        "the attacker gets write access to repository contents/packages."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line.strip()}",
                    fix="Use least-privilege permissions. Only grant write where explicitly needed.",
                    impact="Compromised workflow gets full write access to the repository.",
                )

        # 5. environment: production without protection rules
        for lineno, line in self.grep_lines(r"environment:\s*production"):
            # Simple heuristic: if there's no 'required_reviewers' or 'deployment_branch_policy' nearby
            context = self.content[
                max(0, self.content.find(line) - 200) : self.content.find(line) + 500
            ]
            if (
                "required_reviewers" not in context
                and "deployment_branch_policy" not in context
            ):
                self.add_finding(
                    title="GitHub Actions: unprotected production environment",
                    description=(
                        "The 'production' environment is used but no protection rules "
                        "(required reviewers, deployment branch policy) are visible. "
                        "Any workflow run can deploy to production without approval."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line.strip()}",
                    fix="Configure environment protection rules in GitHub Settings > Environments.",
                    impact="Unauthorized deployments to production without human review.",
                )

    def _detect_gitlab_ci_risks(self):
        """Detect GitLab CI misconfigurations."""
        if not self.path or "gitlab-ci" not in self.path.lower():
            return

        # 1. $CI_ variables in script blocks (potential injection)
        for lineno, line in self.grep_lines(r"\$CI_(?:COMMIT|BRANCH|MERGE|PIPELINE)"):
            if re.search(r"(?i)(script|before_script|after_script)", line):
                self.add_finding(
                    title="GitLab CI: CI variable in script (potential injection)",
                    description=(
                        "A GitLab CI predefined variable is used in a script block. "
                        "If the variable contains user-controlled data (commit message, branch name), "
                        "it can be used for command injection."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line.strip()[:80]}",
                    fix="Never use CI variables directly in script blocks. Quote them or use environment variables.",
                    impact="Command injection via crafted commit messages or branch names.",
                )

        # 2. Unpinned Docker images
        for lineno, line in self.grep_lines(r"image:\s*[^@:\s]+$"):
            if ":latest" in line or (":" not in line and "@" not in line):
                self.add_finding(
                    title="GitLab CI: unpinned Docker image",
                    description=(
                        "A Docker image is used without a specific tag or digest. "
                        "This means the image can change at any time, including to a compromised version."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line.strip()}",
                    fix="Pin to a specific version tag or SHA256 digest.",
                    impact="Compromised container image used in CI pipeline.",
                )

    def _detect_dockerfile_risks(self):
        """Detect Dockerfile misconfigurations."""
        if not self.path or "dockerfile" not in self.path.lower():
            return

        # 1. RUN curl/wget without verification
        for lineno, line in self.grep_lines(r"RUN.*curl\s|RUN.*wget\s"):
            if (
                "sha256" not in line.lower()
                and "checksum" not in line.lower()
                and "gpg" not in line.lower()
            ):
                self.add_finding(
                    title="Dockerfile: download without integrity verification",
                    description=(
                        "A RUN command downloads a file via curl/wget without verifying its integrity "
                        "(no SHA256 checksum, no GPG signature). If the URL is compromised, "
                        "a malicious file is installed."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line.strip()[:80]}",
                    fix="Add SHA256 checksum verification or GPG signature check to all downloads.",
                    impact="Supply-chain attack via compromised download URL.",
                )

        # 2. COPY . . or ADD . . — copies everything including secrets
        for lineno, line in self.grep_lines(r"COPY\s+\.\s+\.|ADD\s+\.\s+\."):
            self.add_finding(
                title="Dockerfile: COPY . . may include secrets",
                description=(
                    "The Dockerfile copies the entire build context (COPY . .). "
                    "This may include .env files, SSH keys, API tokens, or other secrets "
                    "that end up in the container image."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Line {lineno}: {line.strip()}",
                fix="Use .dockerignore to exclude sensitive files. Copy only what's needed.",
                impact="Secrets baked into container image layers.",
            )

        # 3. Using latest tag
        for lineno, line in self.grep_lines(r"FROM\s+\w+:\s*latest"):
            self.add_finding(
                title="Dockerfile: using :latest tag",
                description=(
                    "The Dockerfile uses the :latest tag for a base image. "
                    "This means the base image can change at any time."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Line {lineno}: {line.strip()}",
                fix="Pin to a specific version tag.",
                impact="Compromised base image used in build.",
            )

    def _detect_secret_exposure_in_ci(self):
        """Detect secrets that may be exposed in CI configuration."""
        patterns = [
            (
                r"(?i)password\s*[=:]\s*['\"][^'\"]+['\"]",
                "Hardcoded password in CI config",
            ),
            (
                r"(?i)token\s*[=:]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
                "Hardcoded token in CI config",
            ),
            (
                r"(?i)api_?key\s*[=:]\s*['\"][A-Za-z0-9]{10,}['\"]",
                "Hardcoded API key in CI config",
            ),
        ]
        for pattern, label in patterns:
            for lineno, line in self.grep_lines(pattern):
                if re.search(r"(?i)(example|placeholder|your_|test|dummy|\$\{)", line):
                    continue
                self.add_finding(
                    title=f"CI/CD secret exposure: {label}",
                    description=(
                        f"'{label}' was found in CI configuration. "
                        "Secrets should be stored as CI/CD variables or secrets, not hardcoded."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Line {lineno}: [REDACTED]",
                    fix="Move secrets to CI/CD secret storage. Remove from configuration files.",
                    impact="Secrets visible in version control and CI logs.",
                )

    def _detect_unpinned_actions(self):
        """Detect GitHub Actions that are not pinned to a SHA."""
        if ".github/workflows" not in (self.path or "").lower():
            return

        for lineno, line in self.grep_lines(
            r"uses:\s*[^\s@]+@(?!v\d|sha256:|[a-f0-9]{40})"
        ):
            # Check if pinned to a version tag (v1, v2, etc.) — still risky but not critical
            if re.search(r"uses:\s*[^\s@]+@v\d", line):
                # Version tag — medium risk
                self.add_finding(
                    title="GitHub Action pinned to version tag (not commit SHA)",
                    description=(
                        "A GitHub Action is pinned to a version tag (e.g., v3) instead of a commit SHA. "
                        "Version tags can be moved by the maintainer, allowing silent updates."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"Line {lineno}: {line.strip()[:80]}",
                    fix="Pin to a specific commit SHA for maximum security.",
                    impact="Action can be silently updated to a compromised version.",
                )
            elif not re.search(r"uses:\s*\./", line):  # Local actions are fine
                self.add_finding(
                    title="GitHub Action not pinned to any version",
                    description=(
                        "A GitHub Action is used without any version or SHA pinning. "
                        "This always uses the latest version, which could be compromised."
                    ),
                    severity=Severity.HIGH,
                    evidence=f"Line {lineno}: {line.strip()[:80]}",
                    fix="Pin to a specific commit SHA: uses: owner/action@a1b2c3d4...",
                    impact="Attacker can push a compromised version that gets used automatically.",
                )
