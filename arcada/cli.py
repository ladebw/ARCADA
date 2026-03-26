"""
ARCADA CLI
Usage: arcada audit <target> [options]
"""

from __future__ import annotations
import asyncio
import sys
import os
from pathlib import Path

if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich.rule import Rule
from rich import box

from arcada.models import AuditRequest, AuditReport, Severity
from arcada.orchestrator import Orchestrator
from arcada.report import format_report

console = Console(force_terminal=True)

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "orange1",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "dim",
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🟢",
    Severity.INFO: "ℹ️ ",
}

MATURITY_COLORS = {
    "Unsafe": "bold red",
    "Weak": "orange1",
    "Moderate": "yellow",
    "Strong": "green",
    "Hardened": "bold green",
}


def print_banner():
    console.print()
    console.print(
        Panel.fit(
            "[bold red]ARCADA[/bold red] [dim]—[/dim] [bold]AI Runtime & Trust Evaluator[/bold]\n"
            "[dim]Zero-trust security auditor for AI systems & supply chains[/dim]",
            border_style="red",
            padding=(0, 2),
        )
    )
    console.print()


def print_summary(report: AuditReport):
    s = report.summary
    maturity_color = MATURITY_COLORS.get(s.security_maturity, "white")
    score_color = (
        "red" if s.risk_score >= 70 else "yellow" if s.risk_score >= 40 else "green"
    )

    # Score panel
    console.print(Rule("[bold]Executive Summary[/bold]", style="dim"))
    console.print()

    summary_table = Table(box=box.ROUNDED, show_header=False, border_style="dim")
    summary_table.add_column("Metric", style="bold", width=25)
    summary_table.add_column("Value")

    summary_table.add_row("Target", f"[cyan]{report.target}[/cyan]")
    summary_table.add_row("Type", report.target_type)
    summary_table.add_row(
        "Risk Score",
        f"[{score_color}]{'█' * (s.risk_score // 10)}{'░' * (10 - s.risk_score // 10)} {s.risk_score}/100[/{score_color}]",
    )
    summary_table.add_row(
        "Security Maturity",
        f"[{maturity_color}]{s.security_maturity}[/{maturity_color}]",
    )
    summary_table.add_row("Total Findings", str(s.total_findings))
    summary_table.add_row("🔴 Critical", f"[bold red]{s.critical_count}[/bold red]")
    summary_table.add_row("🟠 High", f"[orange1]{s.high_count}[/orange1]")
    summary_table.add_row("🟡 Medium", f"[yellow]{s.medium_count}[/yellow]")
    summary_table.add_row("🟢 Low", f"[green]{s.low_count}[/green]")

    console.print(summary_table)
    console.print()


def print_top_risks(report: AuditReport):
    s = report.summary
    if s.top_risks:
        console.print(Rule("[bold red]Top 5 Critical Risks[/bold red]", style="red"))
        console.print()
        for i, risk in enumerate(s.top_risks[:5], 1):
            console.print(f"  [bold red]{i}.[/bold red] {risk}")
        console.print()

    if s.immediate_actions:
        console.print(
            Rule("[bold yellow]⚡ Immediate Actions[/bold yellow]", style="yellow")
        )
        console.print()
        for i, action in enumerate(s.immediate_actions[:5], 1):
            console.print(f"  [bold yellow]{i}.[/bold yellow] {action}")
        console.print()


def print_findings(report: AuditReport, verbose: bool = False):
    severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]

    for sev in severity_order:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue

        color = SEVERITY_COLORS[sev]
        icon = SEVERITY_ICONS[sev]
        console.print(
            Rule(
                f"[{color}]{icon} {sev.value.upper()} ({len(group)})[/{color}]",
                style=color,
            )
        )
        console.print()

        for finding in group:
            title_text = Text(f"  ▸ {finding.title}", style=f"bold {color}")
            console.print(title_text)
            console.print(
                f"    [dim]Scanner:[/dim] {finding.scanner}  [dim]Location:[/dim] {finding.location or 'N/A'}"
            )

            if verbose:
                console.print(f"\n    [bold]Description:[/bold] {finding.description}")
                console.print(f"    [bold]Impact:[/bold] {finding.impact}")
                if finding.evidence:
                    console.print(f"    [bold]Evidence:[/bold]")
                    for line in finding.evidence.splitlines():
                        console.print(f"    [dim]  {line}[/dim]")
                console.print(f"    [bold green]Fix:[/bold green] {finding.fix}")

            console.print()


@click.group()
@click.version_option(version="0.1.0", prog_name="arcada")
def main():
    """ARCADA — AI Runtime & Trust Evaluator\n\nZero-trust security auditor for AI systems, LLM infrastructure, and supply chains."""
    pass


@main.command()
@click.argument("target", required=True)
@click.option(
    "--type",
    "-t",
    "target_type",
    default="auto",
    type=click.Choice(["auto", "code", "dependencies", "docker", "config", "url"]),
    help="Type of target to audit (default: auto-detect)",
    show_default=True,
)
@click.option(
    "--format",
    "-f",
    "output_format",
    default="terminal",
    type=click.Choice(["terminal", "json", "markdown", "sarif"]),
    help="Output format",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Write report to file instead of stdout",
)
@click.option(
    "--scanners",
    "-s",
    default=None,
    help="Comma-separated list of scanners to run (default: all)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show full finding details in terminal output",
)
@click.option(
    "--no-banner",
    is_flag=True,
    default=False,
    help="Suppress the ARCADA banner",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with code 1 if findings at this severity or above are found (useful for CI)",
)
def audit(
    target: str,
    target_type: str,
    output_format: str,
    output_file: str | None,
    scanners: str | None,
    verbose: bool,
    no_banner: bool,
    fail_on: str | None,
):
    """Run a full security audit on TARGET.

    TARGET can be:

    \b
      - A file path (e.g. requirements.txt, app.py, Dockerfile)
      - A directory path (scans all files recursively)
      - A URL (fetches and audits the content)
      - Inline content (paste code directly)

    \b
    Examples:
      arcada audit requirements.txt
      arcada audit ./my-project/ --format markdown --output report.md
      arcada audit app.py --verbose
      arcada audit ./repo --scanners secrets,ai_risks,network
      arcada audit requirements.txt --fail-on high
    """
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] DEEPSEEK_API_KEY environment variable not set."
        )
        console.print(
            "  Set it with: [cyan]export DEEPSEEK_API_KEY=your-key-here[/cyan]"
        )
        sys.exit(1)

    if not no_banner and output_format == "terminal":
        print_banner()

    scanner_list = [s.strip() for s in scanners.split(",")] if scanners else []

    request = AuditRequest(
        target=target,
        target_type=target_type,
        scanners=scanner_list,
        output_format=output_format if output_format != "terminal" else "json",
    )

    # Run the audit
    if output_format == "terminal":
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Running scanners...", total=None)

            orchestrator = Orchestrator()
            report: AuditReport = asyncio.run(orchestrator.audit(request))
            progress.update(task, description="[cyan]AI analysis complete")

        print_summary(report)
        print_top_risks(report)
        print_findings(report, verbose=verbose)

        if output_file:
            fmt = "markdown" if output_file.endswith(".md") else "json"
            Path(output_file).write_text(format_report(report, fmt))
            console.print(f"[dim]Report saved to:[/dim] [cyan]{output_file}[/cyan]")

    else:
        orchestrator = Orchestrator()
        report = asyncio.run(orchestrator.audit(request))
        output = format_report(report, output_format)

        if output_file:
            Path(output_file).write_text(output)
            console.print(f"Report saved to: [cyan]{output_file}[/cyan]")
        else:
            click.echo(output)

    # CI exit code support
    if fail_on:
        sev_order = ["low", "medium", "high", "critical"]
        threshold = sev_order.index(fail_on)
        s = report.summary
        counts = {
            0: s.low_count,
            1: s.medium_count,
            2: s.high_count,
            3: s.critical_count,
        }
        should_fail = any(counts[i] > 0 for i in range(threshold, 4))
        if should_fail:
            console.print(
                f"\n[bold red]CI check failed:[/bold red] findings at or above '{fail_on}' severity were found."
            )
            sys.exit(1)


@main.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="Host to bind to")
@click.option("--port", "-p", default=8000, show_default=True, help="Port to listen on")
@click.option(
    "--reload", is_flag=True, default=False, help="Enable auto-reload (dev only)"
)
def serve(host: str, port: int, reload: bool):
    """Start the ARCADA REST API server."""
    import uvicorn

    console.print(
        Panel.fit(
            f"[bold]ARCADA API Server[/bold]\n"
            f"[dim]Listening on[/dim] [cyan]http://{host}:{port}[/cyan]\n"
            f"[dim]Docs:[/dim] [cyan]http://{host}:{port}/docs[/cyan]",
            border_style="green",
        )
    )
    uvicorn.run("arcada.api:app", host=host, port=port, reload=reload)


@main.command("deep-audit")
@click.argument("target", required=False, default="")
@click.option(
    "--installed-only",
    is_flag=True,
    default=False,
    help="Scan all installed packages (no requirements file needed)",
)
@click.option(
    "--package",
    "-p",
    "packages",
    multiple=True,
    help="Specific installed packages to scan (repeat for multiple)",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    default="terminal",
    type=click.Choice(["terminal", "json", "markdown", "sarif"]),
    help="Output format",
    show_default=True,
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Write report to file instead of stdout",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Show full finding details in terminal output",
)
@click.option(
    "--fail-on",
    "fail_on",
    default=None,
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Exit with code 1 if findings at or above this severity",
)
def deep_audit(
    target: str,
    installed_only: bool,
    packages: tuple,
    output_format: str,
    output_file: str | None,
    verbose: bool,
    fail_on: str | None,
):
    """Deep audit: scan your code AND all installed dependency source code.

    \b
    This runs all standard scanners against your project code,
    then enumerates installed packages and scans their source files
    through every scanner, queries PyPI/npm for metadata anomalies,
    and performs AST-based behavioral analysis on each package.

    \b
    Examples:
      arcada deep-audit requirements.txt
      arcada deep-audit ./my-project/
      arcada deep-audit --installed-only
      arcada deep-audit --package requests --package flask
      arcada deep-audit --package express --format json -o deep-report.json
    """
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] DEEPSEEK_API_KEY environment variable not set."
        )
        console.print(
            "  Set it with: [cyan]export DEEPSEEK_API_KEY=your-key-here[/cyan]"
        )
        sys.exit(1)

    if not target and not installed_only and not packages:
        console.print(
            "[bold red]Error:[/bold red] Provide a target, --installed-only, or --package."
        )
        sys.exit(1)

    print_banner()

    target_type = "auto"
    if installed_only or (not target and packages):
        target_type = "dependencies"
        if not target:
            target = "<installed-only>"

    pkg_list = list(packages) if packages else []

    request = AuditRequest(
        target=target,
        target_type=target_type,
        output_format=output_format if output_format != "terminal" else "json",
        deep=True,
        packages=pkg_list,
    )

    pkg_count_msg = f" ({len(pkg_list)} packages)" if pkg_list else " (all installed)"
    console.print(
        f"[bold red]Deep Audit Mode[/bold red] — "
        f"scanning project code + installed dependency source{pkg_count_msg}"
    )
    console.print()

    if output_format == "terminal":
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[cyan]Phase 1: Scanning project code...", total=None
            )

            orchestrator = Orchestrator()
            report: AuditReport = asyncio.run(orchestrator.deep_audit(request))
            progress.update(task, description="[cyan]Deep audit complete")

        print_summary(report)
        print_top_risks(report)
        print_findings(report, verbose=verbose)

        if output_file:
            fmt = "markdown" if output_file.endswith(".md") else "json"
            Path(output_file).write_text(format_report(report, fmt))
            console.print(f"[dim]Report saved to:[/dim] [cyan]{output_file}[/cyan]")

    else:
        orchestrator = Orchestrator()
        report = asyncio.run(orchestrator.deep_audit(request))
        output = format_report(report, output_format)

        if output_file:
            Path(output_file).write_text(output)
            console.print(f"Report saved to: [cyan]{output_file}[/cyan]")
        else:
            click.echo(output)

    if fail_on:
        sev_order = ["low", "medium", "high", "critical"]
        threshold = sev_order.index(fail_on)
        s = report.summary
        counts = {
            0: s.low_count,
            1: s.medium_count,
            2: s.high_count,
            3: s.critical_count,
        }
        should_fail = any(counts[i] > 0 for i in range(threshold, 4))
        if should_fail:
            console.print(
                f"\n[bold red]CI check failed:[/bold red] findings at or above '{fail_on}' severity were found."
            )
            sys.exit(1)


@main.command("list-scanners")
def list_scanners():
    """List all available scanner modules."""
    from arcada.scanners import ALL_SCANNERS, DEEP_SCANNERS

    table = Table(title="Available Scanners", box=box.ROUNDED, border_style="dim")
    table.add_column("Name", style="bold cyan")
    table.add_column("Type", style="dim")
    table.add_column("Description")

    descriptions = {
        "dependency": "CVE detection, unpinned deps, typosquatting, AI packages",
        "supply_chain": "Install hooks, dynamic imports, CI/CD secret leakage, obfuscation",
        "secrets": "API keys, tokens, private keys, unsafe logging patterns",
        "network": "Suspicious endpoints, telemetry, SSL bypass, exfiltration",
        "code_exec": "eval/exec, shell injection, unsafe deserialization, SSTI",
        "ai_risks": "Prompt injection, token abuse, LLM logging, RAG injection",
        "agent_risks": "Dangerous tools, MCP risks, infinite loops",
        "runtime": "Root execution, privileged containers, Docker socket",
        "abuse": "Rate limits, authentication, per-user quotas",
        "trust_model": "JWT vulnerabilities, CORS, SQL injection, debug mode",
        "dep_source": "Scans installed package source code through all scanners",
        "package_metadata": "PyPI/npm registry analysis, age, maintainers, install scripts",
        "dep_behavior": "AST analysis: module-level network/subprocess/threading on import",
    }

    for scanner_cls in ALL_SCANNERS:
        table.add_row(
            scanner_cls.name, "standard", descriptions.get(scanner_cls.name, "")
        )

    for scanner_cls in DEEP_SCANNERS:
        table.add_row(scanner_cls.name, "deep", descriptions.get(scanner_cls.name, ""))

    console.print(table)


if __name__ == "__main__":
    main()
