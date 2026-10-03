"""Rich terminal output renderer styled after Daytona and Claude Code CLIs."""

import sys

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED, SIMPLE, HORIZONTALS

from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.framework.base import Endpoint
from trace_engine.security.hypotheses import SecurityHypothesis
from trace_engine.apm.model import AttackPathModel
from trace_engine.doctor import DoctorReport

console = Console(force_terminal=True, legacy_windows=False)

# Daytona-inspired geometric ASCII emblem from Image 2
LOGO_ASCII = """\
        -#####=
       -######-
  +###= -######:
  #####* -#####%-.. .. .. .
  ##########: =#############-
  #####* =%#- =#############-
 :*%=  #####*       ....:*#:.....
 =#####%==+++-           +#####*.
 :*#####%=               =%####+.
 .*#####%=               =%####+.
 .*#####*.             .####-=%#####*.
 :::::=%+:::::     .   .####:   =%##%-
 #############   .*#%-.####:     +-
 %%%%%%%%%%%%%%%%*#####%=####:
 .*#####%= .####:
 .*#####%=  .####:
 +%##%=      ****:\
"""


def print_banner() -> None:
    """Renders the Daytona-inspired split banner with ASCII emblem and green highlights."""
    grid = Table.grid(padding=(0, 4))
    grid.add_column("logo", justify="left")
    grid.add_column("info", justify="left")

    logo_text = Text(LOGO_ASCII, style="bold white")

    info_text = Text()
    info_text.append("TRACE\n", style="bold green")
    info_text.append("Threat Reconnaissance & Attack-path Correlation Engine\n", style="bold white")
    info_text.append("v1.0.0-poc", style="dim")
    info_text.append("  |  ", style="green")
    info_text.append("local-first application security platform\n", style="dim white")
    info_text.append("-" * 52 + "\n\n", style="dim")

    info_text.append("Get started\n", style="bold white")
    
    commands = [
        ("trace init <repo>", "initialize .trace directory"),
        ("trace index <repo>", "ingest files & build AST symbol index"),
        ("trace endpoints <repo>", "discover HTTP routes & auth gates"),
        ("trace apm <repo>", "generate Attack-Path Model graph"),
        ("trace analyze <repo>", "evaluate static security hypotheses"),
        ("trace scan <repo> --target <url>", "end-to-end static + runtime validation"),
        ("trace findings", "view confirmed security vulnerabilities"),
        ("trace explain <ID>", "deep-dive with root cause analysis"),
        ("trace doctor", "inspect local environment & security tools"),
        ("trace lab start", "launch vulnerable vending-api lab target"),
    ]

    for cmd, desc in commands:
        info_text.append(" > ", style="bold green")
        info_text.append(f"{cmd:<34}", style="green")
        info_text.append(f"({desc})\n", style="dim")

    info_text.append("\nview all commands: ", style="dim")
    info_text.append("trace --help\n", style="bold green")

    grid.add_row(logo_text, info_text)

    console.print()
    console.print(grid)
    console.print()


def print_security_notes() -> None:
    """Renders Claude Code style security boundary notice."""
    panel_content = Text()
    panel_content.append("Security Notes:\n", style="bold white")
    panel_content.append(" 1. ", style="bold green")
    panel_content.append("Local-First Execution: ", style="bold white")
    panel_content.append("TRACE operates entirely offline without telemetry or external cloud APIs.\n", style="dim")
    
    panel_content.append(" 2. ", style="bold green")
    panel_content.append("Scope Guard Active: ", style="bold white")
    panel_content.append("Runtime requests are strictly bounded to localhost and approved private lab CIDRs.\n", style="dim")
    
    panel_content.append(" 3. ", style="bold green")
    panel_content.append("Evidence-First Findings: ", style="bold white")
    panel_content.append("Findings require correlated static AST attack-paths and runtime behavioral proof.\n", style="dim")

    console.print(
        Panel(
            panel_content,
            title="[bold green]* TRACE Security Boundary *[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(0, 2),
        )
    )
    console.print()


def print_endpoints_table(endpoints: List[Endpoint]) -> None:
    """Renders table of discovered endpoints."""
    table = Table(
        title="Discovered Application Endpoints",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("Method", style="bold white", no_wrap=True)
    table.add_column("Path", style="green")
    table.add_column("Auth", justify="center", no_wrap=True)
    table.add_column("Roles", style="dim", no_wrap=True)
    table.add_column("Database", justify="center", no_wrap=True)
    table.add_column("Outbound", justify="center", no_wrap=True)
    table.add_column("Source", style="dim", overflow="ellipsis", max_width=25)

    for ep in endpoints:
        auth_badge = "[bold green]YES[/bold green]" if ep.auth_required else "[dim red]NO[/dim red]"
        db_badge = "[green]YES[/green]" if ep.database_access else "[dim]NO[/dim]"
        ext_badge = "[bold yellow]YES[/bold yellow]" if ep.external_network else "[dim]NO[/dim]"
        roles_str = ", ".join(ep.roles) if ep.roles else "-"

        table.add_row(
            ep.method,
            ep.path,
            auth_badge,
            roles_str,
            db_badge,
            ext_badge,
            str(ep.source),
        )

    console.print(table)


def print_hypotheses_table(hypotheses: List[SecurityHypothesis]) -> None:
    """Renders table of derived security hypotheses."""
    table = Table(
        title="Derived Security Hypotheses (Attack Surface)",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("ID", style="bold green", no_wrap=True)
    table.add_column("Category", style="bold white", no_wrap=True)
    table.add_column("Endpoint", style="white")
    table.add_column("Test Pack", style="green", no_wrap=True)
    table.add_column("Confidence Prior", justify="right", no_wrap=True)

    for h in hypotheses:
        prior_str = f"{int(h.confidence_prior * 100)}%"
        table.add_row(
            h.id,
            h.category.value,
            h.endpoint_display,
            h.recommended_test_pack,
            prior_str,
        )

    console.print(table)


def print_findings_table(findings: List[Finding]) -> None:
    """Renders table of correlated findings."""
    if not findings:
        console.print("[green]No correlated vulnerabilities detected.[/green]\n")
        return

    table = Table(
        title=f"Correlated Vulnerability Findings ({len(findings)})",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("ID", style="bold green", no_wrap=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Confidence", justify="center", no_wrap=True)
    table.add_column("Category", style="bold white", no_wrap=True)
    table.add_column("Endpoint", style="white")
    table.add_column("Title", style="dim white")

    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }

    confidence_colors = {
        FindingConfidence.CONFIRMED: "bold green",
        FindingConfidence.HIGH: "green",
        FindingConfidence.MEDIUM: "yellow",
        FindingConfidence.POTENTIAL: "dim",
    }

    for f in findings:
        sev_style = severity_colors.get(f.severity, "white")
        conf_style = confidence_colors.get(f.confidence, "white")

        table.add_row(
            f.id,
            f"[{sev_style}]{f.severity.value}[/{sev_style}]",
            f"[{conf_style}]{f.confidence.value}[/{conf_style}]",
            f.category,
            f.endpoint,
            f.title,
        )

    console.print(table)
    console.print("[dim]Use [bold green]trace explain <ID>[/bold green] for root cause analysis and reproduction steps.[/dim]\n")


def print_finding_detail(f: Finding) -> None:
    """Renders detailed card for a single finding."""
    content = Text()
    content.append(f"Title: ", style="bold green")
    content.append(f"{f.title}\n", style="bold white")
    content.append(f"Category: ", style="bold green")
    content.append(f"{f.category}  |  ", style="white")
    content.append(f"Severity: ", style="bold green")
    content.append(f"{f.severity.value}  |  ", style="bold red")
    content.append(f"Confidence: ", style="bold green")
    content.append(f"{f.confidence.value}\n", style="bold green")
    content.append(f"Endpoint: ", style="bold green")
    content.append(f"{f.endpoint}\n", style="white")

    if f.source_location:
        content.append(f"Source Code: ", style="bold green")
        content.append(f"{f.source_location}\n", style="dim")

    if f.attack_path:
        content.append("\nAttack Path (APM Hops):\n", style="bold green")
        for idx, hop in enumerate(f.attack_path):
            prefix = "  +- "
            content.append(f"{prefix}{hop}\n", style="dim white")

    if f.static_evidence:
        content.append("\nStatic Code Evidence:\n", style="bold green")
        for ev in f.static_evidence:
            content.append(f"  * {ev}\n", style="white")

    if f.runtime_evidence:
        content.append("\nRuntime Behavioral Evidence:\n", style="bold green")
        for ev in f.runtime_evidence:
            content.append(f"  * {ev}\n", style="green")

    if f.reproduction_steps:
        content.append("\nReproduction Steps:\n", style="bold green")
        for idx, step in enumerate(f.reproduction_steps, 1):
            content.append(f"  {idx}. {step}\n", style="white")

    content.append("\nRemediation Guidance:\n", style="bold green")
    content.append(f"  {f.remediation}\n", style="dim white")

    console.print(
        Panel(
            content,
            title=f"[bold green]Finding {f.id}[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        )
    )


def print_doctor_report(report: DoctorReport) -> None:
    """Renders trace doctor diagnostic results."""
    table = Table(
        title="TRACE System Health & Environment Doctor",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("Component", style="bold white", no_wrap=True)
    table.add_column("Category", style="dim", no_wrap=True)
    table.add_column("Status", justify="center", no_wrap=True)
    table.add_column("Details", style="dim white")

    for item in report.items:
        status_badge = "[bold green]PASS[/bold green]" if item.status else "[dim red]MISSING[/dim red]" if not item.critical else "[bold red]FAIL[/bold red]"
        table.add_row(item.name, item.category, status_badge, item.details)

    console.print(table)
    if report.all_critical_passed:
        console.print("[bold green]All critical TRACE runtime requirements are satisfied.[/bold green]\n")
    else:
        console.print("[bold red]One or more critical dependencies failed. Review above.[/bold red]\n")
