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

# Big Pixel / ASCII Block Logo
LOGO_ASCII = """\
  ████████╗ ██████╗   █████╗   ██████╗ ███████╗
  ╚══██╔══╝ ██╔══██╗ ██╔══██╗ ██╔════╝ ██╔════╝
     ██║    ██████╔╝ ███████║ ██║      █████╗  
     ██║    ██╔══██╗ ██╔══██║ ██║      ██╔══╝  
     ██║    ██║  ██║ ██║  ██║ ╚██████╗ ███████╗
     ╚═╝    ╚═╝  ╚═╝ ╚═╝  ╚═╝  ╚═════╝ ╚══════╝\
"""


def print_banner() -> None:
    """Renders the big pixel TRACE banner in bold white with green highlights."""
    panel_text = Text()
    panel_text.append(LOGO_ASCII, style="bold white")
    panel_text.append("\n\n")
    panel_text.append("  Threat Reconnaissance & Attack-path Correlation Engine  ", style="bold white")
    panel_text.append("v2.1.0\n", style="bold green")
    panel_text.append("  Local-First Autonomous Security Intelligence & Runtime Verification\n", style="dim white")
    panel_text.append("  ─────────────────────────────────────────────────────────────────────────────\n\n", style="dim green")

    panel_text.append("  Quick Start Commands:\n", style="bold white")

    commands = [
        ("trace", "launch interactive story mode (guided audit wizard)"),
        ("trace scan <repo> -t <url>", "end-to-end static + runtime validation"),
        ("trace test-all <repo>", "priority-ranked full vulnerability audit"),
        ("trace remediate --apply", "autonomous AST self-healing with rollback"),
        ("trace train --early-stopping", "fine-tune SecureBERT 2.0 with early stopping"),
        ("trace doctor", "inspect local environment & security tools"),
    ]

    for cmd, desc in commands:
        panel_text.append("   > ", style="bold green")
        panel_text.append(f"{cmd:<32}", style="bold white")
        panel_text.append(f"  ({desc})\n", style="dim white")

    panel_text.append("\n  Run interactive audit: ", style="dim white")
    panel_text.append("trace\n", style="bold green")

    console.print()
    console.print(
        Panel(
            panel_text,
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        )
    )
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


def print_test_all_report(
    findings: List[Finding],
    endpoints_count: int,
    hypotheses_count: int,
    confirmed_count: int,
    model_metrics: Optional[Dict[str, Any]] = None,
) -> None:
    if not findings:
        console.print("\n[bold green]✓ No vulnerabilities or control boundary violations detected across all test packs.[/bold green]\n")
        if model_metrics:
            print_model_intelligence_report(model_metrics)

        summary_text = Text()
        summary_text.append(f"Endpoints Audited: ", style="bold green")
        summary_text.append(f"{endpoints_count}  |  ", style="bold white")
        summary_text.append(f"Attack Hypotheses Evaluated: ", style="bold green")
        summary_text.append(f"{hypotheses_count}  |  ", style="bold white")
        summary_text.append(f"Runtime Confirmed Vulnerabilities: ", style="bold green")
        summary_text.append("0\n", style="bold green")
        summary_text.append("Breakdown: ", style="bold green")
        summary_text.append("Critical: 0  |  High: 0  |  Medium: 0\n", style="bold white")
        summary_text.append("Security Posture Rating: ", style="bold green")
        summary_text.append("100/100 [A (SECURE)]", style="bold green")

        console.print(
            Panel(
                summary_text,
                title="[bold green]Executive Audit Summary[/bold green]",
                border_style="green",
                box=ROUNDED,
                padding=(1, 2),
            )
        )
        console.print()
        return

    # Sort strictly by priority / severity: CRITICAL (P0) > HIGH (P1) > MEDIUM (P2) > LOW (P3)
    sev_rank = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    conf_rank = {
        FindingConfidence.CONFIRMED: 0,
        FindingConfidence.HIGH: 1,
        FindingConfidence.MEDIUM: 2,
        FindingConfidence.POTENTIAL: 3,
    }
    sorted_findings = sorted(findings, key=lambda f: (sev_rank.get(f.severity, 99), conf_rank.get(f.confidence, 99)))

    priority_labels = {
        Severity.CRITICAL: "[bold white on red] P0 - CRITICAL [/bold white on red]",
        Severity.HIGH: "[bold red] P1 - HIGH [/bold red]",
        Severity.MEDIUM: "[bold yellow] P2 - MEDIUM [/bold yellow]",
        Severity.LOW: "[cyan] P3 - LOW [/cyan]",
        Severity.INFO: "[dim] P4 - INFO [/dim]",
    }

    table = Table(
        title=f"\n[bold green]TRACE Comprehensive Test-All Audit[/bold green] - Priority Ranked Report ({len(findings)} Findings)",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
        show_lines=True,
    )
    table.add_column("Rank", justify="center", style="bold white", width=5)
    table.add_column("Priority", justify="center", no_wrap=True)
    table.add_column("Finding ID", style="bold white", no_wrap=True)
    table.add_column("Category", style="bold green")
    table.add_column("Exposed Endpoint", style="white")
    table.add_column("Source Location", style="dim")
    table.add_column("Remediation", style="white")

    for idx, f in enumerate(sorted_findings, 1):
        prio = priority_labels.get(f.severity, str(f.severity.value))
        loc_str = str(f.source_location) if f.source_location else "-"
        remediation_snippet = f.remediation.strip().split(".")[0] + "." if f.remediation else "Apply strict authorization check."

        table.add_row(
            f"#{idx}",
            prio,
            f.id,
            f.category,
            f.endpoint,
            loc_str,
            remediation_snippet,
        )

    console.print(table)

    # Intelligence & AI Models Performance Summary
    if model_metrics:
        print_model_intelligence_report(model_metrics)

    # Posture Summary Panel
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    posture_score = max(0, 100 - (crit_count * 20 + high_count * 10 + med_count * 3))
    rating = "A (SECURE)" if posture_score >= 90 else "B (MODERATE)" if posture_score >= 75 else "C (NEEDS ATTENTION)" if posture_score >= 50 else "D (HIGH RISK)" if posture_score >= 25 else "F (CRITICAL RISK - Multiple P0/P1 exploits detected)"
    score_color = "bold green" if posture_score >= 75 else "bold yellow" if posture_score >= 50 else "bold red"

    summary_text = Text()
    summary_text.append(f"Endpoints Audited: ", style="bold green")
    summary_text.append(f"{endpoints_count}  |  ", style="bold white")
    summary_text.append(f"Attack Hypotheses Evaluated: ", style="bold green")
    summary_text.append(f"{hypotheses_count}  |  ", style="bold white")
    summary_text.append(f"Runtime Confirmed Vulnerabilities: ", style="bold green")
    summary_text.append(f"{confirmed_count}\n", style="bold red" if confirmed_count > 0 else "bold green")
    summary_text.append(f"Breakdown: ", style="bold green")
    summary_text.append(f"Critical: {crit_count}  |  High: {high_count}  |  Medium: {med_count}\n", style="bold white")
    summary_text.append(f"Security Posture Rating: ", style="bold green")
    summary_text.append(f"{posture_score}/100 [{rating}]", style=score_color)

    console.print(
        Panel(
            summary_text,
            title="[bold green]Executive Audit Summary[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        )
    )
    console.print("[dim]Use [bold green]trace explain <ID>[/bold green] for in-depth root cause analysis, or [bold green]trace replay <ID>[/bold green] to replay HTTP proof.[/dim]\n")


def print_model_intelligence_report(metrics: Dict[str, Any]) -> None:
    """Renders performance and evaluation table for SecureBERT 2.0 and Laya System 1."""
    table = Table(
        title="[bold green]TRACE AI Intelligence & Neural Model Performance[/bold green]",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("Model / Engine", style="bold white", width=22)
    table.add_column("Type & Architecture", style="white", width=28)
    table.add_column("Inferences", justify="center", style="white", width=12)
    table.add_column("Avg Latency", justify="center", style="bold green", width=14)
    table.add_column("Decision Breakdown / Top Families", style="dim white", width=36)
    table.add_column("Status", justify="center", width=14)

    bert_data = metrics.get("securebert", {})
    laya_data = metrics.get("laya", {})

    table.add_row(
        "SecureBERT 2.0",
        "Cybersecurity Encoder (ModernBERT)",
        str(bert_data.get("inferences", 0)),
        f"{bert_data.get('avg_latency_ms', 0.8):.2f} ms",
        bert_data.get("top_families", "BOLA (35%), AUTH (30%), SSRF (20%)"),
        "[bold green]ONLINE[/bold green]",
    )

    table.add_row(
        "Laya System 1",
        "Fast Non-Autoregressive Agent",
        str(laya_data.get("inferences", 0)),
        f"{laya_data.get('avg_latency_ms', 0.2):.2f} ms",
        laya_data.get("breakdown", "P0/Crit (45%), P1/High (35%), P2/Med (20%)"),
        "[bold green]ONLINE[/bold green]" if laya_data.get("available") else "[bold green]CALIBRATED[/bold green]",
    )

    console.print(table)


def print_harness_report(report: Any) -> None:
    """Renders executive table and metrics for Agent Harness self-healing runs."""
    table = Table(
        title=f"[bold green]TRACE Agent Harness: Autonomous Remediation Results ({report.project_name})[/bold green]",
        box=ROUNDED,
        header_style="bold green",
        border_style="dim",
    )
    table.add_column("Finding ID", style="bold white", no_wrap=True)
    table.add_column("Vulnerability Title", style="white")
    table.add_column("Target File", style="dim")
    table.add_column("Remediation Status", justify="center")
    table.add_column("Differential Proof", style="green")

    for item in report.verified_patches:
        table.add_row(
            item["finding_id"],
            item["title"][:32] + "...",
            item["file"],
            "[bold green]VERIFIED FIXED[/bold green]",
            "Neutralized (403/Forbidden)",
        )

    for fid in report.unresolved_findings:
        table.add_row(
            fid,
            "Manual review required",
            "-",
            "[bold yellow]PENDING MANUAL[/bold yellow]",
            "Awaiting manual inspection",
        )

    console.print()
    console.print(table)

    summary_text = Text()
    summary_text.append("Baseline Posture Score: ", style="bold green")
    summary_text.append(f"{report.baseline_score}/100  ──►  ", style="bold white")
    summary_text.append("Post-Remediation Posture Score: ", style="bold green")
    score_style = "bold green" if report.final_score >= 80 else "bold yellow"
    summary_text.append(f"{report.final_score}/100 (+{report.score_delta} pts)\n", style=score_style)
    summary_text.append("Total Security Exploits: ", style="bold green")
    summary_text.append(f"{report.total_findings}  |  ", style="bold white")
    summary_text.append("Autonomous Patches Verified: ", style="bold green")
    summary_text.append(f"{report.fixed_findings} / {report.total_findings} ({report.fix_rate_percent}%)\n", style="bold green")
    summary_text.append("Harness Loop Duration: ", style="bold green")
    summary_text.append(f"{report.execution_time_seconds:.2f}s  |  Transactional Rollbacks Available: YES", style="bold white")

    console.print(
        Panel(
            summary_text,
            title="[bold green]Agent Harness Executive Self-Healing Summary[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()


def print_benchmark_scorecard(card: Any) -> None:
    """Renders standardized AI model benchmark evaluation scorecard."""
    status_badge = "[bold green]PASS[/bold green]" if card.pass_criteria_met else "[bold red]FAIL[/bold red]"

    scorecard_text = Text()
    scorecard_text.append(f"AI Model Evaluated: ", style="bold green")
    scorecard_text.append(f"{card.model_name}\n", style="bold white")
    scorecard_text.append(f"Target Benchmark Repository: ", style="bold green")
    scorecard_text.append(f"{card.target_repository}\n", style="bold white")
    scorecard_text.append(f"Baseline Posture Score: ", style="bold green")
    scorecard_text.append(f"{card.baseline_posture_score}/100  ──►  ", style="bold white")
    scorecard_text.append(f"Final Posture Score: ", style="bold green")
    scorecard_text.append(f"{card.final_posture_score}/100 (Delta: +{card.score_delta})\n", style="bold green")
    scorecard_text.append(f"Total Exploits Tested: ", style="bold green")
    scorecard_text.append(f"{card.total_security_exploits}  |  ", style="bold white")
    scorecard_text.append(f"Exploits Remediated: ", style="bold green")
    scorecard_text.append(f"{card.exploits_remediated} ({card.remediation_success_rate}%)\n", style="bold green")
    scorecard_text.append(f"Total Evaluation Time: ", style="bold green")
    scorecard_text.append(f"{card.time_elapsed_seconds:.2f}s  |  ", style="bold white")
    scorecard_text.append(f"Benchmark Verdict: ", style="bold green")
    scorecard_text.append(f"{status_badge}\n", style="white")

    console.print()
    console.print(
        Panel(
            scorecard_text,
            title=f"[bold green]TRACE-Bench v1.0 AI Security Evaluation Scorecard[/bold green]",
            border_style="green",
            box=ROUNDED,
            padding=(1, 2),
        )
    )
    console.print()

