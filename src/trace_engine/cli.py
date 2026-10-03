"""Command Line Interface for TRACE (Threat Reconnaissance & Attack-path Correlation Engine)."""

import sys
import subprocess
import time
from pathlib import Path
from typing import Optional, List

# Ensure UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console

from trace_engine.config.loader import init_trace_dir, load_config, get_trace_dir
from trace_engine.ingest.repository import RepositoryScanner
from trace_engine.parsing.parser import CodeParser, ParsedFile
from trace_engine.framework import get_adapters
from trace_engine.framework.base import Endpoint
from trace_engine.apm.builder import APMBuilder
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.serialization import save_apm_sqlite, export_apm_json
from trace_engine.security.hypotheses import HypothesisEngine, SecurityHypothesis
from trace_engine.policy.scope import ScopeGuard
from trace_engine.runtime.target import Target
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.testpacks.registry import default_registry
from trace_engine.testpacks.base import TestContext, UserIdentity
from trace_engine.findings.correlate import EvidenceCorrelator
from trace_engine.findings.store import FindingStore
from trace_engine.findings.model import Finding
from trace_engine.doctor import run_doctor
from trace_engine.tools.registry import default_tool_registry
from trace_engine.output.terminal import (
    print_banner,
    print_security_notes,
    print_endpoints_table,
    print_hypotheses_table,
    print_findings_table,
    print_finding_detail,
    print_doctor_report,
)
from trace_engine.output.markdown import generate_markdown_report
from trace_engine.output.html import generate_html_report

app = typer.Typer(
    name="trace",
    help="Threat Reconnaissance & Attack-path Correlation Engine",
    invoke_without_command=True,
    no_args_is_help=False,
)
console = Console()


@app.callback()
def main(ctx: typer.Context):
    """If no command is provided, display the Daytona/Claude welcome screen."""
    if ctx.invoked_subcommand is None:
        print_banner()
        print_security_notes()


@app.command()
def welcome():
    """Display the welcome screen and quick start guide."""
    print_banner()
    print_security_notes()


@app.command()
def init(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Initialize .trace directory structure and default configuration in target repo."""
    project_dir = path.resolve()
    if not project_dir.exists():
        console.print(f"[bold red]Error:[/bold red] Path '{project_dir}' does not exist.")
        raise typer.Exit(code=1)

    trace_dir = init_trace_dir(project_dir, project_name=project_dir.name)
    console.print(f"[bold green]Initialized TRACE[/bold green] in [white]{trace_dir}[/white]")
    console.print("  [dim]Created config.toml, runs/, cache/, and reports/[/dim]\n")


@app.command()
def index(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Scan and index source code files and extract AST symbols."""
    project_dir = path.resolve()
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()

    console.print(f"\n[bold green]Ingestion Complete:[/bold green] Discovered [bold white]{len(source_files)}[/bold white] source files.")

    parser = CodeParser()
    total_fns = 0
    total_classes = 0

    for sf in source_files:
        try:
            content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
            pf = parser.parse(sf.path, content, sf.language)
            total_fns += len(pf.functions)
            total_classes += len(pf.classes)
        except Exception:
            continue

    console.print(f"  [dim]• Files parsed:[/dim] [white]{len(source_files)}[/white]")
    console.print(f"  [dim]• Functions & Handlers indexed:[/dim] [white]{total_fns}[/white]")
    console.print(f"  [dim]• Classes identified:[/dim] [white]{total_classes}[/white]\n")


@app.command()
def endpoints(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Discover application endpoints, parameters, and authentication gates."""
    project_dir = path.resolve()
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    discovered_endpoints: List[Endpoint] = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language)
        for adapter in adapters:
            if adapter.can_handle(pf):
                eps = adapter.extract_endpoints(pf, content)
                discovered_endpoints.extend(eps)

    if not discovered_endpoints:
        console.print("\n[yellow]No framework endpoints detected in scanned files.[/yellow]\n")
        return

    console.print()
    print_endpoints_table(discovered_endpoints)
    console.print(f"[dim]Total endpoints discovered: {len(discovered_endpoints)}[/dim]\n")


@app.command()
def apm(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Construct and inspect the Attack-Path Model (APM) graph."""
    project_dir = path.resolve()
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    parsed_files: List[ParsedFile] = []
    discovered_endpoints: List[Endpoint] = []

    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language)
        parsed_files.append(pf)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

    builder = APMBuilder(project_name=project_dir.name)
    graph_model = builder.build(project_dir, source_files, parsed_files, discovered_endpoints)

    # Persist graph
    trace_dir = get_trace_dir(project_dir)
    save_apm_sqlite(graph_model, trace_dir / "graph.db")
    export_apm_json(graph_model, trace_dir / "graph.json")

    summary = graph_model.summary()
    console.print("\n[bold green]Attack-Path Model (APM) Generated:[/bold green]")
    console.print(f"  [dim]• Total Nodes:[/dim] [bold white]{summary['total_nodes']}[/bold white]")
    console.print(f"  [dim]• Directed Edges:[/dim] [bold white]{summary['total_edges']}[/bold white]")
    for ntype, cnt in summary["nodes_by_type"].items():
        console.print(f"    - {ntype}: {cnt}")
    console.print(f"  [dim]Graph serialized to SQLite: {trace_dir / 'graph.db'}[/dim]\n")


@app.command()
def analyze(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Analyze static security signals and derive actionable attack-surface hypotheses."""
    project_dir = path.resolve()
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    parsed_files = []
    discovered_endpoints = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language)
        parsed_files.append(pf)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

    builder = APMBuilder(project_name=project_dir.name)
    graph_model = builder.build(project_dir, source_files, parsed_files, discovered_endpoints)

    engine = HypothesisEngine()
    hypotheses = engine.derive_hypotheses(graph_model, discovered_endpoints)

    console.print()
    print_hypotheses_table(hypotheses)
    console.print(f"[dim]Derived {len(hypotheses)} testable security hypotheses from Attack-Path Model.[/dim]\n")


@app.command()
def test(
    path: Path = typer.Argument(Path("."), help="Path to project repository"),
    target: str = typer.Option("http://127.0.0.1:18080", "--target", "-t", help="Target URL (must be localhost or authorized lab)"),
):
    """Execute active test packs against derived hypotheses using ScopedHttpClient."""
    project_dir = path.resolve()
    config = load_config(project_dir)

    # Ingest and derive hypotheses
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    parsed_files = []
    discovered_endpoints = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language)
        parsed_files.append(pf)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

    builder = APMBuilder(project_name=project_dir.name)
    graph_model = builder.build(project_dir, source_files, parsed_files, discovered_endpoints)

    engine = HypothesisEngine()
    hypotheses = engine.derive_hypotheses(graph_model, discovered_endpoints)

    # Setup ScopedHttpClient
    scope_guard = ScopeGuard(
        allowed_hosts=config.target.allowed_hosts,
        allowed_ports=config.target.allowed_ports,
        mode=config.target.scope_mode,
    )
    client = ScopedHttpClient(scope_guard=scope_guard, timeout_seconds=config.runtime.timeout_seconds)

    # Setup test context with synthetic tokens
    context = TestContext(
        target_base_url=target,
        active_tokens={"user-a": "user-a", "user-b": "user-b", "admin": "admin"},
    )

    console.print(f"\n[bold green]Executing Controlled Runtime Tests[/bold green] against [white]{target}[/white]...")
    executed = 0
    confirmed = 0

    for hyp in hypotheses:
        pack = default_registry.get(hyp.recommended_test_pack)
        if pack:
            executed += 1
            res = pack.execute(hyp, client, context)
            if res.confirmed:
                confirmed += 1
                console.print(f"  [bold red]CONFIRMED:[/bold red] [{hyp.id}] {res.summary}")
            else:
                console.print(f"  [dim]Passed / Inconclusive:[/dim] [{hyp.id}] {res.summary}")

    console.print(f"\n[dim]Executed {executed} test packs. {confirmed} attack paths confirmed.[/dim]\n")


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to project repository"),
    target: str = typer.Option("http://127.0.0.1:18080", "--target", "-t", help="Target URL (must be localhost or authorized lab)"),
):
    """Execute end-to-end scan: Ingestion -> APM -> Signals -> Runtime Tests -> Correlated Findings."""
    project_dir = path.resolve()
    config = load_config(project_dir)

    console.print(f"\n[bold green]Starting TRACE Full Scan[/bold green] on [white]{project_dir.name}[/white]")
    console.print(f"  [dim]Target Runtime:[/dim] [white]{target}[/white]")

    # 1. Ingest
    scanner = RepositoryScanner(project_dir)
    source_files = scanner.scan()
    parser = CodeParser()
    adapters = get_adapters()

    parsed_files = []
    discovered_endpoints = []
    for sf in source_files:
        content = Path(sf.absolute_path).read_text(encoding="utf-8", errors="replace")
        pf = parser.parse(sf.path, content, sf.language)
        parsed_files.append(pf)
        for adapter in adapters:
            if adapter.can_handle(pf):
                discovered_endpoints.extend(adapter.extract_endpoints(pf, content))

    console.print(f"  [dim]✓ Ingestion:[/dim] {len(source_files)} files, {len(discovered_endpoints)} endpoints discovered")

    # 2. Attack-Path Model
    builder = APMBuilder(project_name=project_dir.name)
    graph_model = builder.build(project_dir, source_files, parsed_files, discovered_endpoints)
    trace_dir = init_trace_dir(project_dir)
    save_apm_sqlite(graph_model, trace_dir / "graph.db")
    console.print(f"  [dim]✓ Attack-Path Model:[/dim] {graph_model.graph.number_of_nodes()} nodes, {graph_model.graph.number_of_edges()} edges")

    # 3. Hypotheses
    engine = HypothesisEngine()
    hypotheses = engine.derive_hypotheses(graph_model, discovered_endpoints)
    console.print(f"  [dim]✓ Security Hypotheses:[/dim] {len(hypotheses)} derived attack hypotheses")

    # 4. Runtime Validation
    scope_guard = ScopeGuard(
        allowed_hosts=config.target.allowed_hosts,
        allowed_ports=config.target.allowed_ports,
        mode=config.target.scope_mode,
    )
    client = ScopedHttpClient(scope_guard=scope_guard, timeout_seconds=config.runtime.timeout_seconds)
    context = TestContext(
        target_base_url=target,
        active_tokens={"user-a": "user-a", "user-b": "user-b", "admin": "admin"},
    )

    correlator = EvidenceCorrelator()
    findings: List[Finding] = []

    for hyp in hypotheses:
        pack = default_registry.get(hyp.recommended_test_pack)
        test_res = None
        if pack:
            try:
                test_res = pack.execute(hyp, client, context)
            except Exception:
                test_res = None

        finding = correlator.correlate(hyp, test_res, graph_model)
        if finding:
            findings.append(finding)

    # 5. Persist Findings
    store = FindingStore(trace_dir)
    store.save_findings(findings)

    console.print(f"  [dim]✓ Evidence Correlation:[/dim] [bold white]{len(findings)}[/bold white] correlated findings\n")
    print_findings_table(findings)


@app.command()
def findings(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Display stored vulnerability findings from previous scan."""
    project_dir = path.resolve()
    store = FindingStore(get_trace_dir(project_dir))
    findings_list = store.load_findings()
    console.print()
    print_findings_table(findings_list)


@app.command()
def explain(
    finding_id: str = typer.Argument(..., help="ID of the finding to explain (e.g. TR-BOLA-001)"),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Path to project repository"),
):
    """Deep-dive into a finding with root cause analysis and reproduction details."""
    project_dir = path.resolve()
    store = FindingStore(get_trace_dir(project_dir))
    finding = store.get_finding_by_id(finding_id)
    if not finding:
        console.print(f"[bold red]Finding '{finding_id}' not found.[/bold red] Run [green]trace findings[/green] to view available findings.\n")
        return

    console.print()
    print_finding_detail(finding)
    console.print()


@app.command()
def replay(
    finding_id: str = typer.Argument(..., help="ID of finding to replay"),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Path to project repository"),
):
    """Replay the exact HTTP reproduction requests for a finding."""
    project_dir = path.resolve()
    store = FindingStore(get_trace_dir(project_dir))
    finding = store.get_finding_by_id(finding_id)
    if not finding or not finding.reproduction_steps:
        console.print(f"[yellow]No reproduction steps recorded for finding {finding_id}.[/yellow]")
        return

    console.print(f"\n[bold green]Replaying Finding {finding.id}:[/bold green] {finding.title}")
    for idx, step in enumerate(finding.reproduction_steps, 1):
        console.print(f"  [green]Step {idx}:[/green] {step}")
    console.print()


@app.command()
def report(
    format: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, html, or json"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Path to project repository"),
):
    """Export comprehensive security assessment report."""
    project_dir = path.resolve()
    store = FindingStore(get_trace_dir(project_dir))
    findings_list = store.load_findings()

    if format.lower() == "html":
        content = generate_html_report(findings_list, project_name=project_dir.name)
        ext = ".html"
    elif format.lower() == "json":
        import json
        content = json.dumps([f.model_dump() for f in findings_list], indent=2)
        ext = ".json"
    else:
        content = generate_markdown_report(findings_list, project_name=project_dir.name)
        ext = ".md"

    out_file = output or (get_trace_dir(project_dir) / f"reports/trace_report{ext}")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(content, encoding="utf-8")
    console.print(f"[bold green]Report generated:[/bold green] [white]{out_file}[/white]\n")


@app.command()
def doctor():
    """Verify local environment, Tree-sitter, SQLite, Ollama, and security tool adapters."""
    console.print()
    rep = run_doctor()
    print_doctor_report(rep)


@app.command()
def tools():
    """List registered external tool adapters and installation status."""
    console.print("\n[bold green]TRACE Tool Adapters[/bold green]")
    for t in default_tool_registry.get_all_info():
        badge = "[green]Installed[/green]" if t.installed else "[dim]Not installed[/dim]"
        console.print(f"  • [bold white]{t.name:<16}[/bold white] ({t.category:<16}) - {badge} - [dim]{t.description}[/dim]")
    console.print()


@app.command()
def testpacks():
    """List registered security test packs."""
    console.print("\n[bold green]TRACE Registered Test Packs[/bold green]")
    for p in default_registry.list_all():
        console.print(f"  • [bold green]{p.name:<18}[/bold green] - [dim]{p.description}[/dim]")
    console.print()


@app.command()
def lab(
    action: str = typer.Argument("status", help="Action: start or status"),
    port: int = typer.Option(18080, "--port", "-p", help="Port to host vulnerable lab"),
):
    """Manage the vulnerable Vending API testbed for offline evaluation."""
    lab_dir = Path(__file__).resolve().parent.parent.parent / "labs/vending-api"
    if action == "start":
        console.print(f"\n[bold green]Starting Vending API Lab on http://127.0.0.1:{port}...[/bold green]")
        console.print("[dim]Press Ctrl+C to terminate the lab process.[/dim]\n")
        runner_path = lab_dir / "run.py"
        subprocess.run([sys.executable, str(runner_path), str(port)])
    else:
        # Check health
        import httpx
        try:
            with httpx.Client(timeout=1.0) as client:
                res = client.get(f"http://127.0.0.1:{port}/health")
                if res.status_code == 200:
                    console.print(f"\n[bold green]Vending API Lab is active and healthy on http://127.0.0.1:{port}[/bold green]\n")
                    return
        except Exception:
            pass
        console.print(f"\n[yellow]Vending API Lab is not running on port {port}.[/yellow]")
        console.print("Start it with: [bold green]trace lab start[/bold green]\n")


@app.command()
def verify(
    finding_id: str = typer.Argument(..., help="Finding ID to verify (e.g. TR-BOLA-001)"),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Path to project repository"),
    target: str = typer.Option("http://127.0.0.1:18080", "--target", "-t", help="Target URL"),
):
    """Verify whether a code modification by a coding agent resolved a finding (Section 58)."""
    from trace_engine.verify import VerificationEngine, VerificationStatus

    project_dir = path.resolve()
    console.print(f"\n[bold green]Verifying Finding {finding_id}[/bold green] on [white]{project_dir.name}[/white]...")
    engine = VerificationEngine(repo_path=project_dir, target_url=target)
    res = engine.verify(finding_id)

    status_color = "bold green" if res.status == VerificationStatus.FIXED else "bold red" if res.status == VerificationStatus.STILL_PRESENT else "bold yellow"
    console.print(f"  Result: [{status_color}]{res.status.value}[/{status_color}]")
    console.print(f"  Summary: {res.summary}")
    console.print(f"  Differential: [dim]{res.differential_analysis}[/dim]\n")


@app.command()
def mcp():
    """Start the TRACE Model Context Protocol (MCP) server over stdio for Claude Code / Codex."""
    from trace_engine.mcp.server import TraceMCPServer

    server = TraceMCPServer()
    server.run_stdio()


@app.command("setup-mcp")
def setup_mcp(
    path: Path = typer.Argument(Path("."), help="Path to project repository")
):
    """Generate .mcp.json and configure MCP coding agent integration (Section 64)."""
    from trace_engine.mcp.config import generate_mcp_json

    project_dir = path.resolve()
    mcp_file = generate_mcp_json(project_dir)

    console.print(f"\n[bold green]Configured TRACE MCP[/bold green] in [white]{mcp_file}[/white]")
    console.print("\n[bold white]Connect to Claude Code:[/bold white]")
    console.print("  [green]claude mcp add trace -- cmd /c npx -y @trace-security/trace mcp[/green]")
    console.print("\n[bold white]Connect to Codex / Cursor / Antigravity:[/bold white]")
    console.print("  [dim]The generated .mcp.json is already recognized by compatible IDEs and CLI agents.[/dim]\n")


@app.command()
def benchmark(
    limit: int = typer.Option(50, "--limit", "-l", help="Number of benchmark test cases to evaluate")
):
    """Evaluate TRACE against the OWASP Benchmark Python ground truth (Section 12)."""
    from benchmarks.runner import run_owasp_benchmark
    run_owasp_benchmark(limit=limit)


@app.command()
def intelligence():
    """Display status of the Laya System 1 and SecureBERT 2.0 neural intelligence stack."""
    from trace_engine.intelligence.laya.router import LayaDecisionEngine
    from trace_engine.intelligence.securebert.classifier import SecureBERTClassifier

    console.print("\n[bold green]TRACE Intelligence Stack Status[/bold green]")
    laya = LayaDecisionEngine()
    bert = SecureBERTClassifier()

    laya_status = "[bold green]ONLINE (convaiinnovations/laya loaded on CPU)[/bold green]" if laya.is_available() else "[yellow]Standby (calibrated fallback active)[/yellow]"
    console.print(f"  • Laya System 1 Decision Engine: {laya_status}")
    console.print(f"  • SecureBERT 2.0 Semantic Classifier: [bold green]ONLINE ({bert.model_name})[/bold green]")
    console.print("  • Model Hierarchy: Deterministic -> SecureBERT -> Laya System 1 -> Local LLM\n")


if __name__ == "__main__":
    app()

