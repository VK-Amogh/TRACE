"""Markdown security report generator."""

from pathlib import Path
from typing import Any, List, Optional
from trace_engine.findings.model import Finding


def generate_markdown_report(
    findings: List[Finding],
    project_name: str = "Application",
    scope_summary=None,
    endpoints_count: Optional[int] = None,
) -> str:
    lines = [
        f"# TRACE Security Assessment Report — {project_name}",
        "Threat Reconnaissance & Attack-path Correlation Engine",
        "",
        "## Executive Summary",
        f"- **Target Application:** `{project_name}`",
        f"- **Total Correlated Findings:** **{len(findings)}**",
    ]

    effective_endpoints = endpoints_count if endpoints_count is not None else len({f.endpoint for f in findings})

    if endpoints_count == 0 or (endpoints_count is None and not findings):
        lines.append("- **Audited Endpoints:** `0` (No endpoints detected)")
        lines.append("- **Overall Status:** `No findings in the checks performed (no endpoints detected)`")
    else:
        lines.append(f"- **Audited Endpoints:** `{effective_endpoints}`")
        if not findings:
            lines.append("- **Overall Status:** `No findings in the checks performed`")
        else:
            app_count = sum(1 for f in findings if not (getattr(f, "is_fixture", False) or getattr(f, "provenance", "application") == "fixture/test"))
            fix_count = sum(1 for f in findings if (getattr(f, "is_fixture", False) or getattr(f, "provenance", "application") == "fixture/test"))
            lines.append(f"- **Overall Status:** `{len(findings)} finding(s) identified in checks performed (App: {app_count}, Fixture/Test: {fix_count})`")
    lines.append("")

    if scope_summary is not None:
        lines.append("## Scan Scope")
        for scope_line in scope_summary.summary_lines():
            lines.append(f"- {scope_line}")
        if scope_summary.excluded_top_dirs:
            lines.append("- Findings from excluded directories are out of scope for this report;")
            lines.append("  run with `--scope full` (or the fixtures profile) to assess them separately.")
        lines.append("")

    lines.append("## Assessment Coverage & Scope Status")
    lines.append("| Security Dimension | Status | Coverage Details |")
    lines.append("|---|:---:|---|")
    if endpoints_count == 0 or (endpoints_count is None and not findings):
        lines.append("| Endpoint & Route Invariants | **NOT APPLICABLE** | 0 HTTP routes detected in target scope |")
    else:
        lines.append(f"| Endpoint & Route Invariants | **ASSESSED** | Evaluated {effective_endpoints} HTTP route(s) (Auth, BOLA, BFLA, Injection, CORS) |")
    lines.append("| Hardcoded Secrets / API Keys | *NOT ASSESSED* | Secret scanning analyzer not configured |")
    lines.append("| Software Dependencies / CVEs | *NOT ASSESSED* | SCA package manifest audit not executed |")
    lines.append("| Cloud & Infrastructure Config | *NOT ASSESSED* | IaC / container posture assessment not in scope |")
    lines.append("")

    if endpoints_count == 0 or (endpoints_count is None and not findings):
        lines.append("> [!NOTE]")
        lines.append("> **Zero endpoints detected in target scope.** Endpoint-based checks were not applicable because no endpoints were found. Zero endpoint findings does **not** mean the codebase has no vulnerabilities or is secure. Unsupported categories (secrets, dependencies, configuration) were not assessed.")
        lines.append("")
        return "\n".join(lines)

    if not findings:
        lines.append("> [!NOTE]")
        lines.append(f"> **No findings in the checks performed across {effective_endpoints} evaluated endpoint(s).** Unsupported categories (secrets, dependencies, configuration) were not assessed.")
        lines.append("")
        return "\n".join(lines)

    fixture_findings = [f for f in findings if getattr(f, "is_fixture", False) or getattr(f, "provenance", "application") == "fixture/test"]
    if fixture_findings:
        lines.append("> [!NOTE]")
        lines.append(f"> **Scope & Provenance Notice:** {len(fixture_findings)} finding(s) originate from test/fixture directories (e.g. `labs/`, `test-repository/`, `testbed_hardcore/`, `tests/`). These establish detections in test/lab assets, NOT vulnerabilities in TRACE application code.")
        lines.append("")

    lines.extend(
        [
            "## Findings Summary",
            "",
            "| ID | Severity | Confidence | Category | Provenance | Endpoint | Remediation Action |",
            "|---|:---:|:---:|---|:---:|---|---|",
        ]
    )

    def _cell(value: Any) -> str:
        return str(value or "").replace("|", "\\|").replace("\n", " ")

    for f in findings:
        action_summary = f.short_action or f.title
        prov_label = "Fixture/Test" if (getattr(f, "is_fixture", False) or getattr(f, "provenance", "") == "fixture/test") else "Application"
        lines.append(
            f"| `{_cell(f.id)}` | **{_cell(f.severity.value)}** | {_cell(f.confidence.value)} | {_cell(f.category)} | {_cell(prov_label)} | `{_cell(f.endpoint)}` | {_cell(action_summary)} |"
        )

    lines.extend(["", "---", "", "## Finding Details", ""])

    for f in findings:
        prov_label = "Fixture/Test" if (getattr(f, "is_fixture", False) or getattr(f, "provenance", "") == "fixture/test") else "Application"
        lines.append(f"### [{f.id}] {str(f.title).replace(chr(10), ' ')}")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **Confidence:** {f.confidence.value}")
        lines.append(f"- **Provenance:** {prov_label}")
        lines.append(f"- **Endpoint:** `{f.endpoint}`")
        if f.source_location:
            lines.append(f"- **Source:** `{f.source_location}`")
        lines.append("")

        if f.root_cause:
            lines.append("#### Root Cause & Exploit Mechanics")
            lines.append(f"{f.root_cause}\n")

        if f.attack_path:
            lines.append("#### Attack Path Hops (APM Traversal)")
            for hop in f.attack_path:
                lines.append(f"1. `{hop}`")
            lines.append("")

        if f.static_evidence:
            lines.append("#### Static AST Evidence")
            for ev in f.static_evidence:
                lines.append(f"- {ev}")
            lines.append("")

        if f.runtime_evidence:
            lines.append("#### Runtime Behavioral Evidence")
            for ev in f.runtime_evidence:
                lines.append(f"- {ev}")
            lines.append("")

        if f.reproduction_steps:
            lines.append("#### Reproduction Steps")
            for idx, step in enumerate(f.reproduction_steps, 1):
                lines.append(f"{idx}. {step}")
            lines.append("")

        lines.append("#### Concrete Remediation Plan")
        lines.append(f"{f.remediation}\n")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
