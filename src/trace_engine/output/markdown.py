"""Markdown security report generator."""

from pathlib import Path
from typing import List
from trace_engine.findings.model import Finding


def generate_markdown_report(findings: List[Finding], project_name: str = "Application") -> str:
    lines = [
        f"# TRACE Security Assessment Report — {project_name}",
        "Threat Reconnaissance & Attack-path Correlation Engine",
        "",
        "## Summary",
        f"- Total Correlated Findings: **{len(findings)}**",
        "",
        "| ID | Severity | Confidence | Category | Endpoint | Title |",
        "|---|---|---|---|---|---|",
    ]

    for f in findings:
        lines.append(
            f"| {f.id} | {f.severity.value} | {f.confidence.value} | {f.category} | `{f.endpoint}` | {f.title} |"
        )

    lines.extend(["", "---", "", "## Finding Details", ""])

    for f in findings:
        lines.append(f"### [{f.id}] {f.title}")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Severity:** {f.severity.value}")
        lines.append(f"- **Confidence:** {f.confidence.value}")
        lines.append(f"- **Endpoint:** `{f.endpoint}`")
        if f.source_location:
            lines.append(f"- **Source:** `{f.source_location}`")
        lines.append("")
        
        if f.attack_path:
            lines.append("#### Attack Path Hops")
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

        lines.append(f"#### Remediation Guidance\n{f.remediation}\n")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
