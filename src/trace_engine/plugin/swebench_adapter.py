"""SWE-bench dataset adapter for the TRACE Agent Harness Plugin."""

import json
from pathlib import Path
from typing import List, Dict, Any

from trace_engine.findings.model import Finding
from trace_engine.plugin.task import HarnessTaskSpec


def build_harness_task(finding: Finding, repo_path: Path) -> HarnessTaskSpec:
    """Transform a CorrelatedFinding into a standardized agent harness task specification."""
    rel_path = str(finding.source_location.file) if finding.source_location else "unknown"
    start_line = finding.source_location.line_start if finding.source_location else 1
    end_line = finding.source_location.line_end if finding.source_location else 1

    code_snippet = ""
    try:
        full_file = repo_path / rel_path
        if full_file.is_file():
            lines = full_file.read_text(encoding="utf-8", errors="replace").splitlines()
            sl = max(0, start_line - 1)
            el = min(len(lines), end_line + 5)
            code_snippet = "\n".join(lines[sl:el])
    except Exception:
        code_snippet = ""

    static_ev = "\n".join(f"- `{ev}`" for ev in (finding.static_evidence or []))

    problem_stmt = (
        f"# Security Vulnerability Remediation: {finding.title}\n\n"
        f"**Category:** {finding.category}\n"
        f"**Severity:** {finding.severity.value}\n"
        f"**Target Endpoint:** `{finding.endpoint}`\n"
        f"**Vulnerable Source:** `{rel_path}:{start_line}`\n\n"
        f"## Vulnerability Description\n"
        f"{finding.correlation_notes or finding.title}\n\n"
        f"## Static Analysis Evidence\n"
        f"{static_ev or 'None'}\n\n"
        f"## Attack Path\n"
        + "\n".join(f"- {hop}" for hop in (finding.attack_path or [])) + "\n\n"
        f"## Live Exploit Proof\n"
        + "\n".join(f"- `{proof}`" for proof in (finding.runtime_evidence or [])) + "\n\n"
        f"## Objective\n"
        f"Modify `{rel_path}` to fix the vulnerability without breaking the endpoint contract or returning static dummy responses."
    )

    hints = (
        f"Recommended Remediation Architecture:\n"
        f"{finding.remediation}\n\n"
        f"Reproduction steps:\n"
        + "\n".join(f"1. {step}" for step in (finding.reproduction_steps or []))
    )

    task_id = f"trace__{repo_path.name.lower()}-{finding.id}"

    return HarnessTaskSpec(
        instance_id=task_id,
        finding_id=finding.id,
        title=finding.title,
        category=finding.category,
        severity=finding.severity.value,
        repo_name=repo_path.name,
        endpoint=finding.endpoint,
        source_file=rel_path,
        line_start=start_line,
        line_end=end_line,
        code_snippet=code_snippet,
        problem_statement=problem_stmt,
        hints_text=hints,
        attack_path_hops=finding.attack_path or [],
        runtime_exploit_proof=finding.runtime_evidence or [],
        reproduction_steps=finding.reproduction_steps or [],
        fail_to_pass=[f"test_exploit_{finding.id}"],
        pass_to_pass=["test_endpoint_functional_health"],
        metadata={
            "finding_id": finding.id,
            "category": finding.category,
            "severity": finding.severity.value,
        },
    )


def export_swebench_jsonl(tasks: List[HarnessTaskSpec], output_file: Path) -> int:
    """Export tasks to a SWE-bench compatible JSONL benchmark dataset file."""
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as f:
        for t in tasks:
            f.write(json.dumps(t.to_swebench_dict()) + "\n")
    return len(tasks)
