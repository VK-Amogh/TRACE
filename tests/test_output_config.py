"""Smoke tests for output renderers, MCP config, and CLI entry points."""

from pathlib import Path

from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.output.markdown import generate_markdown_report
from trace_engine.output.html import generate_html_report
from trace_engine.output.sarif import generate_sarif_report
from trace_engine.mcp.config import generate_mcp_json


def _finding():
    return Finding(
        id="TR-SSRF-001",
        title="t",
        category="ssrf",
        severity=Severity.HIGH,
        confidence=FindingConfidence.HIGH,
        endpoint="POST /api/hook",
        attack_path=["a", "b"],
        static_evidence=[],
        runtime_evidence=[],
        correlation_notes="",
        remediation="validate url",
        reproduction_steps=[],
        observations=[],
        root_cause="",
        short_action="validate",
    )


def test_markdown_escapes_table_cells():
    evil = _finding()
    evil.title = "a|b\nc"
    evil.short_action = "do x|y"
    md = generate_markdown_report([evil], project_name="P")
    row = [ln for ln in md.splitlines() if ln.startswith("| `TR-SSRF-001`")][0]
    assert "do x\\|y" in row
    assert "\n" not in row
    heading = [ln for ln in md.splitlines() if ln.startswith("###")][0]
    assert "\n" not in heading


def test_html_report_escapes_content():
    evil = _finding()
    evil.title = "<script>alert(1)</script>"
    html = generate_html_report([evil], project_name="P")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_sarif_report_structure():
    sarif = generate_sarif_report([_finding()], project_name="P", workspace_root=".")
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["locations"], "results must carry locations"
    for cf in results[0].get("codeFlows", []):
        for tf in cf["threadFlows"]:
            for loc in tf["locations"]:
                assert "physicalLocation" in loc["location"]


def test_mcp_config_merges_and_is_deterministic(tmp_path: Path):
    existing = tmp_path / ".mcp.json"
    existing.write_text('{"mcpServers": {"other": {"command": "x"}}}', encoding="utf-8")
    out = generate_mcp_json(tmp_path)
    import json

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["mcpServers"]["other"]["command"] == "x"
    assert data["mcpServers"]["trace"]["env"]["PYTHONUNBUFFERED"] == "1"


def test_cli_version_flag():
    from typer.testing import CliRunner
    from trace_engine.cli import app

    res = CliRunner().invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "TRACE" in res.output
