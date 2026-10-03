"""Tests for TRACE Agent Harness Plugin, SWE-bench adapter, and evaluation oracles."""

import json
import pytest
from pathlib import Path

from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.parsing.locations import SourceLocation
from trace_engine.plugin import TraceHarnessPlugin, HarnessTaskSpec
from trace_engine.plugin.swebench_adapter import build_harness_task, export_swebench_jsonl
from trace_engine.mcp.server import TraceMCPServer


@pytest.fixture
def mock_finding() -> Finding:
    return Finding(
        id="TR-TEST-001",
        title="Test BOLA Vulnerability on Record Retrieval",
        category="BOLA",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="GET /api/records/{id}",
        source_location=SourceLocation(file="src/records.py", line_start=10, line_end=15),
        attack_path=["ep_records_GET", "fn_get_record", "sink_db_query"],
        static_evidence=["Missing tenantId check in findById query"],
        runtime_evidence=["HTTP GET /api/records/99 -> 200 OK across tenant boundaries"],
        correlation_notes="AST indicates unscoped query, runtime confirmed cross-tenant retrieval.",
        remediation="Enforce tenant boundary checks using SecurityContext.",
        reproduction_steps=["Login as tenant B", "Request tenant A record /api/records/99"],
    )


def test_build_harness_task(mock_finding: Finding, tmp_path: Path):
    # Setup dummy source file
    src_file = tmp_path / "src" / "records.py"
    src_file.parent.mkdir(parents=True)
    src_file.write_text("\n".join([f"line_{i}" for i in range(1, 30)]), encoding="utf-8")

    task = build_harness_task(mock_finding, tmp_path)
    assert task.instance_id.startswith("trace__")
    assert task.finding_id == "TR-TEST-001"
    assert task.category == "BOLA"
    assert task.severity == "HIGH"
    assert "Enforce tenant boundary" in task.hints_text
    assert "Missing tenantId" in task.problem_statement


def test_swebench_export(mock_finding: Finding, tmp_path: Path):
    task = build_harness_task(mock_finding, tmp_path)
    out_file = tmp_path / "bench.jsonl"
    count = export_swebench_jsonl([task], out_file)

    assert count == 1
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8").strip())
    assert data["instance_id"] == task.instance_id
    assert data["version"] == "1.0"
    assert data["FAIL_TO_PASS"] == ["test_exploit_TR-TEST-001"]
    assert "target_endpoint" in data


def test_plugin_installation(tmp_path: Path):
    plugin = TraceHarnessPlugin(repo_path=tmp_path)
    locations = plugin.install(workspace_mode=True, global_mode=False)

    ws_path = locations["workspace"]
    assert (ws_path / "plugin.json").exists()
    assert (ws_path / "mcp_config.json").exists()
    assert (ws_path / "hooks.json").exists()
    assert (ws_path / "rules" / "security_remediation.md").exists()
    assert (ws_path / "skills" / "trace-security-harness" / "SKILL.md").exists()

    # Verify manifest content
    manifest = json.loads((ws_path / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == "trace-security"
    assert manifest["version"] == "2.0.0"


def test_mcp_harness_tools():
    server = TraceMCPServer()
    list_res = server.handle_request({"method": "tools/list", "id": 100})
    tool_names = [t["name"] for t in list_res["result"]["tools"]]

    assert "trace_harness_task" in tool_names
    assert "trace_eval_patch" in tool_names
    assert "trace_findings" in tool_names
    assert "trace_verify" in tool_names
