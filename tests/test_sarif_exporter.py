"""Tests for OASIS SARIF v2.1.0 exporter."""

import pytest
import json
from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.parsing.locations import SourceLocation
from trace_engine.output.sarif import generate_sarif_report, export_sarif_json


def test_sarif_generation(tmp_path):
    f1 = Finding(
        id="FIND-SQLI-001",
        title="SQL Injection in user lookup",
        category="sqli",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/api/users",
        source_location=SourceLocation(file="app/users.py", line_start=42, line_end=45),
        attack_path=["client -> /api/users", "query -> db.execute(sql)"],
        static_evidence=["db.execute with format string"],
        runtime_evidence=["Payload 1' OR '1'='1 returned 200 OK"],
        correlation_notes="AST injection confirmed by runtime payload",
        remediation="Use parameterized queries cursor.execute(query, (id,))",
        reproduction_steps=["curl http://127.0.0.1:8000/api/users?id=1' OR '1'='1"],
    )

    f2 = Finding(
        id="FIND-BOLA-002",
        title="BOLA in tenant record",
        category="bola",
        severity=Severity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/api/records/{id}",
        source_location=SourceLocation(file="app/records.py", line_start=12, line_end=15),
        correlation_notes="Missing tenant isolation",
        remediation="Verify tenant_id == auth_user.tenant_id",
    )

    sarif = generate_sarif_report([f1, f2], project_name="TestApp", workspace_root="/workspace")
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "TRACE Security Engine"
    assert len(run["tool"]["driver"]["rules"]) == 2
    assert len(run["results"]) == 2

    # Verify rule IDs and CWEs
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert "TRACE-SQLI" in rule_ids
    assert "TRACE-BOLA" in rule_ids

    # Verify results
    r1 = run["results"][0]
    assert r1["ruleId"] == "TRACE-SQLI"
    assert r1["level"] == "error"
    assert "codeFlows" in r1
    assert r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/users.py"

    # Test file export
    out_file = tmp_path / "test.sarif"
    exported_path = export_sarif_json([f1, f2], str(out_file))
    assert out_file.exists()
    with open(out_file, "r", encoding="utf-8") as fp:
        loaded = json.load(fp)
    assert loaded["version"] == "2.1.0"
