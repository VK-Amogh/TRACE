"""Tests for multi-language autonomous remediators (Go, Ruby, C#)."""

import pytest
from trace_engine.harness.remediators import AutonomousRemediator
from trace_engine.harness.context import AgentRemediationPackage


def test_go_sqli_remediation():
    code = """
    func QueryUser(c *gin.Context) {
        id := c.Query("id")
        var user User
        db.Raw(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)).Scan(&user)
        c.JSON(200, user)
    }
    """
    pkg = AgentRemediationPackage(
        finding_id="FIND-GO-SQLI",
        title="Go SQL Injection",
        category="INJECTION",
        severity="HIGH",
        priority_rank=1,
        endpoint="/api/v1/users",
        source_file="server.go",
        line_start=3,
        line_end=5,
        code_snippet=code,
        remediation_guidance="Use parameterized SQL query",
        verification_criteria="Ensure query uses placeholders",
    )
    patch = AutonomousRemediator.generate_patch(pkg)
    assert patch is not None
    target, replacement = patch
    assert 'fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)' in target
    assert '?' in replacement
    assert 'id' in replacement


def test_go_bola_remediation():
    code = """
    func GetVaultSecret(c *gin.Context) {
        record := db.Find(c.Param("id"))
        c.JSON(http.StatusOK, record)
    }
    """
    pkg = AgentRemediationPackage(
        finding_id="FIND-GO-BOLA",
        title="Go BOLA in Vault",
        category="BOLA",
        severity="CRITICAL",
        priority_rank=1,
        endpoint="/vault/:id",
        source_file="vault.go",
        line_start=2,
        line_end=4,
        code_snippet=code,
        remediation_guidance="Validate tenant boundary",
        verification_criteria="Block cross-tenant access",
    )
    patch = AutonomousRemediator.generate_patch(pkg)
    assert patch is not None
    target, replacement = patch
    assert "TenantID != currentTenantID" in replacement
    assert "http.StatusForbidden" in replacement
