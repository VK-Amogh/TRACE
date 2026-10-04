"""Tests for autonomous AST self-healing and transactional rollback."""

import pytest
from pathlib import Path
from trace_engine.harness.patcher import SafePatcher
from trace_engine.harness.remediators import AutonomousRemediator
from trace_engine.harness.context import AgentRemediationPackage


def test_bola_sqlalchemy_auto_patch():
    """Verify BOLA patch automatically scopes SQLAlchemy filter_by with tenant_id."""
    sample_code = """
    @app.route('/orders/<int:order_id>')
    def get_order(order_id):
        order = Order.query.filter_by(id=order_id).first()
        return jsonify(order.to_dict())
    """
    pkg = AgentRemediationPackage(
        finding_id="FIND-BOLA-001",
        title="BOLA in Order Lookup",
        category="BOLA",
        severity="CRITICAL",
        priority_rank=1,
        endpoint="/orders/{order_id}",
        source_file="app/orders.py",
        line_start=3,
        line_end=4,
        code_snippet=sample_code,
        remediation_guidance="Enforce tenant boundary in database queries",
        verification_criteria="Ensure current_user.tenant_id is verified",
    )

    patch = AutonomousRemediator.generate_patch(pkg)
    assert patch is not None
    target, replacement = patch

    assert "Order.query.filter_by(id=order_id).first()" in target
    assert "tenant_id=current_user.tenant_id" in replacement


def test_transactional_patcher_and_rollback(tmp_path):
    """Verify SafePatcher creates backups and cleanly rolls back on demand."""
    test_file = tmp_path / "service.py"
    original_code = "def query():\n    return db.execute(f'SELECT * FROM {table}')\n"
    test_file.write_text(original_code, encoding="utf-8")

    patcher = SafePatcher(tmp_path)
    patch_res = patcher.apply_replacement(
        finding_id="FIND-01",
        rel_path="service.py",
        target_content="f'SELECT * FROM {table}'",
        replacement_content="'SELECT * FROM :table', {'table': table}",
    )

    assert patch_res.success is True
    assert "service.py" in patch_res.target_file
    assert ":table" in test_file.read_text(encoding="utf-8")
    assert Path(patch_res.backup_file).exists()

    # Trigger rollback
    rolled_back = patcher.rollback("service.py", Path(patch_res.backup_file))
    assert rolled_back is True
    assert test_file.read_text(encoding="utf-8") == original_code
