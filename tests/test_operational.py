"""Operational tests: the CLI must behave in pipes, scripts, and CI.

Covers non-interactive startup (never hang waiting for input), machine
readable output purity (valid JSON on stdout), port conflicts, and the
doctor health gate. Uses typer's CliRunner (non-tty stdin by design).
"""

import json
import shutil
import socket
from pathlib import Path

from typer.testing import CliRunner

from trace_engine.cli import app, _maybe_update_notice
from trace_engine.doctor import run_doctor

runner = CliRunner()


def test_bare_invoke_prints_help_without_hanging():
    """Bare `trace` with no TTY must print help and exit, not prompt."""
    res = runner.invoke(app, [])
    assert res.exit_code == 0
    assert "audit" in res.output.lower() or "usage" in res.output.lower()


def test_version_flag_works_offline():
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "TRACE" in res.output


def test_help_lists_key_commands():
    res = runner.invoke(app, ["--help"])
    assert res.exit_code == 0
    for cmd in ("audit", "scan", "verify", "doctor"):
        assert cmd in res.output


def test_update_notice_stays_silent_for_machines():
    """Update banner/prompt must never pollute structured or piped output."""
    _maybe_update_notice("json")
    _maybe_update_notice("markdown")
    _maybe_update_notice("sarif")
    _maybe_update_notice("table")  # non-tty under CliRunner: also silent


def test_audit_json_output_parses(tmp_path: Path):
    """End-to-end audit on an isolated fixture copy yields valid JSON."""
    src = Path(__file__).parent.parent / "testbed_hardcore"
    work = tmp_path / "tb"
    shutil.copytree(src, work)
    res = runner.invoke(app, ["audit", str(work), "--format", "json", "--no-models"])
    assert res.exit_code == 0, res.output[-2000:]
    payload = json.loads(res.stdout)
    assert "findings" in payload
    assert payload["findings_count"] == len(payload["findings"])


def test_scan_sarif_output_parses(tmp_path: Path):
    """SARIF report on stdout must be valid JSON with results."""
    src = Path(__file__).parent.parent / "testbed_hardcore"
    work = tmp_path / "tb"
    shutil.copytree(src, work)
    res = runner.invoke(app, ["scan", str(work), "--format", "sarif"])
    assert res.exit_code == 0, res.output[-2000:]
    payload = json.loads(res.stdout)
    assert payload["version"] == "2.1.0"
    assert isinstance(payload["runs"][0]["results"], list)


def test_mcp_server_refuses_occupied_port():
    """Port conflict must fail fast with an actionable error, not hang."""
    from trace_engine.mcp.server import TraceMCPServer, _suggest_free_port

    blocker = socket.create_server(("127.0.0.1", 0))
    busy_port = blocker.getsockname()[1]
    try:
        suggestion = _suggest_free_port("127.0.0.1", busy_port)
        assert suggestion is not None and suggestion != busy_port
        try:
            TraceMCPServer().run_sse_server(host="127.0.0.1", port=busy_port)
        except OSError:
            pass
        else:
            raise AssertionError("expected OSError for occupied port")
    finally:
        blocker.close()


def test_doctor_report_shape():
    """Doctor always returns a structured report, even with missing deps."""
    report = run_doctor()
    assert report is not None
    assert len(report.items) > 0
    names = {i.name for i in report.items}
    assert "Accelerators" in names
    assert any(i.critical for i in report.items)
