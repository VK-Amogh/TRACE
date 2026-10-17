"""Tests for TRACE CLI command surface and flag aliases.

Verifies:
- trace version / --version / --json
- trace upgrade / --upgrade / update / --update
- trace doctor / --doctor / diagnose / health
- trace epics / eps / routes / endpoints / epics version
- trace help
"""

import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from trace_engine.cli import app
import trace_engine


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_version_flag(runner):
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert trace_engine.__version__ in res.output


def test_cli_version_cmd(runner):
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert trace_engine.__version__ in res.output


def test_cli_version_cmd_json(runner):
    res = runner.invoke(app, ["version", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert data["version"] == trace_engine.__version__
    assert data["package"] == "trace-sec"


def test_cli_help_cmd(runner):
    res = runner.invoke(app, ["help"])
    assert res.exit_code == 0
    assert "Threat Reconnaissance & Attack-path Correlation Engine" in res.output
    assert "doctor" in res.output
    assert "epics" in res.output


def test_cli_epics_alias(runner, tmp_path):
    # Running 'epics' against an empty tmp directory
    res = runner.invoke(app, ["epics", str(tmp_path)])
    assert res.exit_code == 0
    assert "No framework endpoints detected" in res.output


def test_cli_eps_alias(runner, tmp_path):
    res = runner.invoke(app, ["eps", str(tmp_path)])
    assert res.exit_code == 0
    assert "No framework endpoints detected" in res.output


def test_cli_routes_alias(runner, tmp_path):
    res = runner.invoke(app, ["routes", str(tmp_path)])
    assert res.exit_code == 0
    assert "No framework endpoints detected" in res.output


def test_cli_epics_version_graceful(runner):
    # When user executes 'epics version'
    res = runner.invoke(app, ["epics", "version"])
    assert res.exit_code == 0
    assert "TRACE Endpoints" in res.output


def test_cli_doctor_flag(runner, monkeypatch):
    # Mock run_doctor to verify --doctor flag invokes doctor handler
    from trace_engine.doctor import DoctorReport
    monkeypatch.setattr("trace_engine.doctor.run_doctor", lambda project_root=None: DoctorReport(items=[], all_critical_passed=True))
    res = runner.invoke(app, ["--doctor"])
    assert res.exit_code == 0
    assert "Doctor" in res.output


def test_cli_doctor_aliases(runner, monkeypatch):
    from trace_engine.doctor import DoctorReport
    monkeypatch.setattr("trace_engine.doctor.run_doctor", lambda project_root=None: DoctorReport(items=[], all_critical_passed=True))
    for alias in ["doctor", "diagnose", "health"]:
        res = runner.invoke(app, [alias])
        assert res.exit_code == 0
        assert "Doctor" in res.output


def test_cli_upgrade_flag(runner, monkeypatch):
    monkeypatch.setattr("trace_engine.updater.check_for_updates", lambda force=True: {"update_available": False})
    for flag in ["--upgrade", "--update"]:
        res = runner.invoke(app, [flag])
        assert res.exit_code == 0
        assert "up to date" in res.output or "Checking for TRACE updates" in res.output


def test_cli_upgrade_cmd(runner, monkeypatch):
    monkeypatch.setattr("trace_engine.updater.check_for_updates", lambda force=True: {"update_available": False})
    for cmd in ["upgrade", "update"]:
        res = runner.invoke(app, [cmd])
        assert res.exit_code == 0
        assert "up to date" in res.output or "Checking for TRACE updates" in res.output
