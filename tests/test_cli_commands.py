"""Tests for TRACE CLI command surface and flag aliases.

Verifies:
- trace version / --version / --json
- trace upgrade / --upgrade / update / --update
- trace doctor / --doctor / diagnose / health
- trace epics / eps / routes / endpoints / epics version
- trace help
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import trace_engine
from trace_engine.cli import app


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
    res = runner.invoke(app, ["epics", "version"])
    assert res.exit_code == 0
    assert "TRACE Endpoints" in res.output


def test_cli_doctor_flag(runner, monkeypatch):
    from trace_engine.doctor import DoctorReport

    monkeypatch.setattr(
        "trace_engine.doctor.run_doctor",
        lambda project_root=None: DoctorReport(items=[], all_critical_passed=True),
    )
    res = runner.invoke(app, ["--doctor"])
    assert res.exit_code == 0
    assert "Doctor" in res.output


def test_cli_doctor_aliases(runner, monkeypatch):
    from trace_engine.doctor import DoctorReport

    monkeypatch.setattr(
        "trace_engine.doctor.run_doctor",
        lambda project_root=None: DoctorReport(items=[], all_critical_passed=True),
    )
    for alias in ["doctor", "diagnose", "health"]:
        res = runner.invoke(app, [alias])
        assert res.exit_code == 0
        assert "Doctor" in res.output


def test_cli_upgrade_flag(runner, monkeypatch):
    monkeypatch.setattr(
        "trace_engine.updater.check_for_updates",
        lambda force=True: {"update_available": False},
    )
    for flag in ["--upgrade", "--update"]:
        res = runner.invoke(app, [flag])
        assert res.exit_code == 0
        assert "up to date" in res.output or "Checking for TRACE updates" in res.output


def test_cli_upgrade_cmd(runner, monkeypatch):
    monkeypatch.setattr(
        "trace_engine.updater.check_for_updates",
        lambda force=True: {"update_available": False},
    )
    for cmd in ["upgrade", "update"]:
        res = runner.invoke(app, [cmd])
        assert res.exit_code == 0
        assert "up to date" in res.output or "Checking for TRACE updates" in res.output


def test_cli_epics_with_real_fixtures(runner):
    fixture_dir = Path("testbed_hardcore")
    if not fixture_dir.exists():
        pytest.skip("testbed_hardcore fixture missing")
    for cmd in ["endpoints", "epics", "eps", "routes"]:
        res = runner.invoke(app, [cmd, str(fixture_dir)])
        assert res.exit_code == 0
        assert "Discovered Application Endpoints" in res.output
        assert "/api/v1/anal" in res.output
        assert "Total endpoints discovered:" in res.output


def test_node_launcher_version():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed on PATH")
    for flag in ["--version", "-v", "version"]:
        res = subprocess.run(
            [node, "bin/trace.js", flag],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert res.returncode == 0
        assert trace_engine.__version__ in res.stdout


def test_node_launcher_flag_normalization():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed on PATH")
    env = {**os.environ, "PYTHONPATH": "src", "PYTHONIOENCODING": "utf-8"}

    res_upg = subprocess.run(
        [node, "bin/trace.js", "--upgrade"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    assert res_upg.returncode == 0
    assert "Checking for TRACE updates" in res_upg.stdout

    res_help = subprocess.run(
        [node, "bin/trace.js", "help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    assert res_help.returncode == 0
    assert "Threat Reconnaissance" in res_help.stdout or "doctor" in res_help.stdout


def test_cli_upgrade_when_update_available(runner, monkeypatch):
    monkeypatch.setattr(
        "trace_engine.updater.check_for_updates",
        lambda force=True: {
            "update_available": True,
            "current_version": trace_engine.__version__,
            "latest_version": "9.9.9",
            "command": "npm install -g trace-sec@latest",
        },
    )
    res = runner.invoke(app, ["--upgrade"])
    assert res.exit_code == 0
    assert "9.9.9" in res.output or "Update Available" in res.output

    res2 = runner.invoke(app, ["upgrade"])
    assert res2.exit_code == 0
    assert "9.9.9" in res2.output or "Update Available" in res2.output


def test_node_launcher_doctor():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed on PATH")
    env = {**os.environ, "PYTHONPATH": "src", "PYTHONIOENCODING": "utf-8"}
    res = subprocess.run(
        [node, "bin/trace.js", "--doctor"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )
    assert res.returncode == 0
    assert "Doctor" in res.stdout
