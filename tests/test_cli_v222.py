"""End-to-end CLI behavior for the 2.2.2 pipeline: gate, baseline, suppression, extras."""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trace_engine.cli import app

APP = '''
from flask import Flask, request

app = Flask(__name__)


@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    cur.execute("SELECT * FROM items WHERE name = '" + name + "'")
    return "ok"
'''

AWS = "AKIAIOSFODNN7EXAMPLQ"


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "app.py").write_text(APP, encoding="utf-8")
    return repo


def run(args):
    return CliRunner().invoke(app, args)


def scan_json(repo: Path, *extra):
    out = repo.parent / "out.json"
    res = run(["scan", str(repo), "--no-models", "-f", "json", "-o", str(out), *extra])
    return res, (json.loads(out.read_text(encoding="utf-8")) if out.exists() else None)


def test_scan_reports_taint_flow_with_identity_and_priority(project):
    res, findings = scan_json(project)
    assert res.exit_code == 0, res.output
    inj = [f for f in findings if f["category"] == "INJECTION"]
    assert len(inj) == 1
    f = inj[0]
    assert len(f["fingerprint"]) == 16 and f["cwe"] and f["priority_tier"] in {"P0", "P1", "P2", "P3"}
    assert any("Tainted data flow" in e for e in f["static_evidence"])
    assert "mitigation" not in f


def test_fail_on_gates_and_baseline_ignores_known_findings(project):
    res, _ = scan_json(project, "--fail-on", "high")
    assert res.exit_code == 1 and "Gate failed" in res.output

    baseline = project.parent / "out.json"
    res2 = run(["scan", str(project), "--no-models", "-f", "json", "-o", str(project.parent / "b.json"),
                "--fail-on", "high", "--baseline", str(baseline)])
    assert res2.exit_code == 0, res2.output
    assert "0 new" in res2.output


def test_baseline_flags_a_new_finding(project):
    scan_json(project)
    baseline = project.parent / "out.json"
    (project / "other.py").write_text(APP.replace("lookup", "find").replace("/find", "/find2"), encoding="utf-8")
    res = run(["scan", str(project), "--no-models", "-f", "json", "-o", str(project.parent / "n.json"),
               "--fail-on", "high", "--baseline", str(baseline)])
    assert res.exit_code == 1
    assert "new" in res.output


def test_suppression_file_hides_a_finding(project):
    _, findings = scan_json(project)
    fp = next(f["fingerprint"] for f in findings if f["category"] == "INJECTION")
    (project / ".trace-suppress.toml").write_text(
        f'[[suppress]]\nfingerprint = "{fp}"\nreason = "accepted in review"\n', encoding="utf-8"
    )
    res, after = scan_json(project, "--fail-on", "high")
    assert res.exit_code == 0, res.output
    assert not [f for f in after if f["fingerprint"] == fp]
    assert (project / ".trace" / "suppressed.json").is_file()
    assert "Suppressed" in res.output
    res3, again = scan_json(project, "--no-suppress")
    assert [f for f in again if f["fingerprint"] == fp]


def test_junit_output_is_valid_and_marks_failures(project):
    out = project.parent / "r.xml"
    res = run(["scan", str(project), "--no-models", "-f", "junit", "-o", str(out)])
    assert res.exit_code == 0, res.output
    root = ET.fromstring(out.read_text(encoding="utf-8"))
    assert int(root.attrib["tests"]) >= 1 and int(root.attrib["failures"]) >= 1


def test_secrets_flag_adds_findings_and_flips_coverage_row(project):
    (project / ".env").write_text(f"AWS_KEY={AWS}\n", encoding="utf-8")
    res, findings = scan_json(project, "--secrets")
    assert res.exit_code == 0, res.output
    secret = [f for f in findings if f["category"] == "SECRETS"]
    assert len(secret) == 1 and AWS not in json.dumps(findings)
    md = project.parent / "r.md"
    run(["scan", str(project), "--no-models", "--secrets", "-f", "markdown", "-o", str(md)])
    text = md.read_text(encoding="utf-8")
    assert "Hardcoded Secrets / API Keys | **ASSESSED**" in text
    assert "Software Dependencies / CVEs | *NOT ASSESSED*" in text


def test_dry_run_sends_and_saves_nothing(project):
    res = run(["scan", str(project), "--no-models", "--dry-run"])
    assert res.exit_code == 0, res.output
    assert "Planned probes" in res.output and "Nothing was" in res.output
    assert not (project / ".trace" / "findings.json").exists()


def test_audit_reports_spec_inventory(project):
    (project / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0", "info": {"title": "x"},
        "paths": {"/lookup": {"get": {}}, "/documented/only": {"get": {}}},
    }), encoding="utf-8")
    res = run(["audit", str(project), "--no-models", "-f", "json"])
    assert res.exit_code == 0, res.output
    start = res.output.index("{")
    payload = json.loads(res.output[start:res.output.rindex("}") + 1])
    assert payload["inventory"]["documented_not_in_code"] == ["GET /documented/only"]
    assert payload["mitigation"]["total_paths"] >= 0


def test_scan_notes_skipped_non_code_files(project):
    (project / "index.html").write_text("<html></html>", encoding="utf-8")
    (project / "data.json").write_text("{}", encoding="utf-8")
    res = run(["scan", str(project), "--no-models"])
    assert "skipped 2 non-code files" in res.output


def test_invalid_fail_on_value_is_a_clear_error(project):
    res = run(["scan", str(project), "--no-models", "--fail-on", "nope"])
    assert res.exit_code != 0
