"""Scan-scope profiles: full/app/fixtures separation without silent hiding."""

from pathlib import Path

from trace_engine.ingest.scan_scope import (
    FIXTURE_DIR_PATTERNS,
    VALID_PROFILES,
    resolve_scope,
    scoped_scanner,
)


def _make_repo(tmp_path: Path) -> Path:
    (tmp_path / "src" / "app").mkdir(parents=True)
    (tmp_path / "src" / "app" / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/hi')\ndef hi(): return {}\n",
        encoding="utf-8",
    )
    (tmp_path / "labs" / "vuln").mkdir(parents=True)
    (tmp_path / "labs" / "vuln" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x(): pass\n", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.md").write_text("# notes\n", encoding="utf-8")
    return tmp_path


def test_profiles_are_explicit_and_known():
    assert set(VALID_PROFILES) == {"full", "app", "fixtures"}
    assert "labs" in FIXTURE_DIR_PATTERNS and "tests" in FIXTURE_DIR_PATTERNS


def test_full_scope_reproduces_unfiltered_scan(tmp_path):
    repo = _make_repo(tmp_path)
    scanner, result = scoped_scanner(repo, "full")
    files = scanner.scan()
    paths = {f.path for f in files}
    assert "src/app/main.py" in paths
    assert "labs/vuln/app.py" in paths
    assert "tests/test_x.py" in paths
    assert result.excluded_top_dirs == {}


def test_app_scope_excludes_fixture_dirs_and_reports_why(tmp_path):
    repo = _make_repo(tmp_path)
    scanner, result = scoped_scanner(repo, "app")
    paths = {f.path for f in scanner.scan()}
    assert "src/app/main.py" in paths
    assert "labs/vuln/app.py" not in paths
    assert "tests/test_x.py" not in paths
    assert "labs" in result.excluded_top_dirs
    assert "tests" in result.excluded_top_dirs
    assert result.excluded_top_dirs["labs"] == "fixture/test directory pattern"
    assert any("labs" in line for line in result.summary_lines())


def test_fixtures_scope_scans_only_fixture_dirs(tmp_path):
    repo = _make_repo(tmp_path)
    scanner, result = scoped_scanner(repo, "fixtures")
    paths = {f.path for f in scanner.scan()}
    assert "labs/vuln/app.py" in paths
    assert "tests/test_x.py" in paths
    assert "src/app/main.py" not in paths
    assert "src" in result.excluded_top_dirs


def test_traceignore_still_honored_in_every_profile(tmp_path):
    repo = _make_repo(tmp_path)
    (repo / ".traceignore").write_text("src/app/main.py\n", encoding="utf-8")
    for profile in ("full", "app", "fixtures"):
        scanner, _ = scoped_scanner(repo, profile)
        paths = {f.path for f in scanner.scan()}
        assert "src/app/main.py" not in paths


def test_unknown_profile_rejected(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        resolve_scope(tmp_path, "everything")


def test_fixtures_profile_on_fixture_repo_scans_it_whole(tmp_path):
    # A benchmark fixture repo has no fixture-named top dirs; the fixtures
    # profile must scan it whole (with a note), not return a silent empty scan.
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "routes.dart").write_text("router.get('/x', h);\n", encoding="utf-8")
    scanner, result = scoped_scanner(tmp_path, "fixtures")
    paths = {f.path for f in scanner.scan()}
    assert "lib/routes.dart" in paths
    assert result.excluded_top_dirs == {}
    assert "whole target" in result.note


def test_mcp_rejects_unknown_scope_without_traceback():
    from trace_engine.mcp.server import TraceMCPServer

    res = TraceMCPServer().execute_tool(
        "trace_scan", {"repository": ".", "scope": "bogus", "target": "http://127.0.0.1:9"}
    )
    assert res["status"] == "error"
    assert "bogus" in res["error"]


def test_mcp_refuses_out_of_scope_target_without_fetch():
    from unittest.mock import patch

    from trace_engine.mcp.server import TraceMCPServer

    with patch("httpx.Client") as cli:
        res = TraceMCPServer().execute_tool(
            "trace_scan", {"repository": ".", "scope": "full", "target": "http://evil.com/"}
        )
        assert res["status"] == "refused"
        cli.assert_not_called()


def test_path_provenance_detection():
    from trace_engine.ingest.scan_scope import is_fixture_path, get_path_provenance

    # Fixture paths
    assert is_fixture_path("tests/test_x.py") is True
    assert is_fixture_path("labs/vuln/app.py") is True
    assert is_fixture_path("testbed_hardcore/server.py") is True
    assert is_fixture_path("test-repository/main.py") is True
    assert is_fixture_path(Path("tests/unit/test_auth.py")) is True
    assert get_path_provenance("tests/test_x.py") == "fixture/test"
    assert get_path_provenance("labs/testbed.py") == "fixture/test"

    # Application paths
    assert is_fixture_path("src/trace_engine/cli.py") is False
    assert is_fixture_path("backend/api/users.py") is False
    assert is_fixture_path(None) is False
    assert get_path_provenance("src/trace_engine/cli.py") == "application"
    assert get_path_provenance(None) == "application"


def test_finding_model_provenance_fields():
    from trace_engine.findings.model import Finding, FindingConfidence, Severity

    f = Finding(
        id="FIND-001",
        title="Test Finding",
        category="BOLA",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/test",
        correlation_notes="AST match",
        remediation="Fix it",
    )
    assert f.provenance == "application"
    assert f.is_fixture is False

    f_fixture = Finding(
        id="FIND-002",
        title="Fixture Finding",
        category="BFLA",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/admin/export",
        correlation_notes="AST match",
        remediation="Fix it",
        provenance="fixture/test",
        is_fixture=True,
    )
    assert f_fixture.provenance == "fixture/test"
    assert f_fixture.is_fixture is True


def test_correlator_assigns_provenance():
    from trace_engine.findings.correlate import EvidenceCorrelator
    from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory, Severity
    from trace_engine.parsing.locations import SourceLocation
    from trace_engine.apm.model import AttackPathModel

    correlator = EvidenceCorrelator()
    apm = AttackPathModel()

    # Fixture hypothesis
    hyp_fix = SecurityHypothesis(
        id="HYP-01",
        category=VulnerabilityCategory.BOLA,
        severity=Severity.HIGH,
        title="BOLA in Fixture",
        description="test",
        endpoint_id="ep-1",
        endpoint_display="POST /api/order/{id}",
        recommended_test_pack="bola_pack",
        source_location=SourceLocation(file="tests/testbed_hardcore/app.py", line_start=10, line_end=20),
    )
    finding_fix = correlator.correlate(hyp_fix, test_result=None, apm=apm)
    assert finding_fix.provenance == "fixture/test"
    assert finding_fix.is_fixture is True

    # Application hypothesis
    hyp_app = SecurityHypothesis(
        id="HYP-02",
        category=VulnerabilityCategory.BFLA,
        severity=Severity.HIGH,
        title="BFLA in Core App",
        description="test",
        endpoint_id="ep-2",
        endpoint_display="GET /api/v1/admin",
        recommended_test_pack="bfla_pack",
        source_location=SourceLocation(file="src/trace_engine/server.py", line_start=50, line_end=60),
    )
    finding_app = correlator.correlate(hyp_app, test_result=None, apm=apm)
    assert finding_app.provenance == "application"
    assert finding_app.is_fixture is False


def test_zero_endpoints_terminal_honest_messaging(monkeypatch):
    import io
    from rich.console import Console
    from trace_engine.output import terminal

    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=False, width=120)
    monkeypatch.setattr(terminal, "console", test_console)

    terminal.print_findings_table([], endpoints_count=0)
    output = buf.getvalue()

    assert "No endpoints detected in scanned target" in output
    assert "Endpoint-based checks were not applicable" in output
    assert "Zero endpoint findings does NOT mean the target has no vulnerabilities or is secure" in output
    assert "NOT APPLICABLE" in output
    assert "NOT ASSESSED" in output
    assert "No findings in the checks performed (no endpoints detected)" in output


def test_zero_endpoints_test_all_honest_messaging(monkeypatch):
    import io
    from rich.console import Console
    from trace_engine.output import terminal

    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=False, width=120)
    monkeypatch.setattr(terminal, "console", test_console)

    terminal.print_test_all_report([], endpoints_count=0, hypotheses_count=0, confirmed_count=0)
    output = buf.getvalue()

    assert "Zero endpoints detected in target scope" in output
    assert "Endpoint-based checks were not applicable" in output
    assert "Zero endpoint findings does NOT mean the codebase is secure" in output
    assert "UNASSESSED - 0 ENDPOINTS DETECTED" in output
    assert "100/100" not in output
    assert "A (SECURE)" not in output


def test_zero_endpoints_markdown_report_honest_messaging():
    from trace_engine.output.markdown import generate_markdown_report

    md = generate_markdown_report([], project_name="ZeroApp", endpoints_count=0)
    assert "Audited Endpoints:** `0` (No endpoints detected)" in md
    assert "No findings in the checks performed (no endpoints detected)" in md
    assert "Endpoint & Route Invariants | **NOT APPLICABLE**" in md
    assert "Hardcoded Secrets / API Keys | *NOT ASSESSED*" in md
    assert "Software Dependencies / CVEs | *NOT ASSESSED*" in md
    assert "Zero endpoints detected in target scope" in md
    assert "Zero endpoint findings does **not** mean the codebase has no vulnerabilities or is secure" in md


def test_endpoints_present_with_no_findings():
    from trace_engine.output.markdown import generate_markdown_report

    md = generate_markdown_report([], project_name="CleanApp", endpoints_count=5)
    assert "Audited Endpoints:** `5`" in md
    assert "No findings in the checks performed across 5 evaluated endpoint(s)" in md
    assert "Endpoint & Route Invariants | **ASSESSED**" in md
    assert "Evaluated 5 HTTP route(s)" in md


def test_fixture_findings_provenance_and_disclaimer():
    from trace_engine.output.markdown import generate_markdown_report
    from trace_engine.findings.model import Finding, FindingConfidence, Severity

    f1 = Finding(
        id="FIND-APP",
        title="App Vulnerability",
        category="BOLA",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/api/data",
        correlation_notes="AST match",
        remediation="Fix app auth",
        provenance="application",
        is_fixture=False,
    )
    f2 = Finding(
        id="FIND-FIX",
        title="Lab Testbed Vulnerability",
        category="BFLA",
        severity=Severity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="/testbed/admin",
        correlation_notes="AST match",
        remediation="Fix fixture",
        provenance="fixture/test",
        is_fixture=True,
    )

    md = generate_markdown_report([f1, f2], project_name="MixedRepo", endpoints_count=2)
    assert "Scope & Provenance Notice" in md
    assert "These establish detections in test/lab assets, NOT vulnerabilities in TRACE application code" in md
    assert "| `FIND-APP` | **HIGH** | CONFIRMED | BOLA | Application |" in md
    assert "| `FIND-FIX` | **CRITICAL** | CONFIRMED | BFLA | Fixture/Test |" in md

