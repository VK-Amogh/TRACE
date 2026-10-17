"""Fingerprints, scoring, suppression, baseline diff, CI gate and JUnit."""

import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path

import pytest

from trace_engine.findings.baseline import blocking_findings, diff_findings, load_baseline
from trace_engine.findings.fingerprint import compute_fingerprint, normalize_endpoint
from trace_engine.findings.model import Finding, FindingConfidence, Severity
from trace_engine.findings.scoring import score_finding, tier_for
from trace_engine.findings.store import FindingStore
from trace_engine.findings.suppress import (
    SUPPRESS_FILE,
    SuppressionRule,
    apply_suppressions,
    load_rules,
)
from trace_engine.output.junit import generate_junit_report
from trace_engine.parsing.locations import SourceLocation


def make(
    fid="TR-BOLA-001",
    category="BOLA",
    endpoint="GET /api/items/{id}",
    file="C:/repo/app/api.py",
    severity=Severity.HIGH,
    confidence=FindingConfidence.HIGH,
    title="Potential BOLA on GET /api/items/{id}",
    **kw,
):
    return Finding(
        id=fid, title=title, category=category, severity=severity, confidence=confidence,
        endpoint=endpoint, source_location=SourceLocation(file=file, line_start=10, line_end=12),
        correlation_notes="n", remediation="r", **kw,
    )


def test_fingerprint_survives_id_param_name_line_and_machine_changes():
    a = make(fid="TR-BOLA-001", endpoint="GET /api/items/{id}", file="C:/Users/a/repo/app/api.py")
    b = make(fid="TR-BOLA-007", endpoint="get /api/Items/{item_id}/", file="/home/ci/work/app/api.py")
    assert a.fingerprint == b.fingerprint
    assert len(a.fingerprint) == 16


def test_fingerprint_differs_for_different_flaws():
    base = make()
    assert base.fingerprint != make(category="BFLA").fingerprint
    assert base.fingerprint != make(endpoint="GET /api/orders/{id}").fingerprint
    assert base.fingerprint != make(file="C:/repo/app/other.py").fingerprint


def test_normalize_endpoint_handles_non_routes():
    assert normalize_endpoint("POST /Users/<int:uid>/") == "POST /users/{}"
    assert normalize_endpoint("Authentication Module (verify_password)").startswith("authentication")
    assert compute_fingerprint("SECRETS", "app/.env:3", "app/.env", "Hardcoded secret")


def test_taxonomy_and_priority_are_derived():
    f = make(static_evidence=["Declared auth required: False", "password reset"])
    assert f.cwe == "CWE-639" and f.owasp == "API1:2023"
    assert 0 < f.priority_score <= 100
    assert f.priority_tier in {"P0", "P1", "P2", "P3"}
    assert f.score_factors["unauthenticated"] == 15
    assert f.score_factors["sensitive_data"] == 8


def test_score_is_deterministic_and_orders_by_evidence():
    kwargs = dict(category="INJECTION", severity="CRITICAL", title="x")
    confirmed, _, _ = score_finding(confidence="CONFIRMED", **kwargs)
    potential, _, _ = score_finding(confidence="POTENTIAL", **kwargs)
    fixture, factors, _ = score_finding(confidence="CONFIRMED", is_fixture=True, **kwargs)
    assert confirmed > potential
    assert fixture == confirmed - 30 and factors["fixture_or_test_code"] == -30
    assert score_finding(confidence="HIGH", **kwargs) == score_finding(confidence="HIGH", **kwargs)
    assert tier_for(80) == "P0" and tier_for(10) == "P3"


def test_command_injection_gets_cwe_78():
    f = make(category="INJECTION", title="Command injection via shell")
    assert f.cwe == "CWE-78"


def test_store_finds_by_fingerprint_prefix(tmp_path: Path):
    f = make()
    store = FindingStore(tmp_path / ".trace")
    store.save_findings([f])
    assert store.get_finding_by_id(f.fingerprint).id == f.id
    assert store.get_finding_by_id(f.fingerprint[:8]).id == f.id
    assert store.get_finding_by_id("TR-BOLA-001").id == f.id


def _write_rules(repo: Path, body: str) -> None:
    (repo / SUPPRESS_FILE).write_text(body, encoding="utf-8")


def test_suppression_by_fingerprint_category_and_path(tmp_path: Path):
    a = make(fid="TR-BOLA-001")
    b = make(fid="TR-CORS-002", category="CORS", endpoint="GET /x", file="C:/repo/examples/demo/app.py")
    c = make(fid="TR-BFLA-003", category="BFLA", endpoint="POST /admin")
    _write_rules(tmp_path, f"""
[[suppress]]
fingerprint = "{a.fingerprint}"
reason = "accepted"

[[suppress]]
category = "CORS"
path = "examples/**"
reason = "demo code"
""")
    rules, warnings = load_rules(tmp_path)
    assert warnings == [] and len(rules) == 2
    res = apply_suppressions([a, b, c], rules)
    assert [f.id for f in res.active] == ["TR-BFLA-003"]
    assert {f.id for f in res.suppressed} == {"TR-BOLA-001", "TR-CORS-002"}
    assert res.reasons[a.fingerprint] == "accepted"


def test_invalid_suppressions_are_ignored_with_warnings(tmp_path: Path):
    _write_rules(tmp_path, """
[[suppress]]
category = "BOLA"

[[suppress]]
reason = "no selector"

[[suppress]]
path = "**"
reason = "everything"

[[suppress]]
fingerprint = "abc"
reason = "too short"
""")
    rules, warnings = load_rules(tmp_path)
    assert rules == []
    assert len(warnings) == 4


def test_expired_suppression_is_not_applied(tmp_path: Path):
    f = make()
    rules = [SuppressionRule(fingerprint=f.fingerprint, reason="r", expires=date(2020, 1, 1))]
    res = apply_suppressions([f], rules, today=date(2026, 1, 1))
    assert res.active == [f] and res.suppressed == []
    assert "expired" in res.warnings[0]


def test_baseline_diff_and_roundtrip(tmp_path: Path):
    old_keep, old_gone = make(), make(category="BFLA", endpoint="POST /admin")
    new = make(category="SSRF", endpoint="POST /fetch")
    path = tmp_path / "baseline.json"
    FindingStore(tmp_path / "b").save_findings([old_keep, old_gone])
    path.write_text((tmp_path / "b" / "findings.json").read_text(encoding="utf-8"), encoding="utf-8")
    diff = diff_findings([make(fid="TR-BOLA-009"), new], load_baseline(path))
    assert [f.category for f in diff.new] == ["SSRF"]
    assert [f.category for f in diff.persisted] == ["BOLA"]
    assert [f.category for f in diff.resolved] == ["BFLA"]
    assert diff.summary() == {"new": 1, "persisted": 1, "resolved": 1}


def test_blocking_findings_gate():
    crit_conf = make(severity=Severity.CRITICAL, confidence=FindingConfidence.CONFIRMED)
    high_pot = make(category="SSRF", endpoint="POST /f", severity=Severity.HIGH, confidence=FindingConfidence.POTENTIAL)
    low = make(category="CORS", endpoint="GET /c", severity=Severity.LOW, confidence=FindingConfidence.HIGH)
    fixture = make(category="BFLA", endpoint="POST /a", severity=Severity.CRITICAL,
                   confidence=FindingConfidence.HIGH, is_fixture=True)
    findings = [crit_conf, high_pot, low, fixture]
    assert blocking_findings(findings, None) == []
    assert blocking_findings(findings, "high") == [crit_conf]
    assert set(f.category for f in blocking_findings(findings, "high", min_confidence="potential")) == {"BOLA", "SSRF"}
    assert fixture in blocking_findings(findings, "high", include_fixtures=True)
    with pytest.raises(ValueError):
        blocking_findings(findings, "nope")


def test_junit_report_is_valid_xml_with_failures():
    a, b = make(), make(category="CORS", endpoint="GET /c", title='Wildcard <origin> & "creds"')
    xml = generate_junit_report([a, b], project_name="demo", blocking=[a])
    root = ET.fromstring(xml)
    assert root.attrib["tests"] == "2" and root.attrib["failures"] == "1"
    cases = root.findall(".//testcase")
    assert len(cases) == 2
    assert cases[0].find("failure") is not None
    assert cases[1].find("failure") is None
