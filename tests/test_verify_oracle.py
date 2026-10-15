"""Unit tests for the verification oracle verdict matrix.

No network, no models: the registry is stubbed and the repo is an empty
tmp dir, so re-indexing never reproduces the hypothesis statically.
"""

from pathlib import Path

import trace_engine.verify as verify_mod
from trace_engine.verify import VerificationEngine, VerificationStatus
from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.findings.store import FindingStore
from trace_engine.testpacks.base import TestExecutionResult
from trace_engine.runtime.observations import RuntimeObservation


def _finding():
    return Finding(
        id="TR-BOLA-001",
        title="t",
        category="bola",
        severity=Severity.HIGH,
        confidence=FindingConfidence.HIGH,
        endpoint="GET /api/items/{id}",
        attack_path=[],
        static_evidence=[],
        runtime_evidence=[],
        correlation_notes="",
        remediation="scope to tenant",
        reproduction_steps=[],
        observations=[],
        root_cause="",
        short_action="scope lookup",
    )


def _obs(status):
    return RuntimeObservation(
        request_method="GET",
        request_url="http://127.0.0.1:18080/api/items/1",
        response_status=status,
        response_body="{}",
        latency_ms=5.0,
    )


class _FakePack:
    def __init__(self, confirmed, statuses):
        self._confirmed = confirmed
        self._statuses = statuses

    def execute(self, hyp, client, context):
        return TestExecutionResult(
            testpack_name="bola",
            hypothesis_id=hyp.id,
            confirmed=self._confirmed,
            confidence=0.98 if self._confirmed else 0.2,
            summary="fake",
            observations=[_obs(s) for s in self._statuses],
            reproduction_steps=[],
        )


class _FakeRegistry:
    def __init__(self, pack):
        self._pack = pack

    def get(self, name):
        return self._pack


def _engine(tmp_path, pack, monkeypatch):
    (tmp_path / ".trace").mkdir(exist_ok=True)
    FindingStore(tmp_path / ".trace").save_findings([_finding()])
    monkeypatch.setattr(verify_mod, "default_registry", _FakeRegistry(pack))
    return VerificationEngine(repo_path=tmp_path, target_url="http://127.0.0.1:18080")


def test_missing_finding_is_inconclusive(tmp_path, monkeypatch):
    (tmp_path / ".trace").mkdir(exist_ok=True)
    engine = VerificationEngine(repo_path=tmp_path)
    res = engine.verify("TR-NOPE-000")
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.remediation_verified is False


def test_confirmed_exploit_is_still_present(tmp_path, monkeypatch):
    engine = _engine(tmp_path, _FakePack(True, [200, 200]), monkeypatch)
    res = engine.verify("TR-BOLA-001")
    assert res.status == VerificationStatus.STILL_PRESENT
    assert res.remediation_verified is False


def test_clean_reachable_target_is_fixed(tmp_path, monkeypatch):
    engine = _engine(tmp_path, _FakePack(False, [200, 404]), monkeypatch)
    res = engine.verify("TR-BOLA-001")
    assert res.status == VerificationStatus.FIXED
    assert res.remediation_verified is True


def test_unreachable_target_is_inconclusive(tmp_path, monkeypatch):
    engine = _engine(tmp_path, _FakePack(False, [0, 0]), monkeypatch)
    res = engine.verify("TR-BOLA-001")
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.remediation_verified is False


def test_missing_pack_is_inconclusive(tmp_path, monkeypatch):
    engine = _engine(tmp_path, None, monkeypatch)
    res = engine.verify("TR-BOLA-001")
    assert res.status == VerificationStatus.INCONCLUSIVE
    assert res.remediation_verified is False


def test_reports_last_nonzero_status(tmp_path, monkeypatch):
    engine = _engine(tmp_path, _FakePack(False, [0, 403]), monkeypatch)
    res = engine.verify("TR-BOLA-001")
    assert res.runtime_status_after == 403
