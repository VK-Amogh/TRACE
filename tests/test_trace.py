"""Comprehensive test suite for TRACE core modules."""

from pathlib import Path
import pytest
from trace_engine.ingest.repository import RepositoryScanner
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.fastapi import FastAPIFrameworkAdapter
from trace_engine.apm.builder import APMBuilder
from trace_engine.apm.model import AttackPathModel
from trace_engine.security.hypotheses import HypothesisEngine
from trace_engine.policy.scope import ScopeGuard, ScopeViolationError
from trace_engine.findings.model import Finding, Severity, FindingConfidence
from trace_engine.findings.store import FindingStore


def test_scope_guard_local_allowed():
    guard = ScopeGuard()
    assert guard.validate_url("http://127.0.0.1:8000/api/users")
    assert guard.validate_url("http://localhost:18080/health")


def test_scope_guard_external_rejected():
    guard = ScopeGuard()
    with pytest.raises(ScopeViolationError):
        guard.validate_url("https://google.com/malicious")

    with pytest.raises(ScopeViolationError):
        guard.validate_url("http://198.51.100.1/exploit")


def test_parser_python():
    parser = CodeParser()
    sample_code = """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get('/api/items/{item_id}')
def read_item(item_id: str):
    return {'id': item_id}
"""
    parsed = parser.parse("test.py", sample_code, "python")
    assert len(parsed.imports) >= 1
    assert len(parsed.functions) == 1
    assert parsed.functions[0].name == "read_item"


def test_fastapi_adapter():
    parser = CodeParser()
    sample_code = """
from fastapi import FastAPI, Depends

app = FastAPI()

@app.get('/api/orders/{id}')
def get_order(id: str):
    return {'id': id}
"""
    parsed = parser.parse("test.py", sample_code, "python")
    adapter = FastAPIFrameworkAdapter()
    assert adapter.can_handle(parsed)
    endpoints = adapter.extract_endpoints(parsed, sample_code)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.method == "GET"
    assert ep.path == "/api/orders/{id}"
    assert ep.object_identifier is True


def test_apm_builder(tmp_path):
    parser = CodeParser()
    sample_code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/api/data')
def get_data():
    return {'status': 'ok'}
"""
    parsed = parser.parse("test.py", sample_code, "python")
    adapter = FastAPIFrameworkAdapter()
    endpoints = adapter.extract_endpoints(parsed, sample_code)

    builder = APMBuilder(project_name="test_proj")
    apm = builder.build(tmp_path, [], [parsed], endpoints)

    assert apm.graph.number_of_nodes() > 0
    summary = apm.summary()
    assert "Endpoint" in summary["nodes_by_type"]


def test_findings_store(tmp_path):
    store = FindingStore(tmp_path)
    finding = Finding(
        id="TR-001",
        title="Test Finding",
        category="BOLA",
        severity=Severity.HIGH,
        confidence=FindingConfidence.CONFIRMED,
        endpoint="GET /api/test",
        correlation_notes="Matched",
        remediation="Fix it",
    )
    store.save_findings([finding])
    loaded = store.load_findings()
    assert len(loaded) == 1
    assert loaded[0].id == "TR-001"
    assert loaded[0].category == "BOLA"
