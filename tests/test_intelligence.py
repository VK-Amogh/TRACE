"""Tests for Intelligence stack: Laya, SecureBERT, and Verification."""

import pytest
from trace_engine.intelligence.laya.router import LayaDecisionEngine
from trace_engine.intelligence.securebert.classifier import SecureBERTClassifier
from trace_engine.intelligence.orchestrator import IntelligenceOrchestrator
from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.parsing.locations import SourceLocation
from trace_engine.apm.model import AttackPathModel
from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory
from trace_engine.mcp.server import TraceMCPServer


def test_laya_decision_engine():
    engine = LayaDecisionEngine()
    ep = Endpoint(
        id="ep_test",
        method="GET",
        path="/api/orders/{id}",
        handler_name="get_order",
        auth_required=True,
        object_identifier=True,
        database_access=True,
        source=SourceLocation(file="test.py", line_start=1, line_end=5),
    )
    apm = AttackPathModel()
    priority = engine.decide_priority(ep, apm)
    assert isinstance(priority.should_test, bool)
    assert priority.priority_level in ("critical", "high", "medium", "low")


def test_securebert_classifier():
    classifier = SecureBERTClassifier()
    ep = Endpoint(
        id="ep_test",
        method="GET",
        path="/api/orders/{id}",
        handler_name="get_order",
        object_identifier=True,
        database_access=True,
        source=SourceLocation(file="test.py", line_start=1, line_end=5),
    )
    scores = classifier.classify_slice("order = db.query(Order).filter(id=id).first()", ep)
    assert "BOLA" in scores
    assert scores["BOLA"] > 0.0


def test_mcp_server_protocol():
    server = TraceMCPServer()
    init_res = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_res["result"]["serverInfo"]["name"] == "trace-security-mcp"

    list_res = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = [t["name"] for t in list_res["result"]["tools"]]
    assert "trace_scan" in tools
    assert "trace_findings" in tools
    assert "trace_verify" in tools
