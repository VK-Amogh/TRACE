"""Regression test suite verifying bug fixes and edge case resilience."""

import sys
import io
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from trace_engine.policy.scope import ScopeGuard, ScopeViolationError
from trace_engine.runtime.client import ScopedHttpClient
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.parsing.parser import CodeParser
from trace_engine.parsing.locations import SourceLocation
from trace_engine.framework.express import ExpressFrameworkAdapter
from trace_engine.framework.base import Endpoint, EndpointParameter
from trace_engine.intelligence.orchestrator import IntelligenceOrchestrator
from trace_engine.mcp.server import TraceMCPServer
from trace_engine.testpacks.injection import InjectionTestPack
from trace_engine.testpacks.bfla import BflaTestPack
from trace_engine.testpacks.ssrf import SsrfTestPack
from trace_engine.testpacks.base import TestContext
from trace_engine.security.hypotheses import SecurityHypothesis, VulnerabilityCategory


def test_scope_guard_loopback_dynamic_ports():
    guard = ScopeGuard()
    # Any valid TCP port on loopback is permitted
    assert guard.validate_url("http://127.0.0.1:9000/api/test")
    assert guard.validate_url("http://localhost:5173/vite")
    assert guard.validate_url("http://127.0.0.1:8001/app")

    # Invalid port (< 1 or > 65535) is rejected
    with pytest.raises(ScopeViolationError):
        guard.validate_url("http://127.0.0.1:99999/badport")

    # External targets still rejected
    with pytest.raises(ScopeViolationError):
        guard.validate_url("http://attacker.com:9000/bad")


def test_scope_guard_allow_target_dynamic():
    guard = ScopeGuard(allowed_hosts=["my-lab.local"], allowed_ports=[80])
    guard.allow_target("http://my-lab.local:8443/api")
    assert guard.validate_url("http://my-lab.local:8443/api")


def test_scoped_http_client_redirect_protocol_relative():
    guard = ScopeGuard()
    client = ScopedHttpClient(scope_guard=guard)

    # Mock an HTTP redirect with protocol-relative URL to external site
    mock_resp = MagicMock()
    mock_resp.is_redirect = True
    mock_resp.headers = {"location": "//attacker.com/evil"}

    with patch("httpx.Client.request", return_value=mock_resp):
        with pytest.raises(ScopeViolationError):
            client.execute(method="GET", url="http://127.0.0.1:18080/redirect")


def test_express_multiline_and_arrow_functions():
    code = """
const express = require('express');
const app = express();

const userHandler = async (req, res) => {
    const users = await db.query('SELECT * FROM users');
    res.json(users);
};

app.post(
    '/api/orders/:order_id',
    authMiddleware,
    async (req, res) => {
        const data = await axios.get('http://internal/service');
        res.json(data);
    }
);
"""
    parser = CodeParser()
    pf = parser.parse("server.js", code, "javascript")
    adapter = ExpressFrameworkAdapter()
    endpoints = adapter.extract_endpoints(pf, code)

    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.method == "POST"
    assert ep.path == "/api/orders/{order_id}"
    assert ep.auth_required is True
    assert ep.database_access is True
    assert ep.external_network is True
    assert ep.object_identifier is True


def test_orchestrator_empty_bert_scores():
    orchestrator = IntelligenceOrchestrator()
    dummy_ep = Endpoint(
        id="ep_test",
        method="GET",
        path="/api/test",
        handler_name="test_handler",
        auth_required=False,
        source=SourceLocation(file="test.py", line_start=1, line_end=1),
    )
    # Ensure evaluate_endpoint does not crash even if securebert returns empty dict
    with patch.object(orchestrator.securebert, "classify_slice", return_value={}):
        res = orchestrator.evaluate_endpoint(
            endpoint=dummy_ep,
            code_slice="def test(): pass",
            apm=MagicMock(),
            hypotheses=[],
        )
        assert res.endpoint_id == "ep_test"
        assert res.decision_path in ("deterministic", "laya_system1")


def test_mcp_content_length_framing():
    server = TraceMCPServer()
    msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    msg_str = json.dumps(msg)
    framed = f"Content-Length: {len(msg_str)}\r\n\r\n{msg_str}"

    stdin_backup = sys.stdin
    stdout_backup = sys.stdout

    sys.stdin = io.StringIO(framed)
    sys.stdout = io.StringIO()

    try:
        server.run_stdio()
        output = sys.stdout.getvalue().strip()
        res = json.loads(output)
        assert res["id"] == 1
        assert "result" in res
    finally:
        sys.stdin = stdin_backup
        sys.stdout = stdout_backup


def test_testpacks_path_param_replacement():
    client = MagicMock()
    obs = RuntimeObservation(
        request_method="GET",
        request_url="http://127.0.0.1:18080/api/search/1?q=test",
        response_status=200,
        response_body="syntax error near '1'",
        latency_ms=5.0,
    )
    client.execute.return_value = obs

    ctx = TestContext(target_base_url="http://127.0.0.1:18080")
    hyp = SecurityHypothesis(
        id="HYP-INJ-001",
        category=VulnerabilityCategory.INJECTION,
        endpoint_id="ep_1",
        endpoint_display="GET /api/search/{term}",
        title="Test Inj",
        description="Desc",
        recommended_test_pack="injection",
    )

    pack = InjectionTestPack()
    res = pack.execute(hyp, client, ctx)
    # Check that client.execute was called without literal '{term}' in URL
    call_url = client.execute.call_args[1]["url"]
    assert "{term}" not in call_url
    assert "/api/search/1?" in call_url
    assert res.confirmed is True
