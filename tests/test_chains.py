"""Unit tests for chain-mode escalation and APM choke points."""

from types import SimpleNamespace

from trace_engine.testpacks.chain import (
    harvest_markers,
    substitute_param,
    escalate_chains,
)
from trace_engine.testpacks.base import TestContext
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType


def _obs(body, status=200):
    return RuntimeObservation(
        request_method="GET",
        request_url="http://127.0.0.1:18080/api/x",
        response_status=status,
        response_body=body,
        latency_ms=5.0,
    )


class _StubClient:
    def __init__(self, bodies):
        self._bodies = list(bodies)
        self.calls = []

    def execute(self, method="GET", url="", headers=None, **kwargs):
        self.calls.append(url)
        body = self._bodies.pop(0) if self._bodies else "{}"
        return _obs(body)


def _ctx():
    return TestContext(target_base_url="http://127.0.0.1:18080", active_tokens={"user-b": "tok-b"})


def _finding(fid, bodies):
    return SimpleNamespace(
        id=fid, runtime_evidence=[], observations=[_obs(b) for b in bodies]
    )


def test_harvest_markers_extracts_identifiers():
    markers = harvest_markers(['{"email": "a@x.com", "id": "order-99"}'])
    assert "a@x.com" in markers
    assert "order-99" in markers
    assert harvest_markers(["{}"]) == []
    assert harvest_markers([]) == []


def test_substitute_param_styles():
    assert substitute_param("/api/users/{id}", "42") == "/api/users/42"
    assert substitute_param("/api/users/:id", "42") == "/api/users/42"
    assert substitute_param("/api/health", "42") == "/api/health"


def test_escalate_chains_finds_echo():
    leaked_body = '{"id": "order-99", "owner": "user-a@x.com"}'
    findings = [_finding("TR-BOLA-001", [leaked_body])]
    client = _StubClient([leaked_body])
    hits = escalate_chains([("GET", "/api/orders/{id}")], findings, client, _ctx())
    assert len(hits) == 1
    assert hits[0]["from_finding"] == "TR-BOLA-001"
    assert hits[0]["marker"] in ("order-99", "user-a@x.com")
    assert any("order-99" in c or "user-a@x.com" in c for c in client.calls)


def test_escalate_chains_skips_paramless_routes():
    findings = [_finding("TR-BOLA-001", ['{"id": "order-99"}'])]
    client = _StubClient(['{"id": "order-99"}'])
    hits = escalate_chains([("GET", "/api/health")], findings, client, _ctx())
    assert hits == []
    assert client.calls == []


def test_escalate_chains_respects_limit_and_errors():
    findings = [_finding("TR-BOLA-001", ['{"id": "order-99"}'])]

    class _Boom:
        def execute(self, *a, **k):
            raise ConnectionError("down")

    hits = escalate_chains([("GET", "/api/a/{id}"), ("GET", "/api/b/{id}")], findings, _Boom(), _ctx())
    assert hits == []

    bodies = ['{"other": 1}'] * 30
    hits = escalate_chains(
        [("GET", "/api/a/{id}"), ("GET", "/api/b/{id}")],
        findings,
        _StubClient(bodies),
        _ctx(),
        limit=3,
    )
    assert hits == []


def _chain_graph():
    g = AttackPathModel(name="t")
    for nid, ntype in [("e1", NodeType.ENDPOINT), ("h", NodeType.FUNCTION), ("s", NodeType.DATABASE)]:
        g.add_node(APMNode(id=nid, node_type=ntype, label=nid))
    g.add_edge(APMEdge(source_id="e1", target_id="h", edge_type=EdgeType.ROUTES_TO))
    g.add_edge(APMEdge(source_id="h", target_id="s", edge_type=EdgeType.ACCESSES))
    return g


def test_choke_points_ranks_middle_node():
    g = _chain_graph()
    points = g.choke_points(limit=5)
    assert points
    assert points[0]["node"] == "h"
    assert points[0]["betweenness"] > 0


def test_choke_points_empty_graph():
    assert AttackPathModel(name="t").choke_points() == []


def test_minimum_cut_size_sane():
    size = _chain_graph().minimum_cut_size()
    assert size is None or isinstance(size, int)
    assert AttackPathModel(name="t").minimum_cut_size() is None
