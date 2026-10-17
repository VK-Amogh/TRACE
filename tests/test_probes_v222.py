"""ID shapes, owner discovery, oracle, identities, rate limiting and verdict weighting."""

import json

from trace_engine.config.identities import build_context
from trace_engine.config.settings import IdentityConfig, TraceConfig
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.security.hypotheses import (
    HypothesisEngine,
    SecurityHypothesis,
    VulnerabilityCategory,
)
from trace_engine.security.verdict import score_response_pair
from trace_engine.testpacks.base import TestContext
from trace_engine.testpacks.bola import BolaTestPack
from trace_engine.testpacks.idshapes import classify, mutations
from trace_engine.testpacks.rate_limit import BURST, RateLimitTestPack
from trace_engine.testpacks.registry import default_registry
from trace_engine.testpacks.stateful import (
    collection_path,
    extract_created_id,
    extract_ids,
    trailing_param,
)


def O(status=200, body="{}", headers=None, method="GET", url="http://127.0.0.1:8000/x"):
    return RuntimeObservation(
        request_method=method, request_url=url, response_status=status,
        response_body=body, response_headers=headers or {},
    )


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def execute(self, method, url, headers=None, json_body=None, data=None):
        self.calls.append((method, url, dict(headers or {}), json_body))
        return self.handler(method, url, dict(headers or {}), json_body)


def hyp(display, cat=VulnerabilityCategory.BOLA, pack="bola"):
    return SecurityHypothesis(
        id="HYP-X-001", category=cat, endpoint_id="ep", endpoint_display=display,
        title="t", description="d", recommended_test_pack=pack,
    )


# --- ID shapes -------------------------------------------------------------

def test_id_shape_classification_and_mutations():
    assert classify("42").name == "sequential_int"
    assert classify("order-101").name == "prefixed_int"
    assert classify("123e4567-e89b-12d3-a456-426614174000").name == "uuid"
    assert classify("507f1f77bcf86cd799439011").name == "object_id"
    assert classify("MTIz").name == "base64_int"
    assert mutations("42") == ["43", "41"]
    assert mutations("order-101") == ["order-102", "order-100"]
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    assert mutations(uuid) == ["123e4567-e89b-12d3-a456-426614174001"]
    assert mutations("MTIz") == ["MTI0"]
    assert mutations("0") == ["1"]
    assert mutations("***") == []


# --- stateful helpers ------------------------------------------------------

def test_collection_and_id_extraction():
    assert collection_path("/api/items/{id}") == "/api/items"
    assert collection_path("/api/items") is None
    assert trailing_param("/a/{item_id}/") == "item_id"
    assert extract_ids('[{"id": 1}, {"id": 2}, {"id": 1}]') == ["1", "2"]
    assert extract_ids('{"items": [{"item_id": "a"}, {"item_id": "b"}]}', "item_id") == ["a", "b"]
    assert extract_ids("not json") == []
    assert extract_created_id('{"data": {"id": "new-1"}}') == "new-1"
    assert extract_created_id('{"name": "x"}') is None


# --- BOLA owner discovery, oracle, teardown ---------------------------------

def _tenant_handler(leak: bool):
    def handler(method, url, headers, body):
        who = headers.get("Authorization", "")
        if url.endswith("/api/items") and method == "GET":
            return O(200, json.dumps([{"id": "777", "owner": "alice@example.com"}]))
        if url.endswith("/api/items/777") and method == "GET":
            if "user-a" in who or leak:
                return O(200, json.dumps({"id": "777", "owner": "alice@example.com", "email": "alice@example.com"}))
            return O(403, '{"error": "forbidden"}')
        if "/api/items/" in url:
            return O(404, '{"error": "not found"}')
        return O(404)
    return handler


def test_bola_uses_harvested_owner_ids_and_confirms_leak():
    ctx = TestContext(target_base_url="http://127.0.0.1:8000", active_tokens={"user-a": "user-a", "user-b": "user-b"})
    client = FakeClient(_tenant_handler(leak=True))
    res = BolaTestPack().execute(hyp("GET /api/items/{id}"), client, ctx)
    assert res.confirmed
    assert any(c[1].endswith("/api/items") for c in client.calls), "owner collection was listed"
    assert any(c[1].endswith("/api/items/777") for c in client.calls)
    assert "777" in res.summary


def test_bola_clean_and_reports_existence_oracle():
    ctx = TestContext(target_base_url="http://127.0.0.1:8000", active_tokens={"user-a": "user-a", "user-b": "user-b"})
    res = BolaTestPack().execute(hyp("GET /api/items/{id}"), FakeClient(_tenant_handler(leak=False)), ctx)
    assert not res.confirmed
    assert "Existence oracle" in res.summary


def test_bola_stateful_creates_then_tears_down_only_when_opted_in():
    created = []

    def handler(method, url, headers, body):
        if method == "GET" and url.endswith("/api/notes"):
            return O(200, "[]")
        if method == "POST" and url.endswith("/api/notes"):
            created.append(body)
            return O(201, '{"id": "n-9", "text": "hello"}')
        if method == "DELETE":
            return O(204, "")
        return O(403, "{}")

    hints = {"POST /api/notes": {"body": {"text": "hello"}}, "DELETE /api/notes/{id}": {"exists": True}}
    off = FakeClient(handler)
    ctx = TestContext(target_base_url="http://127.0.0.1:8000", active_tokens={"user-a": "a", "user-b": "b"}, api_hints=hints)
    BolaTestPack().execute(hyp("GET /api/notes/{id}"), off, ctx)
    assert not [c for c in off.calls if c[0] in ("POST", "DELETE")], "nothing is created without --stateful"

    on = FakeClient(handler)
    ctx.stateful = True
    BolaTestPack().execute(hyp("GET /api/notes/{id}"), on, ctx)
    assert created == [{"text": "hello"}]
    assert any(c[0] == "DELETE" and c[1].endswith("/api/notes/n-9") for c in on.calls)


# --- identities --------------------------------------------------------------

def test_default_identities_are_synthetic_bearer():
    ctx, warnings = build_context("http://127.0.0.1:8000", TraceConfig())
    assert warnings == []
    assert ctx.headers_for("user-a") == {"Authorization": "Bearer user-a"}
    assert ctx.headers_for("nobody") == {}


def test_configured_identities_replace_synthetic_ones(monkeypatch):
    monkeypatch.setenv("T_A", "real-a")
    monkeypatch.setenv("T_B", "sess-b")
    cfg = TraceConfig(identities={
        "user-a": IdentityConfig(kind="bearer", token="${T_A}"),
        "user-b": IdentityConfig(kind="cookie", cookie="sid", token="${T_B}"),
        "svc": IdentityConfig(kind="api_key", header="X-Key", token="k1"),
        "bob": IdentityConfig(kind="basic", username="bob", password="pw"),
        "ghost": IdentityConfig(kind="bearer", token="${T_MISSING}"),
        "odd": IdentityConfig(kind="mystery", token="x"),
    })
    ctx, warnings = build_context("http://127.0.0.1:8000", cfg)
    assert ctx.headers_for("user-a") == {"Authorization": "Bearer real-a"}
    assert ctx.headers_for("user-b") == {"Cookie": "sid=sess-b"}
    assert ctx.headers_for("svc") == {"X-Key": "k1"}
    assert ctx.headers_for("bob")["Authorization"].startswith("Basic ")
    assert ctx.headers_for("admin") == {}, "synthetic admin must not leak in"
    assert any("T_MISSING" in w for w in warnings) and any("mystery" in w for w in warnings)


# --- rate limiting -----------------------------------------------------------

def test_rate_limit_pack_confirms_unthrottled_burst():
    client = FakeClient(lambda *a: O(401, '{"error": "bad creds"}'))
    ctx = TestContext(target_base_url="http://127.0.0.1:8000", active_tokens={"user-a": "a"})
    res = RateLimitTestPack().execute(hyp("POST /api/login", VulnerabilityCategory.RATE_LIMIT, "rate_limit"), client, ctx)
    assert res.confirmed and len(client.calls) == BURST
    assert "CWE-770" in res.summary


def test_rate_limit_pack_sees_429_and_headers():
    n = {"i": 0}

    def handler(*a):
        n["i"] += 1
        return O(429 if n["i"] > 3 else 401)

    res = RateLimitTestPack().execute(
        hyp("POST /api/login", VulnerabilityCategory.RATE_LIMIT, "rate_limit"),
        FakeClient(handler), TestContext(target_base_url="http://127.0.0.1:8000"),
    )
    assert not res.confirmed and "Throttling observed" in res.summary
    hdr = RateLimitTestPack().execute(
        hyp("POST /api/login", VulnerabilityCategory.RATE_LIMIT, "rate_limit"),
        FakeClient(lambda *a: O(200, headers={"X-RateLimit-Remaining": "9"})),
        TestContext(target_base_url="http://127.0.0.1:8000"),
    )
    assert not hdr.confirmed


def test_rate_limit_pack_skips_unsafe_methods_and_registers():
    res = RateLimitTestPack().execute(
        hyp("DELETE /api/login", VulnerabilityCategory.RATE_LIMIT, "rate_limit"),
        FakeClient(lambda *a: O()), TestContext(target_base_url="http://127.0.0.1:8000"),
    )
    assert not res.confirmed and "skipped" in res.summary
    assert default_registry.get("rate_limit") is not None


def test_rate_limit_hypotheses_are_opt_in_and_respect_limiter_signals(tmp_path):
    from trace_engine.apm.model import AttackPathModel
    from trace_engine.framework.base import Endpoint
    from trace_engine.parsing.locations import SourceLocation

    plain = tmp_path / "plain.py"
    plain.write_text("def login(): pass\n", encoding="utf-8")
    limited = tmp_path / "limited.py"
    limited.write_text("from slowapi import Limiter\ndef reset(): pass\n", encoding="utf-8")

    def ep(i, path, f):
        return Endpoint(id=f"ep{i}", method="POST", path=path, handler_name="h",
                        source=SourceLocation(file=str(f), line_start=1, line_end=1))

    eps = [ep(1, "/api/login", plain), ep(2, "/api/reset", limited), ep(3, "/api/items", plain)]
    engine = HypothesisEngine()
    off = engine.derive_hypotheses(AttackPathModel("t"), eps)
    on = engine.derive_hypotheses(AttackPathModel("t"), eps, include_runtime_checks=True)
    assert not [h for h in off if h.category == VulnerabilityCategory.RATE_LIMIT]
    rate = [h for h in on if h.category == VulnerabilityCategory.RATE_LIMIT]
    assert [h.endpoint_display for h in rate] == ["POST /api/login"]
    assert rate[0].recommended_test_pack == "rate_limit"


# --- verdict privacy weighting ------------------------------------------------

def test_privacy_fields_raise_the_leak_verdict():
    owner = json.dumps({"id": 1, "name": "Alice A", "email": "alice@example.com", "plan": "gold"})
    prober = json.dumps({"id": 1, "name": "Alice A", "email": "alice@example.com", "plan": "gold"})
    with_priv = score_response_pair(200, owner, 200, prober)
    assert with_priv.breakdown["privacy"] == 0.1
    plain_o = json.dumps({"id": 1, "label": "alpha", "count": 3})
    plain = score_response_pair(200, plain_o, 200, plain_o)
    assert plain.breakdown["privacy"] == 0.0
    assert score_response_pair(200, owner, 403, '{"error": "forbidden"}').verdict == "CLEAR"
