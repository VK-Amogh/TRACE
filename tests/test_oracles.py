"""Unit tests for canary oracles and the weighted multi-signal verdict."""

from trace_engine.testpacks.canary import (
    new_canary,
    contains_canary,
    owner_markers,
    attacker_sees_owner_markers,
)
from trace_engine.security.verdict import score_response_pair


def test_canary_unique_and_prefixed():
    a, b = new_canary(), new_canary("ma")
    assert a != b
    assert b.startswith("ma-")
    assert contains_canary(f"hello {a} world", a) is True
    assert contains_canary("hello world", a) is False
    assert contains_canary("", a) is False


def test_owner_markers_extract_identifiers():
    body = '{"id": "order-101", "email": "a@x.com", "status": "ok"}'
    markers = owner_markers(body)
    assert "order-101" in markers
    assert "a@x.com" in markers
    assert "ok" not in markers
    assert "status" not in markers


def test_attacker_diff_confirms_leak():
    owner = '{"id": "order-101", "total": 42}'
    assert attacker_sees_owner_markers(owner, owner)["confirmed"] is True
    clean = attacker_sees_owner_markers(owner, '{"error": "forbidden"}')
    assert clean["confirmed"] is False


def test_verdict_confirms_identical_leak():
    body = '{"id": "order-101", "total": 42, "owner": "user-a"}'
    v = score_response_pair(200, body, 200, body)
    assert v.verdict == "CONFIRMED"
    assert v.score >= 0.75


def test_verdict_denial_body_is_clear():
    owner = '{"id": "order-101", "total": 42}'
    denied = '{"error": "forbidden: access denied"}'
    v = score_response_pair(200, owner, 403, denied)
    assert v.verdict == "CLEAR"
    assert v.breakdown["denial_penalty"] > 0 or v.score < 0.5


def test_verdict_unrelated_bodies_clear():
    v = score_response_pair(
        200, '{"id": 1, "name": "alpha"}', 200, '{"status": "ok", "count": 3}'
    )
    assert v.verdict in ("CLEAR", "LIKELY")
    assert v.score < 0.75


def test_verdict_non_json_identical_text():
    v = score_response_pair(200, "hello world", 200, "hello world")
    assert v.verdict in ("CONFIRMED", "LIKELY")


def test_verdict_non_200_statuses_not_confirmed():
    v = score_response_pair(404, "{}", 404, "{}")
    assert v.verdict == "CLEAR"
