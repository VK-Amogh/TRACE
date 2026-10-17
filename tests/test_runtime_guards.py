"""Redaction, evidence log, request budget and catch-all (soft-404) detection."""

import json
from pathlib import Path

import pytest

from trace_engine.policy.scope import ScopeGuard
from trace_engine.runtime.client import RequestBudgetExceeded, ScopedHttpClient
from trace_engine.runtime.evidence import EvidenceLog, curl_commands, to_curl
from trace_engine.runtime.observations import RuntimeObservation
from trace_engine.runtime.redact import REDACTED, redact_headers, redact_observation, redact_text
from trace_engine.runtime.soft404 import (
    baseline_from_observation,
    looks_like_catch_all,
    only_catch_all_evidence,
    probe_catch_all,
)

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"


def obs(status=200, body="{}", url="http://127.0.0.1:8000/x", headers=None, method="GET"):
    return RuntimeObservation(
        request_method=method, request_url=url, request_headers=headers or {},
        response_status=status, response_body=body,
    )


def test_headers_and_tokens_are_redacted():
    h = redact_headers({"Authorization": "Bearer secret-value", "X-Api-Key": "k", "Accept": "json", "Cookie": "s=1"})
    assert h["Authorization"] == f"Bearer {REDACTED}"
    assert h["X-Api-Key"] == REDACTED and h["Cookie"] == REDACTED and h["Accept"] == "json"
    assert JWT not in redact_text(f"token={JWT}")
    assert "hunter22222" not in redact_text('{"password": "hunter22222", "name": "ok"}')
    assert '"name": "ok"' in redact_text('{"password": "hunter22222", "name": "ok"}')
    safe = redact_observation(obs(headers={"Authorization": "Bearer abc12345"}, body=f"jwt {JWT}"))
    assert "abc12345" not in json.dumps(safe.model_dump()) and JWT not in safe.response_body


def test_evidence_log_writes_redacted_jsonl_and_curl(tmp_path: Path):
    log = EvidenceLog(tmp_path / "evidence", run_id="r1")
    o = obs(headers={"Authorization": "Bearer abc12345"}, method="POST", url="http://127.0.0.1:8000/a b")
    o = o.model_copy(update={"request_body": '{"a": 1}'})
    log.record(o)
    rows = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1 and rows[0]["status"] == 200
    assert "abc12345" not in log.path.read_text(encoding="utf-8")
    curl = to_curl(o)
    assert curl.startswith("curl -i -X POST") and "abc12345" not in curl and REDACTED in curl
    assert len(curl_commands([o, o, obs(status=0)])) == 1


class _Guard(ScopeGuard):
    def __init__(self):
        super().__init__()


def test_client_enforces_request_budget_and_records(monkeypatch):
    import httpx

    class FakeResp:
        status_code = 200
        headers = {"set-cookie": "sid=abc"}
        text = "ok"
        is_redirect = False

    class FakeClient:
        def __init__(self, *a, **k): ...
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def request(self, **k): return FakeResp()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    seen = []
    client = ScopedHttpClient(ScopeGuard(), max_requests=2, recorder=seen.append)
    first = client.execute("GET", "http://127.0.0.1:8000/a", headers={"Authorization": "Bearer tok-12345678"})
    client.execute("GET", "http://127.0.0.1:8000/b")
    assert first.request_headers["Authorization"] == f"Bearer {REDACTED}"
    assert first.response_headers["set-cookie"] == REDACTED
    assert len(seen) == 2 and client.request_count == 2
    with pytest.raises(RequestBudgetExceeded):
        client.execute("GET", "http://127.0.0.1:8000/c")


def test_catch_all_detection_demotes_spa_style_pages():
    page = "<html><body>App shell 12345678 build</body></html>"
    base = baseline_from_observation(obs(body=page))
    assert base is not None
    assert looks_like_catch_all(base, obs(body="<html><body>App shell 87654321 build</body></html>"))
    assert not looks_like_catch_all(base, obs(body='{"id": 7, "owner": "alice@example.com"}'))
    assert not looks_like_catch_all(base, obs(status=404, body=page))
    assert only_catch_all_evidence(base, [obs(body=page), obs(body=page)])
    assert not only_catch_all_evidence(base, [obs(body=page), obs(body='{"id": 1}')])
    assert not only_catch_all_evidence(None, [obs(body=page)])
    assert baseline_from_observation(obs(status=404)) is None


def test_json_catch_all_matches_on_shape():
    base = baseline_from_observation(obs(body='{"status": "ok", "message": "not found"}'))
    assert looks_like_catch_all(base, obs(body='{"status": "ok", "message": "different text"}'))


def test_probe_catch_all_uses_a_random_unknown_path():
    calls = []

    class Fake:
        def execute(self, method, url, headers=None, json_body=None):
            calls.append(url)
            return obs(body="<html>spa</html>")

    base = probe_catch_all(Fake(), "http://127.0.0.1:8000/")
    assert base is not None and "/trace-" in calls[0]
    assert probe_catch_all(type("F", (), {"execute": lambda *a, **k: obs(status=404)})(), "http://x") is None
