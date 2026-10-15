"""Unit tests for the declarative sink catalog."""

from trace_engine.security import sinks
from trace_engine.security.sinks import match_sinks, has_sink_kind


def test_catalog_loads_entries():
    assert len(sinks._load_catalog()) >= 10
    ids = {e.id for e in sinks._load_catalog()}
    assert "py-sql-execute" in ids
    assert "py-http-outbound" in ids
    assert "go-sql-query" in ids


def test_match_sql_sink_python():
    hits = match_sinks("rows = cursor.execute(f'SELECT * FROM t WHERE id={i}')", "python")
    assert any(h.sink_id == "py-sql-execute" for h in hits)
    assert hits[0].cwe == "CWE-89"
    assert hits[0].testpack == "injection"


def test_sanitizer_suppresses_hit():
    hits = match_sinks("cursor.execute('SELECT * FROM t WHERE id = ?', (i,))", "python")
    assert not any(h.sink_id == "py-sql-execute" for h in hits)


def test_language_scoping():
    hits = match_sinks('db.Raw(fmt.Sprintf("SELECT %s", id))', "go")
    assert any(h.sink_id == "go-sql-query" for h in hits)
    assert not any(h.sink_id.startswith("py-") for h in hits)


def test_has_sink_kind_helper():
    assert has_sink_kind("requests.get(url)", "python", "py-http") is True
    assert has_sink_kind("requests.get(url)", "python", "py-sql") is False
    assert has_sink_kind("print('hello')", "python", "py-sql", "py-http") is False


def test_ssrf_and_template_kinds():
    assert has_sink_kind("render_template_string(tpl)", "python", "py-template") is True
    assert has_sink_kind("pickle.loads(blob)", "python", "py-deserialize") is True
