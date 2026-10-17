"""SecureBERT cache buffering semantics: writes happen on flush, not on set."""

from pathlib import Path

from trace_engine.intelligence.securebert.cache import SecureBERTCache


def test_set_is_buffered_until_flush(tmp_path: Path):
    cache_file = tmp_path / "cache.json"
    cache = SecureBERTCache(cache_file)

    cache.set("order = db.query(Order).filter(id=id).first()", {"BOLA": 0.5})
    assert not cache_file.exists(), "set() must not touch disk before flush()"

    cache.flush()
    assert cache_file.exists()

    reloaded = SecureBERTCache(cache_file)
    assert reloaded.get("order = db.query(Order).filter(id=id).first()") == {"BOLA": 0.5}


def test_flush_is_noop_when_clean(tmp_path: Path):
    cache_file = tmp_path / "cache.json"
    cache = SecureBERTCache(cache_file)

    cache.flush()
    assert not cache_file.exists()


def test_get_returns_none_for_unknown_text(tmp_path: Path):
    cache = SecureBERTCache(tmp_path / "cache.json")
    assert cache.get("never seen") is None
