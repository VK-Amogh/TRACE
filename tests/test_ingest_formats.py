"""Ingestion must skip file formats that no parser or adapter can use.

Markup, styles, data/config files, SQL and similar formats produce no routes,
symbols or sinks, so reading, hashing and graphing them only wastes time.
"""

from pathlib import Path

from trace_engine.ingest.files import ANALYZED_LANGUAGES, EXTENSION_LANGUAGE_MAP
from trace_engine.ingest.ignore import IgnoreFilter
from trace_engine.ingest.repository import RepositoryScanner


def _write(root: Path, rel: str, text: str = "x\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mixed_tree(root: Path) -> Path:
    _write(root, "app/main.py", "x = 1\n")
    _write(root, "web/server.ts", "export const a = 1\n")
    _write(root, "web/index.html", "<html></html>")
    _write(root, "web/site.css", "body{}")
    _write(root, "config/settings.json", "{}")
    _write(root, "config/app.yaml", "a: 1")
    _write(root, "config/pyproject.toml", "[a]")
    _write(root, "db/schema.sql", "select 1;")
    return root


def test_non_analyzed_formats_are_not_ingested(tmp_path: Path):
    files = [f.path for f in RepositoryScanner(_mixed_tree(tmp_path)).scan()]
    assert files == ["app/main.py", "web/server.ts"]


def test_skipped_files_are_counted_not_read(tmp_path: Path, monkeypatch):
    scanner = RepositoryScanner(_mixed_tree(tmp_path))
    opened = []
    original = Path.read_bytes

    def spy(self):
        opened.append(self.name)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", spy)
    scanner.scan()

    assert sorted(opened) == ["main.py", "server.ts"]
    assert scanner.skipped_by_language["html"] == 1
    assert scanner.skipped_by_language["json"] == 1
    assert scanner.skipped_by_language["yaml"] == 1
    assert scanner.skipped_by_language["sql"] == 1


def test_languages_override_opts_back_in(tmp_path: Path):
    scanner = RepositoryScanner(_mixed_tree(tmp_path), languages={"json", "yaml"})
    assert [f.path for f in scanner.scan()] == ["config/app.yaml", "config/settings.json"]


def test_analyzed_languages_are_known_languages():
    assert ANALYZED_LANGUAGES <= set(EXTENSION_LANGUAGE_MAP.values())
    assert not ANALYZED_LANGUAGES & {"html", "css", "json", "yaml", "toml", "sql"}


def test_tool_cache_dirs_and_generated_files_are_ignored(tmp_path: Path):
    _write(tmp_path, "src/api.py", "a = 1\n")
    _write(tmp_path, ".pytest_cache/v/cache.py", "b = 2\n")
    _write(tmp_path, ".mypy_cache/x.py", "c = 3\n")
    _write(tmp_path, "pkg.egg-info/hooks.py", "d = 4\n")
    _write(tmp_path, "types/index.d.ts", "declare const a: number\n")
    _write(tmp_path, "static/app.bundle.js", "var a=1\n")
    assert [f.path for f in RepositoryScanner(tmp_path).scan()] == ["src/api.py"]
    assert IgnoreFilter(tmp_path).should_ignore(tmp_path / ".ruff_cache", is_dir=True)


def test_scan_survives_extensionless_and_dotfiles(tmp_path: Path):
    _write(tmp_path, "Makefile", "all:\n")
    _write(tmp_path, ".py", "x = 1\n")
    _write(tmp_path, "real.py", "y = 2\n")
    assert [f.path for f in RepositoryScanner(tmp_path).scan()] == ["real.py"]
