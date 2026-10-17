"""Ingestion must prune ignored directories instead of walking every file.

Regression: auditing a 398k-file ML repo (datasets/, runs/, weights/)
stalled for minutes because ``rglob("*")`` enumerated every file and ran
the pattern matcher on each one instead of skipping ignored trees.
"""

from pathlib import Path

from trace_engine.ingest.ignore import IgnoreFilter
from trace_engine.ingest.repository import RepositoryScanner


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "venv" / "pkg" / "sub").mkdir(parents=True)
    (tmp_path / "venv" / "pkg" / "sub" / "lib.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / "datasets" / "batch" / "inner").mkdir(parents=True)
    (tmp_path / "datasets" / "batch" / "inner" / "loader.py").write_text("z = 3\n", encoding="utf-8")
    return tmp_path


def test_scan_excludes_ignored_trees(tmp_path: Path):
    scanner = RepositoryScanner(_tree(tmp_path), exclude_patterns=["datasets"])
    assert [f.path for f in scanner.scan()] == ["app/main.py"]


def test_scan_never_descends_into_ignored_dirs(tmp_path: Path, monkeypatch):
    """The walk must prune; ignoring each file deep inside a huge tree is too slow."""
    scanner = RepositoryScanner(_tree(tmp_path), exclude_patterns=["datasets"])

    seen = []
    original = IgnoreFilter.should_ignore

    def spy(self, path, is_dir=None):
        seen.append(Path(path))
        return original(self, path, is_dir=is_dir)

    monkeypatch.setattr(IgnoreFilter, "should_ignore", spy)
    scanner.scan()

    for path in seen:
        ignored_segments = [p for p in path.parts[:-1] if p in ("venv", "datasets")]
        assert not ignored_segments, f"descended into ignored tree: {path}"


def test_file_level_patterns_still_match_without_dir_pruning(tmp_path: Path):
    """Patterns that only match file names must keep excluding those files."""
    (tmp_path / "api.py").write_text("a = 1\n", encoding="utf-8")
    (tmp_path / "api.generated.py").write_text("b = 2\n", encoding="utf-8")
    scanner = RepositoryScanner(tmp_path, exclude_patterns=["*.generated.py"])
    assert [f.path for f in scanner.scan()] == ["api.py"]


def test_source_file_hash_matches_hash_file_bytes(tmp_path: Path):
    """Single-read ingestion must produce the same SHA-256 as hash_file()."""
    from trace_engine.ingest.hashing import hash_file

    sample = tmp_path / "mod.py"
    sample.write_text("print('hi')\n", encoding="utf-8")
    sf = RepositoryScanner(tmp_path).scan()[0]
    assert sf.sha256 == hash_file(sample)
    assert sf.line_count == 1
