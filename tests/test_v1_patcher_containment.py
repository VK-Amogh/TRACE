"""V1 regression: SafePatcher workspace containment (red-green).

Baseline (vulnerable): absolute paths and `..` traversal escape the workspace
in backup/restore/replacement/full-content paths.
Fixed behavior: every file operation resolves inside the workspace root;
outside destinations are refused and the outside file is untouched, while
legitimate in-workspace patching keeps working.
"""

from pathlib import Path

import pytest

from trace_engine.harness.patcher import SafePatcher


def _make_workspace(base: Path):
    ws = base / "ws"
    ws.mkdir()
    (ws / "ok.txt").write_text("hello TARGET", encoding="utf-8")
    (ws / "sub").mkdir()
    (ws / "sub" / "nested.txt").write_text("nested TARGET", encoding="utf-8")
    outside = base / "outside.txt"
    outside.write_text("ORIGINAL_OUT", encoding="utf-8")
    return base, ws, outside


def test_absolute_path_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    res = p.apply_full_content("F-ABS", str(outside), "PWNED")
    assert res.success is False, "absolute path must be refused"
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_parent_traversal_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    res = p.apply_full_content("F-TRAV", "../outside.txt", "PWNED")
    assert res.success is False, "../ traversal must be refused"
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_nested_traversal_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    res = p.apply_replacement("F-NT", "sub/../../outside.txt", "ORIGINAL_OUT", "PWNED")
    assert res.success is False
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_backup_traversal_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    with pytest.raises((ValueError, FileNotFoundError)):
        p.backup("../outside.txt")
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"
    # no backup of the outside file may leak into the backup dir
    backup_dir = ws / ".trace" / "backups"
    leaked = (
        [f for f in backup_dir.iterdir() if "outside" in f.name]
        if backup_dir.exists()
        else []
    )
    assert leaked == []


def test_rollback_outside_target_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    legit_backup = p.backup("ok.txt")
    ok = p.rollback("../outside.txt", legit_backup)
    assert ok is False
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_rollback_foreign_backup_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    # a backup file outside the patcher's backup dir must not be honored
    foreign = base / "foreign.bak"
    foreign.write_text("FOREIGN", encoding="utf-8")
    ok = p.rollback("ok.txt", foreign)
    assert ok is False
    assert (ws / "ok.txt").read_text(encoding="utf-8") == "hello TARGET"


def test_windows_drive_and_unc_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    # Drive-letter / UNC / forward-slash-absolute shapes must never escape,
    # on Windows and when simulated on other platforms.
    evil_shapes = [
        "C:\\Windows\\Temp\\evil.txt",
        "C:/Windows/Temp/evil.txt",
        "\\\\server\\share\\evil.txt",
        "//server/share/evil.txt",
    ]
    for shape in evil_shapes:
        res = p.apply_full_content("F-WIN", shape, "PWNED")
        assert res.success is False, shape
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_symlink_escape_blocked(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    link = ws / "evil_link.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"symlink creation not permitted: {e}")
    p = SafePatcher(ws)
    res = p.apply_full_content("F-LINK", "evil_link.txt", "PWNED")
    assert res.success is False, "symlink escaping workspace must be refused"
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"


def test_legit_in_workspace_operations_still_work(tmp_path):
    base, ws, outside = _make_workspace(tmp_path)
    p = SafePatcher(ws)
    # replacement
    r1 = p.apply_replacement("F-OK", "ok.txt", "TARGET", "PATCHED")
    assert r1.success is True
    assert (ws / "ok.txt").read_text(encoding="utf-8") == "hello PATCHED"
    # full content on nested file
    r2 = p.apply_full_content("F-OK2", "sub/nested.txt", "NEW CONTENT")
    assert r2.success is True
    assert (ws / "sub" / "nested.txt").read_text(encoding="utf-8") == "NEW CONTENT"
    # rollback restores
    assert r2.backup_file
    assert p.rollback("sub/nested.txt", Path(r2.backup_file)) is True
    assert (ws / "sub" / "nested.txt").read_text(encoding="utf-8") == "nested TARGET"
    # dot-segments that stay inside are fine
    r3 = p.apply_full_content("F-OK3", "sub/../ok.txt", "DOT OK")
    assert r3.success is True
    assert (ws / "ok.txt").read_text(encoding="utf-8") == "DOT OK"
    assert outside.read_text(encoding="utf-8") == "ORIGINAL_OUT"
