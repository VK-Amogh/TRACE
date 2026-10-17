"""release_tools keeps shipped skills on the same version as the package."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("release_tools", ROOT / "scripts" / "release_tools.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sandbox(mod, tmp_path: Path, skill_version: str = "1.0.0") -> None:
    (tmp_path / "src" / "trace_engine").mkdir(parents=True)
    (tmp_path / "src" / "trace_engine" / "__init__.py").write_text('__version__ = "1.0.0"\n', encoding="utf-8")
    (tmp_path / "package.json").write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\n", encoding="utf-8")
    skill = tmp_path / "skills" / "demo"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f'---\nname: demo\ndescription: d\nmetadata:\n  version: "{skill_version}"\n---\n\nversion: "9.9.9" in body\n',
        encoding="utf-8",
    )
    mod.ROOT = tmp_path
    mod.INIT = tmp_path / "src" / "trace_engine" / "__init__.py"
    mod.PKG = tmp_path / "package.json"
    mod.CHANGELOG = tmp_path / "CHANGELOG.md"
    mod.SKILLS = tmp_path / "skills"


def test_repo_skills_match_package_version():
    mod = _load()
    assert set(mod.skill_versions().values()) == {mod.npm_version()}
    mod.check(None)


def test_bump_updates_skill_frontmatter_only(tmp_path: Path):
    mod = _load()
    _sandbox(mod, tmp_path)
    mod.bump("1.1.0")
    text = (tmp_path / "skills" / "demo" / "SKILL.md").read_text(encoding="utf-8")
    assert 'version: "1.1.0"' in text
    assert 'version: "9.9.9" in body' in text, "body text must be untouched"
    mod.check("v1.1.0")


def test_check_fails_on_stale_skill(tmp_path: Path):
    mod = _load()
    _sandbox(mod, tmp_path, skill_version="0.9.0")
    with pytest.raises(SystemExit) as exc:
        mod.check(None)
    assert "demo" in str(exc.value)
