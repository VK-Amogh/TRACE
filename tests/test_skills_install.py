"""Skills ship in the npm package and install into any agent harness layout.

Covers the npm manifest, the zero-dependency Node installer, and the Python
plugin installer, which must agree on directory names and never clobber a
user's existing MCP configuration.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = ROOT / "skills"
TRACE_JS = ROOT / "bin" / "trace.js"
NODE = shutil.which("node")


def _skill_names():
    return sorted(p.name for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file())


def _frontmatter_name(skill_md: Path) -> str:
    match = re.search(r"^name:\s*(\S+)\s*$", skill_md.read_text(encoding="utf-8"), re.MULTILINE)
    assert match, f"{skill_md}: missing name"
    return match.group(1)


def _install(cwd: Path, *args: str, env=None):
    return subprocess.run(
        [NODE, str(TRACE_JS), "install-skill", *args],
        cwd=cwd, capture_output=True, text=True, timeout=60, env=env,
    )


def test_npm_manifest_publishes_skills():
    pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    assert "skills" in pkg["files"], "skills/ must be in the npm package"
    assert "agent-skill" in pkg["keywords"]
    assert _skill_names(), "no skills to publish"


def test_wheel_bundles_skills():
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "published-skills" in toml


@pytest.mark.skipif(NODE is None, reason="node not available")
def test_node_installer_is_harness_agnostic(tmp_path: Path):
    proc = _install(tmp_path)
    assert proc.returncode == 0, proc.stderr
    for name in _skill_names():
        for base in (".agents/skills", ".claude/skills"):
            skill_md = tmp_path / base / name / "SKILL.md"
            assert skill_md.is_file(), f"{base}/{name} missing"
            assert _frontmatter_name(skill_md) == name, "directory must match skill name"
    assert set(_skill_names()) == {"trace", "trace-fix"}, "the published skill set is trace + trace-fix"
    assert not (tmp_path / ".claude/skills/trace-security").exists()


@pytest.mark.skipif(NODE is None, reason="node not available")
def test_node_installer_preserves_existing_mcp_servers(tmp_path: Path):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"command": "x"}}}), encoding="utf-8"
    )
    assert _install(tmp_path).returncode == 0
    servers = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
    assert servers["other"] == {"command": "x"}
    assert "trace" in servers


@pytest.mark.skipif(NODE is None, reason="node not available")
def test_node_installer_skills_only_and_flags(tmp_path: Path):
    assert _install(tmp_path, "--skills-only").returncode == 0
    assert (tmp_path / ".agents/skills/trace/SKILL.md").is_file()
    assert not (tmp_path / ".mcp.json").exists()
    assert not (tmp_path / ".agents/plugins").exists()

    listed = _install(tmp_path, "--list")
    assert listed.returncode == 0
    assert set(listed.stdout.split()) == set(_skill_names())

    assert _install(tmp_path, "--bogus").returncode == 2


@pytest.mark.skipif(NODE is None, reason="node not available")
def test_node_installer_global_writes_home_only(tmp_path: Path):
    import os

    home = tmp_path / "home"
    project = tmp_path / "project"
    home.mkdir()
    project.mkdir()
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    assert _install(project, "--global", env=env).returncode == 0
    assert (home / ".agents/skills/trace-fix/SKILL.md").is_file()
    assert not (project / ".agents").exists()
    assert not (project / ".mcp.json").exists()


def test_python_installer_matches_node_layout(tmp_path: Path):
    from trace_engine.plugin import TraceHarnessPlugin

    TraceHarnessPlugin(repo_path=tmp_path).install(workspace_mode=True, global_mode=False)
    for name in _skill_names():
        assert (tmp_path / ".agents/skills" / name / "SKILL.md").is_file()
        assert (tmp_path / ".claude/skills" / name / "SKILL.md").is_file()
    assert not (tmp_path / ".claude/skills/trace-security").exists()
    assert not (tmp_path / ".claude/skills/trace-security-harness").exists()
