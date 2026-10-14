"""Validate the trace-skills package against the Agent Skills spec.

Runs in lite CI (stdlib only): every skill directory must ship a
spec-compliant SKILL.md whose name matches its directory.
"""

import re
from pathlib import Path

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _skill_dirs():
    assert SKILLS_DIR.is_dir(), "skills/ directory missing"
    dirs = sorted(p for p in SKILLS_DIR.iterdir() if p.is_dir())
    assert dirs, "no skills found"
    return dirs


def _load_skill(skill_dir):
    """Split SKILL.md into a flat frontmatter dict and body (no yaml dep)."""
    skill_file = skill_dir / "SKILL.md"
    assert skill_file.is_file(), f"{skill_dir.name}/SKILL.md missing"
    text = skill_file.read_text(encoding="utf-8")
    assert text.startswith("---"), f"{skill_dir.name}: missing frontmatter fence"
    _, frontmatter, body = text.split("---", 2)
    fields = {}
    for line in frontmatter.splitlines():
        if re.match(r"^[A-Za-z][A-Za-z0-9_-]*:", line):
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
    # Folded/multiline descriptions are unsupported: keep them single-line.
    assert "description" in fields, f"{skill_dir}: description missing"
    return fields, body


def test_skills_discoverable():
    assert len(_skill_dirs()) >= 1


def test_skill_frontmatter_valid():
    for skill_dir in _skill_dirs():
        fields, _ = _load_skill(skill_dir)
        name = fields.get("name", "")
        assert 1 <= len(name) <= 64, f"{skill_dir}: bad name length"
        assert NAME_RE.match(name), f"{skill_dir}: name must be lowercase kebab-case"
        assert name == skill_dir.name, f"{skill_dir}: name must match directory"
        desc = fields.get("description", "")
        assert 1 <= len(desc) <= 1024, f"{skill_dir}: description must be 1-1024 chars"


def test_skill_bodies_concise():
    for skill_dir in _skill_dirs():
        _, body = _load_skill(skill_dir)
        assert len(body.splitlines()) < 500, f"{skill_dir}: body over 500 lines"
        assert "trace" in body.lower(), f"{skill_dir}: body should mention trace"


def test_skill_references_resolve():
    for skill_dir in _skill_dirs():
        _, body = _load_skill(skill_dir)
        for match in re.findall(r"\[[^\]]*\]\((references/[^)]+)\)", body):
            target = skill_dir / match
            assert target.is_file(), f"{skill_dir}: dangling reference {match}"
