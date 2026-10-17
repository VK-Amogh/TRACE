"""The two published skills keep distinct, on-point roles.

`trace` is the setup skill (the only one a user installs); `trace-fix` is what
the agent does with findings.
"""

from pathlib import Path

SKILLS = Path(__file__).resolve().parent.parent / "skills"


def _read(*parts: str) -> str:
    return SKILLS.joinpath(*parts).read_text(encoding="utf-8")


def test_published_skill_set_is_exactly_trace_and_trace_fix():
    names = sorted(p.name for p in SKILLS.iterdir() if p.is_dir())
    assert names == ["trace", "trace-fix"]


def test_trace_skill_bootstraps_without_a_prior_install():
    body = _read("trace", "SKILL.md")
    for needle in (
        "npx -y trace-sec --version",  # preflight without an install
        "trace doctor",  # health check
        "trace install-skill",  # MCP + sibling skill
        "claude mcp add trace",  # Claude Code MCP
        "allowed_ports",  # local target configuration
        "ScopeGuard",  # safety boundary
        ".traceignore",  # scan scope
        "trace-fix",  # hand-off
    ):
        assert needle in body, f"trace skill missing: {needle}"
    assert (SKILLS / "trace" / "references" / "troubleshooting.md").is_file()


def test_trace_skill_does_not_teach_remediation():
    body = _read("trace", "SKILL.md")
    assert "playbook" not in body.lower()
    assert "P0" not in body


def test_trace_fix_covers_the_five_steps():
    body = _read("trace-fix", "SKILL.md")
    for step in ("Triage", "Prioritize", "Fix", "Verify", "Report"):
        assert f"## {1 + ['Triage', 'Prioritize', 'Fix', 'Verify', 'Report'].index(step)}. {step}" in body
    for status in ("FIXED", "STILL_PRESENT", "INCONCLUSIVE"):
        assert status in body
    for ref in ("triage", "prioritization", "playbooks", "verification-loop", "guide"):
        assert (SKILLS / "trace-fix" / "references" / f"{ref}.md").is_file()


def test_trace_fix_does_not_duplicate_setup():
    body = _read("trace-fix", "SKILL.md")
    assert "~/.trace/venv" not in body
    assert "winget" not in body
