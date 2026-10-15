# Agent skills

TRACE ships installable [Agent Skills](https://agentskills.io/) in `skills/`.
Any agent package manager that speaks the open skill format can install them;
with the [`skills`](https://github.com/vercel-labs/skills) CLI:

```bash
npx skills add VK-Amogh/TRACE --list
npx skills add VK-Amogh/TRACE --skill trace
```

One skill, three workflows: auditing, verified remediation, and MCP
setup. Scope flags work as usual (`-g` for global, `-a` for specific
agents, `-y` for non-interactive).

Skill authors: keep `SKILL.md` bodies focused (references go in
`references/`), `name` matching the directory, and descriptions starting
with when to use the skill. `tests/test_skills_package.py` enforces the
spec in CI.
