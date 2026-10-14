# Agent skills

TRACE ships installable [Agent Skills](https://agentskills.io/) in `skills/`.
Any agent package manager that speaks the open skill format can install them;
with the [`skills`](https://github.com/vercel-labs/skills) CLI:

```bash
npx skills add auraflaa/TRACE --list
npx skills add auraflaa/TRACE --skill trace-security-audit
npx skills add auraflaa/TRACE --skill trace-remediation-harness --skill trace-mcp-setup
```

No registry submission or npm publish step exists — pushing to GitHub
publishes. Scope flags work as usual (`-g` for global, `-a` for specific
agents, `-y` for non-interactive).

| Skill | What the agent learns |
|---|---|
| `trace-security-audit` | run audits, read findings, explain root causes |
| `trace-remediation-harness` | fix findings end to end with live verification |
| `trace-mcp-setup` | connect the agent to TRACE over MCP |

Skill authors: keep `SKILL.md` bodies focused (references go in
`references/`), `name` matching the directory, and descriptions starting
with when to use the skill. `tests/test_skills_package.py` enforces the
spec in CI.
