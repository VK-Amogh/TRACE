# Agent skills

TRACE ships two installable [Agent Skills](https://agentskills.io/): plain
`SKILL.md` folders, so they work in any agent harness that follows the open
format (Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot, OpenCode,
Antigravity and others).

| Skill | What it is for |
|---|---|
| **`trace`** | **Setup.** The only thing a user needs to install. The agent uses it to install and configure TRACE (runtime, MCP, local target, scan scope), run scans, and fix setup problems |
| **`trace-fix`** | **What to do with findings.** Triage which are real, prioritize, fix by category and language, prove the fix, and report honestly, plus the top security guidance (OWASP/CWE, coverage limits, CI gating) |

A vibe coder installs `trace`; the agent does the rest, including installing
`trace-fix` once there are findings to act on.

## Install

Pick whichever fits your workflow; all produce the same folders.

=== "Any agent (universal)"

    The [`skills`](https://github.com/vercel-labs/skills) CLI installs from
    git into 75+ agents, each in its own directory:

    ```bash
    npx skills add VK-Amogh/TRACE --list
    npx skills add VK-Amogh/TRACE                 # both
    npx skills add VK-Amogh/TRACE --skill trace -a claude-code
    ```

    Useful flags: `-g` global, `-a <agent>` target agents, `-y` non-interactive.

=== "With the npm package"

    The skills ship inside `trace-sec` under `skills/`, versioned with the
    tool. The bundled installer is zero-dependency:

    ```bash
    npx trace-sec install-skill                   # project: .agents/skills + .claude/skills
    npx trace-sec install-skill --global          # your home directory instead
    npx trace-sec install-skill --skills-only     # no plugin, no MCP config
    npx trace-sec install-skill --list
    ```

    It always writes the shared `.agents/skills/` directory and also
    `.claude/skills/` for Claude Code (`--agents` selects harness
    directories). It adds the `trace` server to `.mcp.json` and
    `.cursor/mcp.json` without touching your other MCP servers. For any other
    harness use the universal command above.

    To link skills from `node_modules` automatically, use a tool that scans
    npm packages for `skills/*/SKILL.md`, such as
    [skills-npm](https://github.com/antfu/skills-npm) (also reachable as
    `npx skills experimental_sync`). Install without the Python bootstrap if
    you only want skills:

    ```bash
    TRACE_SKIP_POSTINSTALL=1 npm install --save-dev trace-sec
    ```

=== "With pip"

    ```bash
    pip install trace-sec
    trace install-skill
    ```

    The wheel bundles the same skills.

## How they fit together

```text
trace                                   trace-fix
set up -> configure -> scan   ->   triage -> prioritize -> fix -> verify -> report
```

`trace` gets TRACE running and produces findings. `trace-fix` takes over from
the findings and verifies with `trace verify`, so the two share the same CLI
and MCP tools.

## Publishing (maintainers)

Skills are published two ways from this repository; no separate registry
account is needed.

1. **Git** (for `npx skills add`): any push to `main` makes the `skills/`
   folder installable. There is no publish command; the CLI reads the
   repository. Discovery looks for `skills/<name>/SKILL.md`.
2. **npm** (for `node_modules`-based tools): `package.json` lists `skills` in
   `files` and carries the `agent-skill` keyword, so each `npm publish` of
   `trace-sec` ships the skills at `skills/<name>/SKILL.md`. Check the
   tarball before a release:

   ```bash
   npm pack --dry-run --json | grep '"path": "skills/'
   ```

   The PyPI wheel bundles the same folders (`pyproject.toml`
   `force-include`).

Because skills travel with the tool, their version is `trace-sec`'s version.
Bump skill `metadata.version` with `scripts/release_tools.py bump`.

## Authoring rules

- One folder per skill: `skills/<name>/SKILL.md`, folder name equal to the
  `name` field (lowercase, hyphens, 1-64 chars).
- `description` is one line (max 1024 chars) and starts with when to use the
  skill. Keep `SKILL.md` under 500 lines; put detail in `references/*.md` and
  link it relatively.
- Stay harness-neutral: no agent-specific tool names or frontmatter. Describe
  CLI commands and MCP tools; both are available everywhere.
- Link sibling skills with `../other-skill/SKILL.md`. Keep the set small: new
  guidance belongs in `trace-fix/references/` or `trace/references/`, not in a
  new skill.
- `tests/test_skills_package.py` and `tests/test_skills_install.py` enforce
  the layout, links and installer behavior in CI.
