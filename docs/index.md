---
title: Sub-second, zero-token security audits for AI coding agents
description: TRACE audits any backend in under a second on local CPU, correlates real vulnerabilities, and hands structured findings to AI coding agents over MCP. npx trace-sec audit .
---

# TRACE: the security radar for coding agents

**Full-repo audit in 0.26 s on local CPU. Zero tokens. No cloud.**

[![npm version](https://img.shields.io/npm/v/trace-sec?color=black)](https://www.npmjs.com/package/trace-sec)
[![CI](https://github.com/auraflaa/TRACE/actions/workflows/ci.yml/badge.svg)](https://github.com/auraflaa/TRACE/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-black)](https://github.com/auraflaa/TRACE/blob/main/LICENSE)

```bash
npx trace-sec audit .
```

```bash
trace scan ./backend --target http://localhost:8000
trace explain TR-BOLA-001
trace verify TR-BOLA-001
```

<div class="grid cards" markdown>

- **Audit it**

    Sub-second static audit, live probes, SARIF export for the Security tab.

    [`trace audit .`](quickstart.md) · [`trace scan`](cli.md)

- **Connect your agent**

    Claude Code, Cursor, or Antigravity gain seven security tools over MCP.

    [`claude mcp add trace`](mcp.md) · [harness skill](harness.md)

- **Prove the fix**

    The verification oracle replays the exploit. `FIXED` means dead, not linted.

    [`trace verify`](cli.md) · [why trust a finding](quickstart.md#why-trust-a-finding)

- **Run it anywhere**

    Lite on 4 GB with no torch, full with neural scoring on 8 GB.

    [Lite or Full](lite-or-full.md) · [installation](installation.md)

</div>

## How it works

```
source code → AST adapters → Attack-Path Model → hypotheses
→ testpacks (live probes) → Bayesian fusion → findings → verify
```

Every common task on one page: **[cheat sheet](cheatsheet.md)**. AI assistants
can read the whole documentation from [`llms.txt`](llms.txt).
