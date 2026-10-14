---
name: trace
description: Audit any codebase for OWASP API vulnerabilities with TRACE, fix the findings, and connect agents over MCP. Use when asked to scan for security issues, explain TR-BOLA/TR-SSRF findings, remediate vulnerabilities with live verification, or set up TRACE for Claude Code, Cursor, opencode, or Antigravity.
license: Apache-2.0
compatibility: Requires the trace-sec CLI (npx trace-sec) for audits; Python 3.11+ checkout for engine work; a local target for live probes.
metadata:
  author: TRACE Core Team
  version: "2.1.18"
---

# TRACE

Sub-second, zero-token security audits plus verified remediation.
Three workflows; pick the one the user asked for.

Every workflow below shows **both calling styles**. Prefer MCP tools when
the agent host offers them (structured results, no shell parsing);
otherwise use the CLI. Both hit the same engine.

## 1. Audit

| Step | CLI | MCP tool |
|---|---|---|
| Audit repo | `npx trace-sec audit .` | `trace_scan {"repository": "."}` |
| Scan + probes | `trace scan ./backend --target http://localhost:8000` | `trace_scan {"repository": "./backend", "target": "http://localhost:8000"}` |
| List findings | `trace findings` | `trace_findings {}` (supports `severity`, `limit`, `offset`) |
| Explain one | `trace explain TR-BOLA-001` | `trace_explain {"finding_id": "TR-BOLA-001"}` |
| Reproduce | `trace replay TR-BOLA-001` | read `reproduction_steps` from `trace_explain` |
| Attack path | — | `trace_attack_path {"endpoint": "/api/items/{id}"}` |

Findings carry `category` (BOLA, BFLA, AUTH, SSRF, INJECTION,
MASS_ASSIGNMENT, PATH_TRAVERSAL, SSTI, CORS), `severity`, `endpoint`,
`source_location`, `attack_path`, evidence, and `remediation`.
Explain what the endpoint does, how the path reaches the sink, and the
minimal fix. Never claim a fix works without verifying (workflow 2).

## 2. Remediate

One finding at a time: ingest (`trace findings` / `trace_findings`) →
diagnose (`trace explain` / `trace_explain`, read the evidence, never
guess) → plan the invariant in one sentence → patch minimally (see
[references/patch-patterns.md](references/patch-patterns.md)) → verify:

| Step | CLI | MCP tool |
|---|---|---|
| Verify fix | `trace verify TR-BOLA-001` | `trace_verify {"finding_id": "TR-BOLA-001"}` |
| Score a patch | — | `trace_eval_patch {"finding_id": "...", "target_file": "...", "patch_content": "...", "rollback_after": true}` |
| Auto-heal loop | `trace heal ./backend` | — |
| Benchmark task | — | `trace_harness_task {"finding_id": "..."}` |

`FIXED` with the runtime check passed means done. `STILL_PRESENT` means
return to diagnosis.

## 3. Connect an agent over MCP

```bash
claude mcp add trace -- npx -y trace-sec mcp   # Claude Code
trace mcp-server --port 8765                   # manual bridge for any agent
```

Tools gained: `trace_scan`, `trace_findings`, `trace_explain`,
`trace_attack_path`, `trace_verify`, `trace_harness_task`,
`trace_eval_patch`. If stdio hangs, ensure `PYTHONUNBUFFERED=1`.

## Scope rules

Only audit systems the user owns or the bundled fixtures
(`testbed_hardcore/`, `test-repository/`, `labs/`). `ScopeGuard` blocks
non-local targets — never bypass it. Never commit `.trace/` output or
`*.sarif` files.

See [references/cheatsheet.md](references/cheatsheet.md) for every command
on one page.
