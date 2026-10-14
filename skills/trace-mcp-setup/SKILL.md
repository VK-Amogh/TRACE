---
name: trace-mcp-setup
description: Connect an AI coding agent (Claude Code, Cursor, opencode, Antigravity, Codex) to TRACE over MCP so it can scan, explain, and verify vulnerabilities. Use when asked to set up TRACE for an agent, enable trace tools, or troubleshoot a TRACE MCP connection.
license: Apache-2.0
compatibility: Requires Node.js 18+ for the npx bridge or a TRACE checkout with Python 3.11+.
metadata:
  author: TRACE Core Team
  version: "2.1.18"
---

# TRACE MCP Setup

## Claude Code (recommended)

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

## Manual bridge (any agent)

```bash
trace mcp-server --port 8765
```

Point the agent at `http://127.0.0.1:8765/sse`.

## What the agent gains

| Tool | Purpose |
|---|---|
| `trace_scan` | full audit, returns Attack-Path Model + findings |
| `trace_findings` | query findings with file paths and taint traces |
| `trace_explain` | root cause + remediation for a finding |
| `trace_attack_path` | APM hops for an endpoint |
| `trace_verify` | prove the exploit vector is closed |
| `trace_harness_task` | export a SWE-bench-style task instance |
| `trace_eval_patch` | score a proposed patch |

## Troubleshooting

- `trace doctor` must pass Core Runtime checks first.
- If stdio hangs, ensure `PYTHONUNBUFFERED=1` is set in the MCP config.
- Port in use: pass `--port` with a free port and update the agent config.
- Confirm tools with `trace tools` and packs with `trace testpacks`.
