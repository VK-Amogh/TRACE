# MCP setup (Claude Code, Cursor, Antigravity)

## Claude Code (recommended)

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

## Manual bridge

```bash
trace mcp-server --port 8765
```

Connect the agent to `http://127.0.0.1:8765/sse`.

## Tools the agent gains

| Tool | Purpose |
|---|---|
| `trace_scan` | Full audit, returns Attack-Path Model + findings |
| `trace_findings` | Query findings with file paths and taint traces |
| `trace_explain` | Root cause + remediation for a finding |
| `trace_attack_path` | APM hops for an endpoint |
| `trace_verify` | Prove the exploit vector is closed |
| `trace_harness_task` | Export a SWE-bench-style task instance |
| `trace_eval_patch` | Score a proposed patch |

See also: [Security harness skill](harness.md).
