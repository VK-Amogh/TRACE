# MCP setup (Claude Code, Cursor, Antigravity)

## Claude Code (recommended)

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

## Cursor and other MCP clients

`npx trace-sec install-skill` adds a `trace` server to `.mcp.json` and
`.cursor/mcp.json` and keeps any servers already listed there (`--no-mcp`
skips it). `trace setup-mcp` writes `.mcp.json` only, also preserving other
servers.

## Manual bridge

```bash
trace mcp-server --port 8765
```

Connect the agent to `http://127.0.0.1:8765/sse`.

## Tools the agent gains

| Tool | Purpose |
|---|---|
| `trace_scan` | Full audit; returns counts, endpoints audited and choke points. `profile: quick` skips live probes; `scope` mirrors the CLI; non-local `target` values are refused |
| `trace_status` | Whether the repo is initialized, total findings, confirmed findings |
| `trace_findings` | Query findings; filter by minimum `severity`, page with `limit` / `offset` |
| `trace_explain` | Root cause, evidence, reproduction steps and remediation for a finding |
| `trace_attack_path` | APM hops for an endpoint |
| `trace_verify` | Prove the exploit vector is closed (`FIXED` / `STILL_PRESENT` / `INCONCLUSIVE`) |
| `trace_harness_task` | Export a SWE-bench-style task instance |
| `trace_eval_patch` | Score a proposed patch, optionally rolling it back |

Scans skip file formats TRACE cannot analyze; see
[What TRACE scans](ingestion.md). Pair the tools with the
[agent skills](skills.md) so the agent also knows how to read the results.

See also: [Security harness skill](harness.md).
