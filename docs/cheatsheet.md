# Cheat sheet

Everything you usually need, on one page. Every snippet runs as written once
TRACE is installed ([installation](installation.md)).

## Install

```bash
npm install -g trace-sec          # global CLI: trace, trace-sec
pip install -e ".[dev]"           # contributors: lite + test/lint tooling
pip install -r requirements.txt   # + full AI inference (torch, ~8 GB RAM)
trace doctor                      # what is active on your machine
```

## Command line

| Task | Command |
|---|---|
| Sub-second audit of the current repo | `trace audit .` |
| Full scan with live probes | `trace scan ./backend --target http://localhost:8000` |
| List stored findings | `trace findings` |
| Root cause + remediation for a finding | `trace explain TR-BOLA-001` |
| Replay its reproduction steps | `trace replay TR-BOLA-001` |
| Prove a fix worked | `trace verify TR-BOLA-001` |
| Autonomous self-healing loop | `trace heal ./backend` |
| Export for GitHub code scanning | `trace scan . --format sarif -o trace-results.sarif` |
| Export Markdown / HTML / JSON report | `trace report -f markdown` |
| Inspect pipeline stages | `trace endpoints`, `trace apm`, `trace analyze` |
| Start the agent bridge | `trace mcp-server --port 8765` |

## MCP tools (for agents)

| Tool | One-liner |
|---|---|
| `trace_scan` | full audit, returns Attack-Path Model + findings |
| `trace_findings` | query findings with file paths and taint traces |
| `trace_explain` | root cause + remediation for a finding |
| `trace_attack_path` | APM hops for an endpoint |
| `trace_verify` | prove the exploit vector is closed |
| `trace_harness_task` | export a SWE-bench-style task instance |
| `trace_eval_patch` | score a proposed patch |

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

## Finding IDs

`TR-BOLA`, `TR-BFLA`, `TR-AUTH`, `TR-SSRF`, `TR-INJ`, `TR-MASS`,
`TR-TRAV`, `TR-SSTI`, `TR-CORS` — numbered per finding (`TR-BOLA-001`).
