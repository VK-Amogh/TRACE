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
| Skip tests and fixtures | `trace audit . --scope app` |
| Skip neural models (fast, CI) | `trace audit . --no-models` |
| Full scan with live probes | `trace scan ./backend --target http://localhost:8000` |
| List stored findings | `trace findings` |
| Root cause + remediation for a finding | `trace explain TR-BOLA-001` |
| Replay its reproduction steps | `trace replay TR-BOLA-001` |
| Prove a fix worked | `trace verify TR-BOLA-001 --target http://localhost:8000` |
| Autonomous self-healing loop | `trace heal ./backend` |
| Export for GitHub code scanning | `trace scan . --format sarif -o trace-results.sarif` |
| Export Markdown / HTML / JSON report | `trace report -f markdown` |
| Inspect pipeline stages | `trace endpoints`, `trace apm`, `trace analyze` |
| Start the agent bridge | `trace mcp-server --port 8765` |
| Install the agent skills | `trace install-skill` |

## MCP tools (for agents)

| Tool | One-liner |
|---|---|
| `trace_scan` | full audit; returns counts and choke points (profile `quick` skips probes) |
| `trace_status` | is the repo initialized, how many findings, how many confirmed |
| `trace_findings` | query findings (`severity`, `limit`, `offset`) |
| `trace_explain` | root cause, evidence, reproduction, remediation for a finding |
| `trace_attack_path` | APM hops for an endpoint |
| `trace_verify` | prove the exploit vector is closed |
| `trace_harness_task` | export a SWE-bench-style task instance |
| `trace_eval_patch` | score a proposed patch (optional rollback) |

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

## Agent skills

```bash
npx skills add VK-Amogh/TRACE --skill trace   # universal: any of 75+ agents
npx trace-sec install-skill                   # trace + trace-fix, plus MCP config
npx trace-sec install-skill --list            # names only
```

`trace` = set up, configure, run. `trace-fix` = what to do with findings.

## Finding IDs and statuses

`TR-BOLA`, `TR-BFLA`, `TR-AUTH`, `TR-SSRF`, `TR-INJ`, `TR-MASS`,
`TR-TRAV`, `TR-SSTI`, `TR-CORS`, `TR-DESER`, plus `TR-CHAIN` for chained
escalations. The number is one counter per scan (`TR-BOLA-001`) and can
change when the code or scan changes.

Confidence: `CONFIRMED` (live probe reproduced it), `HIGH`, `MEDIUM`,
`POTENTIAL`. Verify: `FIXED`, `STILL_PRESENT`, `INCONCLUSIVE`.
