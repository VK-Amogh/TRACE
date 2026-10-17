---
name: trace
description: Set up and run TRACE, the local security scanner for backend and API code, with nothing installed beforehand. Use when asked to scan code or an API for vulnerabilities, audit a repo, or set up TRACE or its MCP server, and whenever the trace command is missing, misconfigured or failing.
license: Apache-2.0
compatibility: Needs Node 18+ (or Python 3.11+ with pip). TRACE installs and configures itself on first use; live probes need the app running on localhost.
metadata:
  author: TRACE Core Team
  version: "2.2.1"
---

# TRACE: set up, configure, run

The user installed only this skill. You install and configure TRACE yourself,
run it, and then hand the findings to the [`trace-fix`](../trace-fix/SKILL.md)
skill. TRACE is local-first: zero tokens, no code leaves the machine.

## 1. Preflight: what is already there?

Run these in order and stop at the first that works:

| Check | Meaning |
|---|---|
| `trace --version` | TRACE is installed globally. Use plain `trace ...` below |
| `npx -y trace-sec --version` | Node is present; TRACE runs zero-install. Use `npx -y trace-sec ...` wherever this page says `trace` |
| `node --version` fails | Ask the user to install Node 18+ ([nodejs.org](https://nodejs.org)), or use `pip install trace-sec` if Python 3.11+ exists |

Prefer zero-install (`npx -y`). Ask before anything global (`npm install -g`,
`pip install`) or anything that installs software on the machine.

## 2. First run provisions itself

The first real command (not `--version`) creates an isolated Python
environment at `~/.trace/venv` with the lite dependencies, one time, about a
minute. Tell the user this is happening. If Python 3.11+ is missing, the
launcher installs it via `winget` (Windows) or Homebrew (macOS); on Linux it
prints a `sudo apt` hint, so ask the user to run it. Set
`TRACE_SKIP_PYTHON_INSTALL=1` to forbid the automatic install.

Then check health:

```bash
trace doctor          # Python, Tree-sitter, SQLite, models, adapters; never loads torch
```

Lite mode (default) is enough: AST analysis plus live probes. The full mode
adds ~1 GB of neural models and needs 8 GB RAM; install it only if the user
asks (`TRACE_FULL_DEPS=1`, or `pip install -r requirements.txt` in a checkout).
Pass `--no-models` to `scan` and `audit` to skip model provisioning entirely.

## 3. Connect the agent (MCP) and install the sibling skill

One command does both and keeps any MCP servers already configured:

```bash
trace install-skill        # skills in .agents/skills + .claude/skills, trace server in .mcp.json and .cursor/mcp.json
```

Alternatives: Claude Code only, `claude mcp add trace -- npx -y trace-sec mcp`;
other harnesses, `npx skills add VK-Amogh/TRACE --skill trace-fix -a <agent>`;
a generic MCP entry is `command: npx`, `args: ["-y","trace-sec","mcp"]`,
`env: {"PYTHONUNBUFFERED":"1"}` (on Windows, `command: cmd.exe`,
`args: ["/c","npx","-y","trace-sec","mcp"]`). Restart or reload the agent so
the new tools appear: `trace_scan`, `trace_status`, `trace_findings`,
`trace_explain`, `trace_attack_path`, `trace_verify`, `trace_harness_task`,
`trace_eval_patch`. Use MCP tools when available, the CLI otherwise; both run
the same engine.

## 4. Configure for this project

1. **What to scan.** Only source code in Python, JS/TS, Java/Kotlin, Go, PHP,
   Ruby, Rust, C# and Dart is read; HTML, CSS, JSON, YAML, SQL and similar are
   skipped. Add noisy folders (datasets, generated code) to `.traceignore`
   (one glob per line). Use `--scope app` to leave out tests and fixtures.
2. **A local target for live proof.** Find how the app starts (package.json
   scripts, `uvicorn`, `flask run`, `manage.py runserver`, Docker Compose),
   tell the user what you will run, start it on localhost in the background and
   wait for it to answer. Without a reachable target the scan is static-only:
   no finding can be `CONFIRMED`, and missing runtime evidence means "not
   tested". Never point TRACE at a remote or production host: `ScopeGuard`
   refuses, and you must not widen `allowed_hosts`.
3. **Port allow-list.** `.trace/config.toml` (created on first scan) lists
   `allowed_ports` (80, 443, 3000, 5000, 8000, 8080, 18080 by default). If the
   dev server uses another local port, add it there. Probe limits live in the
   same file (`max_requests`, `rate_limit_per_second`, `destructive_tests =
   false`); keep them conservative.
4. **Probe identities.** Probes use synthetic bearer tokens (`user-a`,
   `user-b`, `admin`). An app that validates real JWTs may reject them, so
   treat a missing runtime confirmation as weak evidence.

## 5. Run

| Goal | CLI | MCP |
|---|---|---|
| Fast static audit | `trace audit . --scope app --no-models` | `trace_scan {"repository": ".", "profile": "quick"}` |
| Scan with live probes | `trace scan . --target http://127.0.0.1:8000 --no-models` | `trace_scan {"repository": ".", "target": "http://127.0.0.1:8000"}` |
| List / detail | `trace findings`, `trace explain TR-BOLA-001` | `trace_findings`, `trace_explain` |
| JSON, Markdown, SARIF | `trace scan . --format json -o findings.json` (or `markdown`, `sarif`); `trace report -f html` | n/a |
| Prove a fix | `trace verify TR-BOLA-001 --target <url>` | `trace_verify` |

Facts to keep straight: `scan` and `audit` exit 0 even when findings exist;
each scan overwrites `.trace/findings.json` and finding numbers can change;
never commit `.trace/` or `*.sarif`.

## 6. Hand off

When a scan finishes, summarize counts by severity and confidence, say whether
it ran static-only or with live probes, then continue with the
[`trace-fix`](../trace-fix/SKILL.md) skill to triage, prioritize, fix and
verify. If it is not installed, run `trace install-skill`.

## When something fails

Common errors and fixes: [references/troubleshooting.md](references/troubleshooting.md).
Every command on one page: [references/cheatsheet.md](references/cheatsheet.md).
