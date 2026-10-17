# CLI reference

Run `trace --help` or `trace <command> --help` for every flag. Commands have
aliases (listed in parentheses) so common spellings just work.

## Global flags

Handled by the `npx`/Node launcher before delegating to Python:

| Flag | Effect |
|---|---|
| `--verbose` | echo resolved interpreter + command; enable debug logs |
| `--format <fmt>` | inject `--format` for `scan`, `audit`, `test-all`, `report` (validated; exit 2 otherwise) |
| `--version`, `-v`, `-V`, `version` | instant version, no Python needed |
| `--upgrade`, `--update` | check for a newer release and upgrade |
| `--doctor` | environment health check (same as `trace doctor`) |

## Scan and analyze

| Command | Purpose | Formats |
|---|---|---|
| `trace` | Interactive security wizard (`interactive`, `story`) | n/a |
| `trace audit <path>` (`test-all`) | Sub-second static audit across all languages | table, markdown, json |
| `trace scan <path> --target <url>` | Audit + live probes + chain escalation | table, markdown, json, sarif |
| `trace index <path>` | Index source files and AST symbols | n/a |
| `trace endpoints <path>` (`routes`, `epics`, `eps`) | Discover endpoints, parameters, auth gates | n/a |
| `trace apm <path>` | Build and inspect the Attack-Path Model | n/a |
| `trace analyze <path>` | Derive security hypotheses | n/a |
| `trace test <path>` | Run test packs against hypotheses | n/a |

Common `scan` / `audit` options:

| Option | Effect |
|---|---|
| `--target`, `-t` | Runtime URL; must be local or a lab. Default `http://127.0.0.1:18080` (env `TRACE_TARGET_URL`). Unreachable targets fall back to static-only |
| `--format`, `-f` / `--output`, `-o` | Output format and file (`scan` also accepts `.sarif`, `.json`, `.md` extensions) |
| `--scope full\|app\|fixtures` | `full` everything, `app` skips fixture/test dirs, `fixtures` only those |
| `--models` / `--no-models` | Provision or skip the neural models (skip for speed and CI) |
| `--chain` / `--no-chain` | `scan` only: re-inject harvested leaks into other routes (bounded) |

Which files are read, and which formats are skipped: [Ingestion](ingestion.md).

Both commands exit 0 even when findings exist. To gate CI, inspect the JSON
output (see the `trace-fix` skill, `references/ci-integration.md`).

## Findings and verification

| Command | Purpose |
|---|---|
| `trace findings [path\|id]` (`finding`) | List stored findings, or detail for one ID |
| `trace explain <id>` | Root cause, attack path, remediation |
| `trace replay <id>` | Print the reproduction steps |
| `trace report [path\|id] -f markdown\|html\|json\|sarif` | Export a report to `.trace/reports/` (or `-o`); `--finding <id>` filters |
| `trace verify <id> --target <url>` | Oracle verdict (below) |
| `trace heal <path>` (`remediate`) | Autonomous rule-guided patch + verify loop |
| `trace target` | Next highest-priority remediation packet for an agent |
| `trace eval-patch` | Score an agent's patch against the oracle |

`verify` returns exactly one of:

| Status | Meaning |
|---|---|
| `FIXED` | A live probe reached the target, the exploit no longer reproduces, and the static re-index no longer flags it |
| `STILL_PRESENT` | The exploit still works at runtime |
| `INCONCLUSIVE` | Target down or refused by scope policy, finding not in the store, or static analysis still flags it. Never treat as fixed |

Restart the target after patching, and run `verify` before rescanning:
every scan overwrites `.trace/findings.json` and finding numbers can change.

## Agents, skills and MCP

| Command | Purpose |
|---|---|
| `trace mcp` | MCP server over stdio (Claude Code, Cursor) |
| `trace mcp-server --port 8765` (`serve-mcp`) | HTTP/SSE MCP bridge for any agent |
| `trace setup-mcp` | Generate `.mcp.json` (keeps your other servers) |
| `trace install-skill` (`setup-agent`, `install-agent`) | Install the TRACE skills into your agent harnesses ([Agent skills](skills.md)) |
| `trace plugin install\|status\|...` | Manage the agent harness plugin |

`install-skill` options (Node launcher): `--global`/`-g`, `--agents <list>`,
`--no-mcp`, `--skills-only`, `--list`. The Python command takes `--global`,
`--workspace`, `--path`.

## Environment and models

| Command | Purpose |
|---|---|
| `trace doctor` (`diagnose`, `health`) | Python, Tree-sitter, SQLite, Ollama, tool adapters; never loads torch |
| `trace upgrade` (`update`) | Upgrade TRACE |
| `trace tools` / `trace testpacks` | List external tool adapters / registered test packs |
| `trace intelligence` | Status of the SecureBERT and Laya models |
| `trace download-models` (`setup-models`) | Provision model weights into `~/.trace/models` |
| `trace init` | Create the `.trace/` directory and default config |
| `trace lab start\|status` | Run the bundled vulnerable Vending API lab |
| `trace benchmark`, `trace bench`, `trace benchmark-models`, `trace train` | Evaluation and training tooling |
| `trace guide` (`architecture`, `how-it-works`), `trace welcome`, `trace help` | Guided tours and help |

The single version source is `src/trace_engine/__init__.py:__version__`.
