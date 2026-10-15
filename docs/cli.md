# CLI reference

NPX global flags (handled before delegating to Python):

| Flag | Effect |
|---|---|
| `--verbose` | echo resolved interpreter + command; enable debug logs |
| `--format <fmt>` | inject `--format` for `scan`, `audit`, `test-all`, `report` (validated; exit 2 otherwise) |
| `--version`, `-v` | instant version, no Python needed |

| Command | Purpose | Formats |
|---|---|---|
| `trace` | Interactive security wizard | — |
| `trace audit <path>` | Sub-second static audit | table, markdown, json |
| `trace scan <path> --target <url>` | Audit + live probes, with report output | table, markdown, json, sarif |
| `trace findings` | List stored findings | — |
| `trace explain <id>` | Root cause, attack path, remediation | — |
| `trace replay <id>` | Print reproduction steps | — |
| `trace verify <id>` | Oracle verdict: `FIXED` / `STILL_PRESENT` | — |
| `trace heal <path>` | Autonomous AST self-healing loop | — |
| `trace mcp-server --port 8765` | MCP bridge for agents | — |
| `trace report -f markdown\|html\|json\|sarif` | Export `.trace/reports/` | markdown, html, json, sarif |
| `trace doctor` | Environment health check | — |
| `trace endpoints` / `trace apm` / `trace analyze` | Pipeline inspection stages | — |

Run `trace --help` or `trace <command> --help` for flags.
The single version source is `src/trace_engine/__init__.py:__version__`.
