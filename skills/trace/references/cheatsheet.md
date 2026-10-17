# TRACE command cheat sheet

Use `npx -y trace-sec` in place of `trace` when it is not installed globally.

| Task | Command |
|---|---|
| Health check | `trace doctor` |
| Install skills + MCP config | `trace install-skill` (`--list`, `--global`, `--skills-only`, `--no-mcp`) |
| Audit current repo (static) | `trace audit . --scope app --no-models` |
| Scan with live probes | `trace scan ./backend --target http://127.0.0.1:8000 --no-models` |
| List findings | `trace findings` |
| Explain a finding | `trace explain TR-BOLA-001` |
| Reproduction steps | `trace replay TR-BOLA-001` |
| Prove a fix | `trace verify TR-BOLA-001 --target http://127.0.0.1:8000` |
| Self-healing loop (review the diff) | `trace heal ./backend` |
| SARIF / JSON export | `trace scan . --format sarif -o trace-results.sarif` |
| Markdown / HTML report | `trace report -f markdown` |
| List routes | `trace endpoints .` |
| Agent bridge | `trace mcp-server --port 8765` |

Finding IDs: `TR-BOLA`, `TR-BFLA`, `TR-AUTH`, `TR-SSRF`, `TR-INJ`,
`TR-MASS`, `TR-TRAV`, `TR-SSTI`, `TR-CORS`, `TR-DESER`, plus `TR-CHAIN` for
chained escalations. The number is one counter per scan and can change.

Verify statuses: `FIXED`, `STILL_PRESENT`, `INCONCLUSIVE`.
Confidence: `CONFIRMED`, `HIGH`, `MEDIUM`, `POTENTIAL`.
