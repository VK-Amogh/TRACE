# TRACE audit cheat sheet

| Task | Command |
|---|---|
| Audit current repo | `npx trace-sec audit .` |
| Scan with live probes | `trace scan ./backend --target http://localhost:8000` |
| List findings | `trace findings` |
| Explain a finding | `trace explain TR-BOLA-001` |
| Reproduction steps | `trace replay TR-BOLA-001` |
| Prove a fix | `trace verify TR-BOLA-001` |
| Self-healing loop | `trace heal ./backend` |
| SARIF export | `trace scan . --format sarif -o trace-results.sarif` |
| Markdown / HTML report | `trace report -f markdown` |
| Health check | `trace doctor` |
| Agent bridge | `trace mcp-server --port 8765` |

Finding IDs: `TR-BOLA`, `TR-BFLA`, `TR-AUTH`, `TR-SSRF`, `TR-INJ`,
`TR-MASS`, `TR-TRAV`, `TR-SSTI`, `TR-CORS`, each numbered per finding.
