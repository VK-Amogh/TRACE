# Troubleshooting TRACE setup

| Symptom | Cause | Fix |
|---|---|---|
| `node: command not found` / `npx` missing | Node not installed | Ask the user to install Node 18+, or `pip install trace-sec` (Python 3.11+) and use `trace` |
| `Python 3.11+ is required` | No suitable interpreter; automatic install unavailable | Windows: `winget install Python.Python.3.12`; macOS: `brew install python`; Linux: `sudo apt install -y python3 python3-pip python3-venv` (ask the user). Or point `TRACE_PYTHON` at an interpreter |
| First run is slow | One-time venv + dependency install in `~/.trace/venv` | Wait; it does not repeat. `TRACE_SKIP_POSTINSTALL=1` skips the install-time step, the first command still provisions |
| `Automatic environment setup incomplete` | pip failed (offline, proxy) | `pip install git+https://github.com/VK-Amogh/TRACE.git` or fix the network and retry |
| `No module named 'trace_engine'` | Running from a source checkout without install | Use `trace.bat`/`trace.cmd`/`trace.ps1`, or `PYTHONPATH=src`, or `pip install -e .` |
| Scan appears to hang | Large tree, model provisioning, dead target | `--no-models`, `.traceignore`, `--scope app`; a dead target is probed once then skipped |
| Model download prompts or stalls (~1 GB) | Full mode requested | Stay on lite; pass `--no-models`; set `HF_HUB_OFFLINE=1` in CI |
| `Target ... refused` | Non-local host, or port not allowed | Use `http://127.0.0.1:<port>`; add the port to `allowed_ports` in `.trace/config.toml`. Never bypass `ScopeGuard` |
| 0 endpoints found | Unsupported framework/language, routes only in skipped config files, wrong path | Run `trace endpoints <path>`; check `--scope`; report it as a coverage gap, not a clean result |
| MCP tools do not appear | Server not registered or agent not restarted | `claude mcp list`; rerun `trace install-skill`; restart the agent; ensure `PYTHONUNBUFFERED=1` |
| MCP hangs on Windows | `npx` needs a shell wrapper | Use `command: cmd.exe`, `args: ["/c","npx","-y","trace-sec","mcp"]` |
| `verify` says `INCONCLUSIVE` | Target down/refused, finding not in the store, or static still flags it | Restart the target, pass the same `--target`, run `verify` before rescanning |
| `index.lock` / sync errors in OneDrive folders | Cloud sync locking files | Pause sync or work outside the synced folder |

Still stuck: `trace --verbose <command>` prints the resolved interpreter and
the exact command; `trace doctor` shows what is active.
