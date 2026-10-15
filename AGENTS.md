# AGENTS.md

Guidance for AI coding agents working with or on TRACE.

## Using the package

```bash
npx trace-sec audit .                  # sub-second audit, zero tokens
trace scan ./backend --target http://localhost:8000
trace explain TR-BOLA-001
trace verify TR-BOLA-001               # oracle: FIXED / STILL_PRESENT
```

- MCP tools for agents: `trace_scan`, `trace_findings`, `trace_explain`, `trace_attack_path`, `trace_verify`, `trace_harness_task`, `trace_eval_patch` (see `src/trace_engine/mcp/server.py`).
- Skill runbook for fixes: `.agents/skills/trace-security-harness/SKILL.md` (Ingest → Diagnose → Plan → Patch → Verify).
- Only test systems you own or the bundled fixtures (`testbed_hardcore/`, `test-repository/`, `labs/`). `ScopeGuard` (`src/trace_engine/policy/scope.py`) blocks non-local targets — never bypass it.

## Developing

```bash
pip install -e ".[dev]"                # lite install, no heavy AI deps
pip install -r requirements.txt        # full AI inference (torch, ~8 GB RAM)
pytest -q                              # pythonpath=src is set in pyproject.toml
```

- Pipeline: `ingest → parse → framework adapters → apm → hypotheses → testpacks → correlate → findings` (entry: `src/trace_engine/cli.py`, shared logic belongs in a `ScanService`, not copy-pasted per command).
- Single version source: `src/trace_engine/__init__.py:__version__` (pyproject reads it dynamically). Bump it together with `package.json`.
- Commit titles: conventional lowercase prefix (`fix:`, `feat:`, `docs:`, `ci:`), no body unless needed.
- Never commit secrets, `.trace/` output, `*.sarif`, or model binaries (`*.pt`, `*.onnx`, `*.safetensors` go through Git LFS).
- `ref/` holds ignored reference clones for inspiration — never import from it.
