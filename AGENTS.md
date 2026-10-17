# AGENTS.md

Guidance for AI coding agents working with or on TRACE.

## Using the package

```bash
npx trace-sec audit .                  # sub-second audit, zero tokens
trace scan ./backend --target http://localhost:8000
trace explain TR-BOLA-001
trace verify TR-BOLA-001               # oracle: FIXED / STILL_PRESENT / INCONCLUSIVE
```

- MCP tools for agents: `trace_scan`, `trace_status`, `trace_findings`, `trace_explain`, `trace_attack_path`, `trace_verify`, `trace_harness_task`, `trace_eval_patch` (see `src/trace_engine/mcp/server.py`).
- Skills (open SKILL.md format, harness-agnostic), in `skills/`: `trace` (set up, configure and run TRACE; the only one users must install) and `trace-fix` (triage → prioritize → fix → verify → report, with OWASP/CWE and CI guidance). Install with `npx skills add VK-Amogh/TRACE` or `npx trace-sec install-skill`.
- `INCONCLUSIVE` is never "fixed". Restart the target after patching and run `trace verify` before rescanning (scans overwrite `.trace/findings.json` and renumber IDs).
- Only test systems you own or the bundled fixtures (`testbed_hardcore/`, `test-repository/`, `labs/`). `ScopeGuard` (`src/trace_engine/policy/scope.py`) blocks non-local targets — never bypass it.

## Developing

```bash
pip install -e ".[dev]"                # lite install, no heavy AI deps
pip install -r requirements.txt        # full AI inference (torch, ~8 GB RAM)
pytest -q                              # pythonpath=src is set in pyproject.toml
```

- Pipeline: `ingest → parse → framework adapters → apm → hypotheses → testpacks → correlate → findings` (entry: `src/trace_engine/cli.py`, shared logic belongs in a `ScanService`, not copy-pasted per command).
- Ingestion reads only languages in `ANALYZED_LANGUAGES` (`src/trace_engine/ingest/files.py`); markup, styles and data/config formats are skipped before being opened. Do not map or hash files no adapter can use.
- Skills ship in the npm package (`skills/` in `package.json` `files`) and the wheel; keep them harness-neutral and their `metadata.version` equal to the package version (`scripts/release_tools.py` enforces it).
- Single version source: `src/trace_engine/__init__.py:__version__` (pyproject reads it dynamically). Bump it together with `package.json`.
- Commit titles: conventional lowercase prefix (`fix:`, `feat:`, `docs:`, `ci:`), no body unless needed.
- Never commit secrets, `.trace/` output, `*.sarif`, or model binaries (`*.pt`, `*.onnx`, `*.safetensors` go through Git LFS).
- `ref/` holds ignored reference clones for inspiration — never import from it.

## Pull Request Policy

- Do NOT open PRs automatically or for every change. Only open PRs when explicitly requested.
- When creating a PR, strictly follow the standardized template defined in `.github/pull_request_template.md` (Summary, Type of Change, Detailed Context, Verification & Test Evidence, and Security & Repository Guidelines Checklist).
- Work on `auraflaa:main` and submit PRs to `VK-Amogh:main`. Never create separate branches on the target repository unless explicitly asked.
