# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Two agent skills with clear roles. `trace` is the setup skill: a user installs only it, and the agent installs, configures (runtime, MCP, local target, scan scope), runs and troubleshoots TRACE. New `trace-fix` covers what to do with findings: triage, prioritization, per-language remediation playbooks, verification and reporting, plus OWASP/CWE mapping, coverage limits and CI gating.
- Skills are published through npm and PyPI: `skills` is in the npm `files` list with `agent-skill` keywords, and the wheel bundles them under `trace_engine/plugin/bundle/published-skills/`. `npx skills add` keeps working from git.
- `install-skill` is harness-agnostic: it writes the shared `.agents/skills/` directory plus `.claude/skills/`, and accepts `--global`, `--agents`, `--no-mcp`, `--skills-only` and `--list`; the Python installer installs the same skills.
- `release_tools.py bump` and `check` keep every skill's `metadata.version` in sync with the package version.
- Docs: new "What TRACE scans" page; refreshed CLI reference, cheat sheet, quick start, MCP, FAQ, troubleshooting, skills and release pages for current commands, the eighth MCP tool (`trace_status`) and `INCONCLUSIVE` verification.

### Changed

- Ingestion skips file formats no parser or adapter can use (HTML, CSS, JSON, YAML, TOML, SQL, Swift, C/C++) before opening them, so they cost no I/O, hashing or graph nodes. Callers can opt formats back in with `RepositoryScanner(languages=...)`; skipped counts are exposed as `skipped_by_language`.
- Ingestion also prunes more tool-cache and package-store directories (`.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.tox`, `.gradle`, `.dart_tool`, `Pods`, `site-packages`, ...) and skips `*.d.ts`, `*.bundle.js`, `*.chunk.js` and `*.egg-info`.

### Fixed

- `install-skill` no longer overwrites existing `.mcp.json` / `.cursor/mcp.json`; it merges the `trace` server and keeps other servers.
- The installed Claude Code skill directory no longer mismatches its `name` (it was `trace-security` for `trace-security-harness`); the separate harness runbook is no longer installed as a skill, since `trace-fix` covers it.
- The bundled harness runbook documents the real verification statuses (`FIXED`, `STILL_PRESENT`, `INCONCLUSIVE`) instead of a non-existent `RESOLVED`.

## [2.2.1] - 2026-10-17

### Fixed

- CLI root `--upgrade` / `--update`: adds options to Typer `main` callback and launcher normalization in `bin/trace.js`, resolving `No such option: --upgrade` when invoking `npx trace --upgrade` or `trace --upgrade`.
- CLI root `--doctor`: adds `--doctor` flag and command aliases (`diagnose`, `health`), optimizes environment diagnostics with 0.5s local Ollama ping and lightweight weight verification, preventing heavy PyTorch model initialization or accidental downloads during diagnostics.
- `version` subcommand: added first-class `trace version` command with `--json` output option, matching launcher behavior and complementing `--version`.
- `endpoints` aliases: added `epics`, `eps`, and `routes` aliases to `endpoints`, plus graceful parameter handling for `epics version`.
- `help` subcommand: added `trace help` command mapping to root Typer help output.
- `trace scan` offline stall: adds `--models/--no-models` (matching `audit`),
  probes target liveness once (`probe_target_online`) and skips runtime
  testpacks + chain escalation when OFFLINE, so static-only scans never hang
  on dead targets.
- Ingest walk pruning: `RepositoryScanner` prunes ignored trees
  (`ref/`, `venv/`, `datasets/`, ...) instead of `rglob("*")`-ing every file;
  single-read file hashing, memoized `fnmatch`, `.traceignore` gains `ref/`.
- Intelligence overhead: SecureBERT cache buffers writes (`set()` marks dirty,
  `flush()` persists once per batch + after single classify); APM
  `betweenness_centrality` sampling caps large graphs (>2000 nodes, seeded
  256 sources); Laya/SecureBERT `git lfs pull` now gated behind
  `TRACE_ALLOW_LFS_PULL=1`.
- MCP `trace_scan` refuses out-of-scope targets before repository scan.
- Tests: added `tests/test_cli_commands.py` covering all CLI commands, aliases, and flags; `--no-models` SARIF path, ingest-pruning + SecureBERT-cache suites, APM sampling determinism, stricter MCP refusal test.

## [2.2.0] - 2026-10-17

### Added

- Dev-line integration branch (`dev`) for staging fork work before upstream PRs.
- Explicit scan scopes (`--scope full|app|fixtures`): fixture/test trees can be excluded or isolated, with per-finding provenance labels and honest zero-endpoint reporting.
- ScopeGuard hardening: DNS-rebind rechecks, alt-IP/metadata blocks, port-0 rejection, register/allow separation with per-host rollback, guarded liveness probes.
- Patcher hardening: cross-platform absolute/UNC/drive rejection, null-byte and symlink handling, backup-dir containment.
- Hypothesis evidence gating: unsafe-SQL/template-sink requirements, stricter BFLA admin evidence, unregistered-route gate; Django decorator-method precedence and evidence-based database flags.
- Canary oracles (owner-marker leaks, SSRF fetch signatures, mass-assignment persist-and-reread) and a weighted multi-signal verdict engine gating BOLA confirmations.
- Declarative sink catalog (`security/sinks.toml` + sanitizer-aware matcher), consulted by the FastAPI adapter.
- Chain-mode escalation (`--chain`, capped at 10 probes): harvested leaks re-injected into other routes as `TR-CHAIN` findings.
- APM choke-point ranking plus minimum-cut size, surfaced in scan output and `trace_scan`.
- NPX-installable agent skill (`skills/trace`: audit, remediate, MCP setup) following the Agent Skills spec, with a spec validator test; install via `npx skills add VK-Amogh/TRACE --skill trace`.
- NPX global flags: `--verbose` (diagnostics + debug logs) and `--format` (validated injection for format-capable commands); launcher split into `bin/lib/` modules with lite-first provisioning.
- Release pipeline (`release.yml`): tag-gated PyPI (trusted publishing) + npm publishing with provenance and version-tag consistency check; npm skips when unconfigured instead of failing.
- Detailed CI matrix (`ci.yml`): Python 3.11–3.13 on Ubuntu/Windows/macOS, Node 18/20 shim checks, SARIF self-audit, plus a `testbed-full` job (CPU torch + LFS models) mirroring the hardcore suite.
- Accelerator-aware inference: shared `intelligence/device.py` resolver (CUDA → MPS → CPU for torch, CUDA → CoreML → OpenVINO → CPU cascade for ONNX, fp16 autocast on CUDA), wired into Laya, SecureBERT, and a new `trace doctor` Accelerators row. Overrides: `TRACE_DEVICE`, `TRACE_DTYPE`, `TRACE_ORT_PROVIDERS`.
- Docs site (`mkdocs.yml`, `docs/`) with `docs.yml` build/deploy workflow publishing to GitHub Pages.
- OSS contributor kit: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `ACCESSIBILITY.md`, `LICENSE` (Apache-2.0), issue/PR templates, Dependabot, `AGENTS.md`, `CITATION.cff`.
- Single-source versioning: `pyproject.toml` reads `__version__` from `src/trace_engine/__init__.py` dynamically.
- Source launchers (`trace.bat`, `trace.cmd`, `trace.ps1`) fall back to `PYTHONPATH=<repo>/src` for uninstalled checkouts.

### Fixed

- Operational reliability: bare `trace` without a terminal prints help instead of hanging; MCP server reports a suggested free port on bind conflicts; progress chatter goes to stderr so `--format json/markdown/sarif` stdout stays machine-parseable; update prompts never appear in non-interactive runs; `scan` emits report payloads to stdout when no `--output` file is given.
- Import weight: report-only output modules, doctor, and tool registry load lazily; CLI and MCP entry points import cleanly with no torch present (~11% faster startup).
- MCP server lightened and hardened: lazy per-tool imports, paginated findings with severity filter, truncated evidence, exact-first attack-path lookup, JSON-RPC errors instead of leaked internals, SSE session caps/TTL with 202 semantics, request size limits, non-loopback bind refusal without `--allow-remote`, and honored `profile`/`limit` schema options.
- Shared `trace_engine/constants.py` replaces scattered hardcoded targets, hosts, ports, timeouts, and probe tokens (all env-overridable).
- Verification oracle no longer reports `FIXED` for dead targets (INCONCLUSIVE instead) and weighs static re-index evidence; `ScopeGuard.allow_target` refuses non-local hosts; patcher paths are workspace-contained; remediator templates fixed (valid imports, balanced Kotlin, no hardcoded secrets, env-driven roots/domains).
- SARIF `codeFlows` now attach a `physicalLocation` to every attack hop (omitted when unlocatable) — GitHub code scanning accepts the upload again.
- `scan`/`test-all` no longer hard-exit when neural models are missing; they warn and continue with deterministic analysis (fixes CI SARIF job on LFS-less checkouts).
- APM path enumeration is capped (25 paths, depth-bounded) — full-repo scans no longer hang on dense graphs.
- Training test modules skip gracefully without `torch` instead of breaking pytest collection in lite installs.
- CI lint step runs under `bash` on all OSs (PowerShell rejected the `||` fallback).
- Hardcore testbed is macOS-proof: server fixture polls for readiness and loopback probes bypass environment proxies.
- Interactive MCP handoff imports `TraceMCPServer` instead of the non-existent `run_server`.
- BOLA testpack returns `0.0` instead of `None` when the target is unreachable, fixing a `ValidationError` on `TestExecutionResult.confidence`.
- Removed hardcoded `D:/Startup/...` model paths; resolution is now `~/.trace/models`, `$TRACE_MODELS_DIR`, then repo-local `models/`.
- Terminal renderer no longer forces ANSI output when piped (`force_terminal=None`), fixing noisy CI logs and part of the pytest colorama `atexit` noise.
- `run_doctor()` accepts an optional project path so the interactive menu diagnostics no longer crash with `TypeError`.
- Verification returns INCONCLUSIVE (and sends nothing) when the target is outside authorized scope; IPv4-mapped IPv6 loopback forms fail closed.

## [2.1.18] - 2026-10-01

### Added

- Multi-language AST adapters (Go, Django, Flask, PHP, Ruby, Rust, C#), multi-language auto-remediation, hardcore multi-service testbed, SARIF export, Welch t-test timing oracle, Bayesian neuro-symbolic confidence fusion.
