# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Added

- Canary oracles (owner-marker leaks, SSRF fetch signatures, mass-assignment persist-and-reread) and a weighted multi-signal verdict engine gating BOLA confirmations.
- Declarative sink catalog (`security/sinks.toml` + sanitizer-aware matcher), consulted by the FastAPI adapter.
- Chain-mode escalation (`--chain`, capped at 10 probes): harvested leaks re-injected into other routes as `TR-CHAIN` findings.
- APM choke-point ranking plus minimum-cut size, surfaced in scan output and `trace_scan`.
- NPX-installable agent skill (`skills/trace`: audit, remediate, MCP setup) following the Agent Skills spec, with a spec validator test; install via `npx skills add VK-Amogh/TRACE --skill trace`.
- NPX global flags: `--verbose` (diagnostics + debug logs) and `--format` (validated injection for format-capable commands); launcher split into `bin/lib/` modules with lite-first provisioning.
- Release pipeline (`release.yml`): tag-gated PyPI (trusted publishing) + NPM/GitHub Packages publishing with version-tag consistency check; NPM skips when unconfigured instead of failing.
- Detailed CI matrix (`ci.yml`): Python 3.11–3.13 on Ubuntu/Windows/macOS, Node 18/20 shim checks, SARIF self-audit, plus a `testbed-full` job (CPU torch + LFS models) mirroring the hardcore suite.
- Accelerator-aware inference: shared `intelligence/device.py` resolver (CUDA → MPS → CPU for torch, CUDA → CoreML → OpenVINO → CPU cascade for ONNX, fp16 autocast on CUDA), wired into Laya, SecureBERT, and a new `trace doctor` Accelerators row. Overrides: `TRACE_DEVICE`, `TRACE_DTYPE`, `TRACE_ORT_PROVIDERS`.
- Docs site (`mkdocs.yml`, `docs/`) with `docs.yml` build/deploy workflow publishing to GitHub Pages.
- OSS contributor kit: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `ACCESSIBILITY.md`, `LICENSE` (Apache-2.0), issue/PR templates, Dependabot, `AGENTS.md`, `CITATION.cff`.
- Single-source versioning: `pyproject.toml` reads `__version__` from `src/trace_engine/__init__.py` dynamically.
- Source launchers (`trace.bat`, `trace.cmd`, `trace.ps1`) fall back to `PYTHONPATH=<repo>/src` for uninstalled checkouts.

## [2.1.18] - 2026-10-01

### Added

- Multi-language AST adapters (Go, Django, Flask, PHP, Ruby, Rust, C#), multi-language auto-remediation, hardcore multi-service testbed, SARIF export, Welch t-test timing oracle, Bayesian neuro-symbolic confidence fusion.
