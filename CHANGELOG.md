# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `run_doctor()` accepts an optional project path so the interactive menu diagnostics no longer crash with `TypeError`.
- Interactive MCP handoff imports `TraceMCPServer` instead of the non-existent `run_server`.
- BOLA testpack returns `0.0` instead of `None` when the target is unreachable, fixing a `ValidationError` on `TestExecutionResult.confidence`.
- Removed hardcoded `D:/Startup/...` model paths; resolution is now `~/.trace/models`, `$TRACE_MODELS_DIR`, then repo-local `models/`.
- Terminal renderer no longer forces ANSI output when piped (`force_terminal=None`), fixing noisy CI logs and part of the pytest colorama `atexit` noise.

### Added

- Detailed CI matrix (`ci.yml`): Python 3.11–3.13 on Ubuntu/Windows/macOS, Node 18/20 shim checks, SARIF self-audit.
- OSS contributor kit: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `LICENSE` (Apache-2.0), issue/PR templates, Dependabot, `AGENTS.md`, `CITATION.cff`.
- Source launchers (`trace.bat`, `trace.cmd`, `trace.ps1`) fall back to `PYTHONPATH=<repo>/src` for uninstalled checkouts.

## [2.1.18] - 2026-10-01

### Added

- Multi-language AST adapters (Go, Django, Flask, PHP, Ruby, Rust, C#), multi-language auto-remediation, hardcore multi-service testbed, SARIF export, Welch t-test timing oracle, Bayesian neuro-symbolic confidence fusion.
