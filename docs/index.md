# TRACE — Threat Reconnaissance & Attack-path Correlation Engine

The sub-second, zero-token security radar for AI coding agents. TRACE audits a
repository in milliseconds on local CPU — no tokens, no cloud — then feeds
structured findings to Claude Code, Cursor, or Codex through MCP for surgical
fixes verified by a live oracle.

## How it works

```
source code → AST adapters → Attack-Path Model (graph) → hypotheses
→ testpacks (live probes) → Bayesian fusion → findings → verify
```

- **Static layer:** multi-framework AST adapters (FastAPI, Django, Flask,
  Express, Next.js, Gin, Spring Boot, Laravel, Rails, …).
- **Graph layer:** an in-memory directed Attack-Path Model links routes to
  handlers, auth gates, databases, and external services.
- **Confidence layer:** SecureBERT 2.0 + AST dataflow + live probes fused as
  `1 − (1−P₁)(1−P₂)(1−P₃)`, with sanitizer attenuation.
- **Agent layer:** MCP server plus a verify oracle, so fixes are proven, not
  assumed.

## Start here

1. [Installation](installation.md) — lite vs full installs per device.
2. [Quick start](quickstart.md) — your first audit in 60 seconds.
3. [MCP setup](mcp.md) — connect your coding agent.
4. [CLI reference](cli.md) — every command.
