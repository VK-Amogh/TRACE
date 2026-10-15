---
title: Sub-second, zero-token security audits for AI coding agents
description: TRACE audits any backend in under a second on local CPU, correlates real vulnerabilities, and hands structured findings to AI coding agents over MCP. npx trace-sec audit .
---

# TRACE

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-wordmark-dark.svg">
    <img src="assets/logo-wordmark.svg" alt="TRACE — Security radar for agents" width="420">
  </picture>
</p>

TRACE reads a backend repository and tells you, in under a second and
with zero tokens, where it can actually be broken into — then hands the
proof to your coding agent to fix.

## Start here

1. [Install](installation.md) — lite on any machine, full where you want neural scoring.
2. [Run your first audit](quickstart.md) — one command, 60 seconds.
3. [Connect your agent](mcp.md) — seven tools over MCP, fixes proven by replay.

## How it works

```
source code → AST adapters → Attack-Path Model → hypotheses
→ live probes → Bayesian fusion → findings → verify
```

Static analysis proposes, live probes dispose, and the verification
oracle replays each exploit after a patch. A finding marked `FIXED`
means the attack is dead.

Everyday commands live on the [cheat sheet](cheatsheet.md); agents can
read the whole site from [llms.txt](llms.txt).
