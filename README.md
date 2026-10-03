# TRACE — Threat Reconnaissance & Attack-path Correlation Engine

Local-first application security analysis and runtime validation engine.

## Overview
TRACE reconstructs the relationship between source code, routes, authentication gates, user parameters, and backend sinks to build an **Attack-Path Model (APM)**. It then validates potential vulnerabilities through controlled, scoped runtime test packs.

## Core Commands
- `trace`: Interactive welcome screen and command guide
- `trace init [REPO]`: Initialize TRACE configuration in target repository
- `trace index [REPO]`: AST parsing and symbol extraction
- `trace endpoints [REPO]`: API route discovery and auth gate detection
- `trace apm [REPO]`: Attack-Path Model graph construction and SQLite persistence
- `trace analyze [REPO]`: Deterministic security signal extraction
- `trace test [REPO] --target <URL>`: Execute controlled security test packs
- `trace scan [REPO] --target <URL>`: End-to-end static + runtime evidence correlation
- `trace findings`: View correlated security findings
- `trace explain <ID>`: Deep-dive root-cause analysis
- `trace doctor`: Diagnostic environment and tool verification
- `trace lab start`: Launch the reference vulnerable Vending API lab
