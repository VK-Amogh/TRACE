---
name: trace-security-audit
description: Audit any codebase for OWASP API vulnerabilities with TRACE in under a second — scan, read findings, explain root causes. Use when asked to check code for security issues, run a vulnerability audit, triage TRACE findings, or explain what TR-BOLA, TR-SSRF, or other TRACE finding IDs mean.
license: Apache-2.0
compatibility: Requires the trace-sec CLI (npx trace-sec) or a TRACE MCP server; no GPU or network needed for static audits.
metadata:
  author: TRACE Core Team
  version: "2.1.18"
---

# TRACE Security Audit

Run a complete vulnerability audit with TRACE — sub-second, zero tokens,
fully local — then read and explain the findings.

## 1. Run the audit

```bash
npx trace-sec audit .                  # current repo, table output
trace scan ./backend --target http://localhost:8000   # + live probes
trace scan . --format sarif -o trace-results.sarif    # GitHub code scanning
```

No install needed beyond Node.js for `npx`. For the richest results
(neural scoring), use a checkout with `pip install -r requirements.txt`.

## 2. Read the findings

```bash
trace findings                          # ranked table with IDs and severities
```

Via MCP: `trace_findings`, then `trace_explain` for any finding ID.
Each finding carries: `category` (BOLA, BFLA, AUTH, SSRF, INJECTION,
MASS_ASSIGNMENT, PATH_TRAVERSAL, SSTI, CORS), `severity`, `endpoint`,
`source_location` (file + lines), `attack_path` hops, `static_evidence`,
`runtime_evidence`, and `remediation`.

## 3. Explain one finding

```bash
trace explain TR-BOLA-001
trace replay TR-BOLA-001               # reproduction steps
```

Explain to the user: what the endpoint does, how the attack path reaches
the sink, why the evidence confirms (or only suggests) the flaw, and the
minimal fix. Never claim a fix works without `trace verify` — that belongs
to the `trace-remediation-harness` skill.

## Scope rules

Only audit systems the user owns or the bundled fixtures
(`testbed_hardcore/`, `test-repository/`, `labs/`). `ScopeGuard` blocks
non-local targets — never bypass it. Never commit `.trace/` output or
`*.sarif` files.

See [references/cheatsheet.md](references/cheatsheet.md) for every command
on one page.
