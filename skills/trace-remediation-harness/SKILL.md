---
name: trace-remediation-harness
description: Fix TRACE vulnerability findings end to end — ingest findings, diagnose the attack path, plan a minimal patch, apply it, and verify with the live exploit oracle. Use when asked to remediate, fix, or patch a TR-BOLA, TR-BFLA, TR-SSRF, or other TRACE finding, or to work through the TRACE Agent Harness.
license: Apache-2.0
compatibility: Requires a TRACE audit already run (findings store present) plus file-edit tools; live verification needs the target service running locally.
metadata:
  author: TRACE Core Team
  version: "2.1.18"
---

# TRACE Remediation Harness

Fix one finding at a time through five phases. Do not skip verification.

```
[Ingest] → [Diagnose] → [Plan] → [Patch] → [Verify]
```

## Phase 1: Ingest

```bash
trace findings                          # or MCP trace_findings
```

Pick the highest-severity finding. Note its `id`, `category`, `endpoint`,
and `source_location`. For benchmark tasks: `trace_harness_task`.

## Phase 2: Diagnose

```bash
trace explain <finding-id>              # or MCP trace_explain
```

Read `attack_path` (entrypoint → sink hops), `static_evidence` (AST facts),
`runtime_evidence` (probe proofs), and `remediation` guidance. Never guess
the fix — the evidence names the missing invariant. See
[references/patch-patterns.md](references/patch-patterns.md) for the
per-category invariants.

## Phase 3: Plan

State the invariant in one sentence before editing, e.g. "every record
lookup must be scoped to the caller's tenant". Keep the patch minimal and
idiomatic; touch nothing unrelated.

## Phase 4: Patch

Apply with file-edit tools. Keep a way back: TRACE's `SafePatcher`
writes timestamped backups under `.trace/backups/` and rolls back on
failed verification (`trace heal` automates this loop).

## Phase 5: Verify

```bash
trace verify <finding-id>               # or MCP trace_verify
```

`FIXED` with the runtime check passed means done. `STILL_PRESENT` means
return to Phase 2 — do not stack more edits on a disproven theory. After
three failed attempts, stop and question the approach with the user.
