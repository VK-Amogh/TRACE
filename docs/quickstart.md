# Quick start

```bash
# Interactive wizard
trace

# Sub-second audit of the current repo (skip tests/fixtures with --scope app)
trace audit . --scope app

# Full scan with live probes against a local target
trace scan ./backend --target http://localhost:8000

# Understand a finding
trace explain TR-BOLA-001

# Replay its reproduction steps
trace replay TR-BOLA-001

# After patching: restart the target, then check whether the fix worked
trace verify TR-BOLA-001 --target http://localhost:8000

# Export for GitHub code scanning
trace scan . --format sarif -o trace-results.sarif
```

!!! warning "Scope"
    Only scan systems you own or the bundled fixtures (`testbed_hardcore/`,
    `test-repository/`, `labs/`). `ScopeGuard` blocks non-local targets.

!!! note "Static-only runs"
    Without a reachable `--target`, TRACE correlates code only. Findings
    carry no runtime evidence and none can be `CONFIRMED`; "not probed" is
    not "safe".

TRACE reads source code in the languages it can analyze and skips markup,
styles, data and config files; see [What TRACE scans](ingestion.md).

## Let your agent do it

```bash
npx skills add VK-Amogh/TRACE --skill trace   # any agent harness
```

Install only the `trace` skill and ask your agent to "scan this project for
security issues": it installs and configures TRACE, runs the scan, then uses
the `trace-fix` skill to triage, fix and verify. See [Agent skills](skills.md).

## Why trust a finding

```text
Confidence = 1 − (1 − P_SecureBERT) × (1 − P_AST) × (1 − P_dynamic)
```

Triple match (~99.8%): AST dataflow finds the sink, SecureBERT flags the
pattern, and a live probe confirms exploitation. An existing guard cuts the
AST signal by 85%, suppressing false positives. After a patch,
`trace verify` replays the exploit and returns one of:

- `FIXED`: a live probe reached the target and the attack no longer works,
  and static analysis no longer flags it.
- `STILL_PRESENT`: the exploit still works.
- `INCONCLUSIVE`: the target was down or refused, or static analysis still
  flags the code. Never read this as fixed.
