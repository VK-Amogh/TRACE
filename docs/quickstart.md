# Quick start

```bash
# Interactive wizard
trace

# Sub-second audit of the current repo
trace audit .

# Full scan with live probes against a local target
trace scan ./backend --target http://localhost:8000

# Understand a finding
trace explain TR-BOLA-001

# Replay its reproduction steps
trace replay TR-BOLA-001

# Check whether a fix worked
trace verify TR-BOLA-001

# Export for GitHub code scanning
trace scan . --format sarif -o trace-results.sarif
```

!!! warning "Scope"
    Only scan systems you own or the bundled fixtures (`testbed_hardcore/`,
    `test-repository/`, `labs/`). `ScopeGuard` blocks non-local targets.
