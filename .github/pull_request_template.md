## Summary

<!-- Brief 1-2 sentence description of what this PR does and why. -->
<!-- Link related issues with `Fixes #123` or `Closes #123`. -->

### Type of Change

<!-- Check all applicable with [x] -->
- [ ] **Bug fix** (non-breaking change which fixes an issue)
- [ ] **New feature** (non-breaking change which adds functionality)
- [ ] **Performance improvement** (speedup, lower memory/CPU footprint)
- [ ] **Refactoring** (code structure improvement, no behavioral change)
- [ ] **Documentation** (updates to README, docs/, comments)
- [ ] **Test suite** (new tests, fixture updates, test hardening)
- [ ] **CI / Tooling** (GitHub Actions, build scripts, linters)

---

## Detailed Description & Context

<!-- Explain the problem being addressed, the root cause, and the solution applied. -->

### Key Changes
- 
- 

---

## Verification & Test Evidence

<!-- Commands you ran + local execution results. CI must be green. -->

### Test Commands Executed
```bash
python -m pytest tests/ -v
ruff check src tests --select E9,F63,F7,F82
python -m compileall -q src tests
```

### Local Test Results
- [ ] Unit tests pass (`pytest`)
- [ ] Linter clean (`ruff check src tests`)
- [ ] Syntax check clean (`python -m compileall -q src tests`)
- [ ] Manual CLI verification performed (if CLI-facing)

### Environments Tested
- [ ] Windows
- [ ] Linux / WSL
- [ ] macOS (Intel / Apple Silicon)

---

## Security & Repository Guidelines Checklist

<!-- All items below MUST be confirmed before merging. -->
- [ ] **No secrets**: No API keys, credentials, or private tokens committed.
- [ ] **No transient artifacts**: No `.trace/`, `*.sarif`, or model weight files committed.
- [ ] **ScopeGuard compliance**: No bypasses of local-only scope policies.
- [ ] **Version synchronization**: `src/trace_engine/__init__.py:__version__` and `package.json` bumped together if version changed.
- [ ] **Clean commit titles**: Conventional commit prefix used (`fix:`, `feat:`, `docs:`, `test:`, `refactor:`, `ci:`).
