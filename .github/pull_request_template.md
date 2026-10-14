## Summary

<!-- What does this PR change and why? Link issues with `Fixes #123`. -->

## Changes

-
-

## Verification

<!-- Commands you ran + results. CI must be green. -->

```text
set PYTHONPATH=src
python -m pytest tests/ -q
```

- [ ] `compileall` clean
- [ ] `pytest` green (or noted failures)
- [ ] SARIF self-scan checked (if security-relevant)

## Device matrix

<!-- Mark environments you tested. CI covers ubuntu/windows/macos x py3.11-3.13. -->

- [ ] Windows
- [ ] Linux
- [ ] macOS (Intel / Apple Silicon)

## Checklist

- [ ] No secrets committed (tokens, keys, `.trace/` artifacts)
- [ ] Docs updated (`README` / `docs/` if behavior changed)
- [ ] Backwards-compatible or migration noted
