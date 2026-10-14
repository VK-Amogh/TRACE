# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | Yes |
| Tagged releases `v*` | Best-effort for 90 days |
| Forks / old commits | No — please rebase on `main` |

## Reporting a vulnerability

**Do not open a public GitHub issue for security bugs.**

1. Email the maintainers (see GitHub profile / Discussions for contact)
   with: affected commit, repro against `testbed_hardcore/` or `labs/`,
   impact, and suggested fix if any.
2. Allow up to 7 days for triage confirmation.
3. Allow up to 90 days for a fix + coordinated disclosure.

We will credit reporters on request.

## Testing rules

- Only test systems you own or the bundled fixtures
  (`testbed_hardcore/`, `test-repository/`, `labs/`).
- `ScopeGuard` (`src/trace_engine/policy/scope.py`) blocks non-local
  targets by default — do not bypass it to hit public hosts.
- Never submit live credentials, tokens, or customer data in issues, PRs,
  SARIF artifacts, or `.trace/` output.

## Scope

In scope: `src/trace_engine/`, `bin/`, install scripts, workflows,
packaging. Out of scope: third-party models, social engineering,
physical attacks.
