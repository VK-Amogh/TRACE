# Remediation plan template

Copy, fill, keep under one page for up to ten findings.

```markdown
# Remediation plan: <repo or service>

Scan: <date>, scope=<full|app|fixtures>, target=<URL or offline>
Not assessed: secrets, dependency CVEs, cloud/IaC config (TRACE does not cover these)
Triage: <N> accepted, <N> dismissed (with reasons), <N> need info

## Summary table
| Batch | Tier | Findings | Root cause | Fix location |
|---|---|---|---|---|

## Batch 1 (P0): <root cause>
- Findings: TR-...
- Invariant: <one sentence, for example "every record lookup is constrained by the caller's tenant">
- Change: <what and where>
- Interim mitigation (if fix is not ready): <route disabled / gateway rule>
- Tests: <regression test names, negative case included>
- Verify: `trace verify TR-... --target <URL>` returns FIXED for each
- Risk and reviewer: <regression surface; who must review (auth/tenancy changes need a human)>

## Batch 2 (P1): ...

## Deferred (P3) and dismissed
| ID | Decision | Reason (file:line of guard, or why low value) |
```

## Filled example (abridged)

```markdown
# Remediation plan: records-api

Scan: 2026-10-17, scope=app, target=http://127.0.0.1:18080 (online)
Not assessed: secrets, dependency CVEs, cloud/IaC config

| Batch | Tier | Findings | Root cause | Fix location |
|---|---|---|---|---|
| 1 | P0 | TR-BOLA-001, TR-BOLA-004, TR-CHAIN-001 | Record lookups not scoped to tenant | repositories/records.py |
| 2 | P1 | TR-SSRF-002 | Webhook preview fetches arbitrary URLs | services/preview.py |

## Batch 1 (P0): unscoped record lookup
- Invariant: a record is only returned or mutated when it belongs to the caller's tenant.
- Change: replace `get(id)` with `get_for_tenant(id, tenant_id)` in the repository; callers pass `current_user.tenant_id`; unknown or foreign id returns 404.
- Interim: none needed (fix is one function).
- Tests: foreign-tenant GET/PUT/DELETE return 404; own-tenant still 200.
- Verify: trace verify for the three IDs -> FIXED on a restarted server.
- Risk: any internal caller that relied on global lookup; grep call sites. Reviewer: owner of tenancy model.
```
