# TRACE remediation playbooks

Input: one batch from [prioritization](prioritization.md).
Work one batch at a time. Every fix = **invariant -> enforce in the right
layer -> test -> verify**. The `trace` skill explains the verify commands;
this page explains what a correct fix looks like.

## Workflow

1. **Diagnose.** `trace explain <ID>` and read the code at `source_location`.
   Follow `attack_path` to find where the missing check belongs.
2. **State the invariant** in one sentence ("a record is only readable when
   `record.tenant_id == caller.tenant_id`"). If you cannot, you do not
   understand the finding yet.
3. **Choose the layer** (see below), patch minimally, no unrelated cleanup.
4. **Write the test first or alongside**: one test that fails before the
   fix (attacker case) and one that passes after (legitimate case).
5. **Verify** with the oracle, in the order given in
   [verification-loop.md](verification-loop.md). The order
   matters because scans renumber IDs and overwrite the store.
6. **Report** what changed, the status per ID, and what was not verified.

## Where to enforce (in order of preference)

1. **Central and default-deny**: router-level auth dependency, framework
   permission class, repository method that always takes the caller's scope.
   One fix covers every route, including future ones.
2. **At the data access boundary**: queries constrained by owner/tenant, not
   filtered after the fact.
3. **At the handler**: explicit check next to the sink. Acceptable for a
   single route; weakest for coverage.
4. **Never only at the client or only by hiding the route.** Obscurity,
   UUIDs and UI checks do not fix authorization.

## Category map

| Finding | Invariant | Playbook |
|---|---|---|
| `TR-BOLA`, `TR-CHAIN` | Object access is constrained by caller identity/tenant | [authz.md](authz.md) |
| `TR-BFLA` | Privileged functions require the privileged role, checked server-side | [authz.md](authz.md) |
| `TR-AUTH` | Every non-public route authenticates; credentials stored with adaptive hashing | [authz.md](authz.md) |
| `TR-MASS` | Only allow-listed fields are bindable, per role | [authz.md](authz.md) |
| `TR-INJ`, `TR-SSTI`, `TR-TRAV`, `TR-DESER` | Untrusted data never becomes code, query, template, path, or object graph | [injection.md](injection.md) |
| `TR-SSRF`, `TR-CORS` | Outbound requests and cross-origin access go only to explicit allow-lists | [network-and-config.md](network-and-config.md) |

## Anti-patterns that make `verify` lie or the fix worthless

- Hard-coding the scanner's probe identities or payloads (`user-a`,
  `admin`, canary markers) into an allow/deny branch.
- Returning 200 with an empty body, or swallowing the exception, so the probe
  "no longer leaks". A fix returns 403/404 for the unauthorized case.
- Fixing the single route TRACE named while sibling routes share the flaw.
- Filtering results after fetching them (`if row.owner != me: skip`) where a
  scoped query is possible.
- Blocklists for SSRF, SQLi, traversal, or file types. Use allow-lists and
  parameterization.
- Disabling the route or test as the permanent fix (fine as a labelled interim).
- Suppressing, ignoring, or editing `.trace/` findings to turn the list green.
- Auto-patching with `trace heal` and merging without reading the diff. The
  harness applies rule-guided patches transactionally and rolls back on
  failure, but a human must review auth and tenancy changes.

## Rules

- Never weaken or bypass `ScopeGuard`; verify only local/lab targets.
- Do not commit `.trace/` or `*.sarif`.
- If a fix needs a schema migration, new dependency, or behavior change for
  legitimate clients, stop and flag it in the plan instead of improvising.
