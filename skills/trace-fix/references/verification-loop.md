# Verification loop

Source: `src/trace_engine/verify.py`, `mcp/server.py`, `harness/`.

## Order of operations (do not reorder)

1. **Patch** the code.
2. **Run the project's own tests**, including the new regression test.
3. **Restart the target** unless it hot-reloads. The oracle replays probes
   against the *running* server; a stale process returns `STILL_PRESENT`
   for a correct fix.
4. **Verify each finding by its current ID**, before any new scan:
   `trace verify TR-BOLA-001 . --target http://127.0.0.1:18080`
   or `trace_verify {"finding_id": "...", "repository": ".", "target": "..."}`.
   Verify reads the finding from `.trace/findings.json`.
5. **Only then rescan.** Every scan overwrites the store and IDs are
   positional, so after a fix `TR-BOLA-002` may become `TR-BOLA-001`.
   Record `category + endpoint + source_location` next to each ID before
   rescanning.
6. **Rescan the same scope** and confirm the finding is gone and no new one
   appeared (`trace scan . --scope app --target ...`).

Default target is `http://127.0.0.1:18080` (env `TRACE_TARGET_URL`);
`trace heal` defaults to `http://127.0.0.1:18082`. Pass `--target`
explicitly so you are never verifying a different server than you patched.

## What each status means

The oracle returns exactly `FIXED`, `STILL_PRESENT` or `INCONCLUSIVE`.
`remediation_verified` is true only for `FIXED`.

| Status | Condition in code | Action |
|---|---|---|
| `STILL_PRESENT` | The test pack still confirms the exploit at runtime | Back to diagnosis. Check: server restarted? other route/method? fix in the right layer? |
| `FIXED` | A live probe reached the target, exploit no longer reproduces, and the static re-index no longer flags the hypothesis | Done for this finding. Keep the regression test |
| `INCONCLUSIVE` | See below | Never report as fixed |

`INCONCLUSIVE` causes, from `differential_analysis`:

- Finding ID not in the store (renumbered, or scan was in another directory).
- Target refused by scope policy (non-local host). No request was sent.
  Fix the target; do not weaken the guard.
- No probe reached the target (server down, wrong port, connection error).
  Start it and rerun. A dead target can never read as `FIXED`.
- Runtime no longer reproduces but static re-index **still flags** the
  hypothesis. The fix may be correct but not recognizable (for example, the
  guard lives in a helper the analyzer does not follow). Read
  `static_signals_after`; make the guard explicit at the route or document
  the residual with evidence, but do not claim `FIXED`.

## Patch scoring and automation

- `trace_eval_patch {finding_id, target_file, patch_content, rollback_after}`
  applies a candidate patch through `SafePatcher` (transactional, rolls back,
  rejects absolute, UNC and symlink-escaping paths) and reports the verify
  result. Use `rollback_after: true` to try a patch without keeping it.
- `trace_harness_task {finding_id}` returns a benchmark-style task bundle
  for a finding.
- `trace heal <repo>` runs the self-healing loop (rule-guided patches, then
  verify). Treat its diff as a proposal; review it like any other change.
  Built-in remediators cover specific known patterns, so many findings will
  need a hand-written fix.

## Evidence to include in the final report

```
TR-BOLA-001  FIXED          verify: runtime 404 for foreign tenant; test: tests/test_records_authz.py
TR-SSRF-002  INCONCLUSIVE   runtime clean, static still flags services/preview.py:41 (guard in helper)
Not verified: <anything you could not run, with the reason>
```
