# CI integration

## Facts that shape the pipeline

- `trace scan` and `trace audit` return exit code 0 even when findings
  exist. A step that only runs the command never fails the build.
- The repo's `trace-gate.yml` uploads SARIF to GitHub code scanning; any
  blocking comes from branch protection on code-scanning results, not from
  the TRACE step.
- Probes only run against a reachable local/lab target. In CI the usual
  setup is static-only (offline) unless the job starts the app first, so
  expect HIGH confidence at best, not CONFIRMED.
- Models are optional. Use `--no-models` in CI for speed and determinism.
- Never commit `.trace/` or `*.sarif`; upload them as artifacts.

## Blocking gate recipe

```bash
trace scan . --scope app --no-models --format json -o trace-findings.json

# Block on CRITICAL/HIGH findings in application code with HIGH or CONFIRMED confidence
count=$(jq '[.[] | select((.severity=="CRITICAL" or .severity=="HIGH")
           and (.confidence=="CONFIRMED" or .confidence=="HIGH")
           and (.is_fixture|not))] | length' trace-findings.json)
echo "blocking findings: $count"
[ "$count" -eq 0 ] || exit 1
```

Choose thresholds from the tiers in `prioritization.md`: block on
P0/P1-equivalents, report P2 as warnings, track P3.

## SARIF to code scanning

```bash
trace scan . --scope app --no-models --format sarif -o trace-results.sarif
```

Upload with `github/codeql-action/upload-sarif` and
`permissions: security-events: write`. Notes:

- Results without a source file anchor to the repo root; use the `endpoint`
  property to find the route.
- `level`: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW/INFO -> note.
- Add `if: always()` to the upload so results appear even if the gate fails.

## With a live target in CI

Start the app on `127.0.0.1` in the job, wait for health, then pass
`--target http://127.0.0.1:<port>`. `ScopeGuard` rejects anything that is not
local or private, so do not point CI at staging or production.

## Pre-merge verification of fixes

For PRs that claim to fix a finding: run the app from the PR branch, then
`trace verify <ID> --target <local URL>`. Require `FIXED`, not
`INCONCLUSIVE`. Remember IDs come from the stored scan; run `verify` before
rescanning.

## Common mistakes

- Treating a green TRACE step as "secure". It means "no crash".
- Scanning with `--scope full` so fixture findings fail the build.
- Comparing finding IDs between runs; compare `category + endpoint + file`.
- Uploading SARIF from a fork PR (token lacks `security-events`); use
  `pull_request` from the same repo or skip upload.
