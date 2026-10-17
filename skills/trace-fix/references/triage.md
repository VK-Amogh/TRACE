# TRACE report triage

TRACE gives you evidence, not verdicts. This step turns a report into a
triaged list: **ACCEPT**, **DISMISS**, or **NEED-INFO** for every finding,
each with a reason. Run it before [prioritization](prioritization.md)
and before touching code. To produce a report in the first place, use the
`trace` skill.

## 1. Get the right data

| Need | CLI | MCP |
|---|---|---|
| Machine-readable list | `trace scan . --format json -o findings.json` | `trace_findings {}` |
| Full evidence for one finding | `trace explain TR-BOLA-001` | `trace_explain {"finding_id": "TR-BOLA-001"}` |
| Human report | `trace report -f markdown` (also `html`, `json`, `sarif`) | n/a |
| Persisted store | `.trace/findings.json` (per repo; overwritten by every scan) | `trace_status {}` |

Prefer JSON or MCP over parsing the terminal table. `trace_explain` truncates
long evidence lists (`shown` / `truncated` / `total`); ask for the file if
`truncated > 0` matters. Field meanings and SARIF mapping:
[finding-schema.md](finding-schema.md).

## 2. Read the header before the findings

Check these first; they change what every finding means.

1. **Scan scope.** `full` includes `labs/`, `tests/`, `testbed*/`, `examples/`;
   `app` excludes them; `fixtures` scans only them. Findings with
   `is_fixture: true` / provenance `fixture/test` are detections in test or
   lab assets, not vulnerabilities in the product. Rescan with `--scope app`
   to separate them.
2. **Runtime status.** `ONLINE` means active probes ran. `OFFLINE` means
   static boundary correlation only. Offline findings carry no
   `runtime_evidence`, and that is "not tested", never "safe".
3. **Endpoint count.** `0` endpoints means no HTTP routes were detected
   (unsupported framework or language, routes defined only in skipped
   config files such as OpenAPI JSON/YAML, or wrong path). It does not mean
   the code is secure.
4. **Coverage table** (Markdown report). Secrets, dependency CVEs, and
   cloud/IaC config are reported as *NOT ASSESSED*. Carry that sentence into
   anything you tell the user. See [guide](guide.md).

## 3. Trust model: confidence is not severity

- **Severity** = how bad if true (CRITICAL..INFO), set by rule and context
  (for example an unauthenticated admin route is higher than an
  authenticated one).
- **Confidence** = how sure TRACE is, fused from signals
  (`1-(1-P_ast)(1-P_dyn)`, plus SecureBERT when models run):
  - `CONFIRMED`: a live probe reproduced it. Highest trust.
  - `HIGH`: strong static source-to-sink evidence, or two signals agree.
  - `MEDIUM`: single signal, exploratory. Needs a human read.
  - `POTENTIAL`: weak or mitigated signal (a sanitizer was seen).

Never rank by severity alone. A `CRITICAL / MEDIUM` finding is a
*question*; a `HIGH / CONFIRMED` finding is a *fact*. Details and edge cases:
[confidence-and-severity.md](confidence-and-severity.md).

## 4. Refute each finding before accepting it

For every finding you will act on (and every one you will dismiss), open
`source_location` and answer in order:

1. **Is the route real?** Registered and reachable, or a decorated function
   nobody mounts? (Check the router/app wiring.)
2. **Is there a guard TRACE could not see?** Global middleware, framework
   policy, decorator on a parent router, gateway, ORM default scope.
3. **Does the evidence match the code?** Read each `static_evidence` line
   against the actual lines. Does the sink really receive attacker input?
4. **What does the attack path say?** `attack_path` hops should go from a
   public entrypoint to the sink. A broken or one-hop path is weaker.
5. **Does runtime evidence agree?** For `CONFIRMED`, read the observations:
   which identity, which status code, which marker leaked.

Outcome:

| Decision | When | Required output |
|---|---|---|
| **ACCEPT** | Steps 1-3 hold and no guard exists | One-sentence invariant that is violated |
| **DISMISS** | A specific guard or non-reachability refutes it | Cite file:line of the guard; never dismiss on "looks fine" |
| **NEED-INFO** | Cannot decide statically | The exact thing to run or ask (for example start the target and rescan) |

Do not dismiss a `CONFIRMED` finding without explaining why the probe was
misleading. Probes use synthetic bearer tokens (`user-a`, `user-b`,
`admin`); an app that validates real JWTs may reject them at the auth layer,
so a *missing* confirmation is weak evidence, but a *present* one is strong.

## 5. Special cases

- `TR-CHAIN-NNN`: chained escalation. A value leaked by finding X unlocked a
  second endpoint. Treat as a pair; the fix is usually scoping both lookups.
- Same root cause across many findings (missing router-level auth, one
  unscoped repository helper): triage as one cluster.
- IDs are positional (`TR-<CAT>-NNN` derived from hypothesis order) and each
  scan overwrites the store. After code changes the same flaw can get a new
  number. Note `category` + `endpoint` + `source_location` alongside the ID.

## 6. Output shape

Return a table, then a short narrative. Do not paste raw JSON.

```
| ID | Decision | Sev/Conf | Endpoint | Why (one line, cite file:line) |
```

Then: what was **not assessed** (scope, offline probes, unsupported
categories) and what is **uncertain**. Hand the ACCEPT list to
[prioritization](prioritization.md).

Rules: never claim the code is secure because the list is short; never
re-run a scan to "make findings go away"; never edit code during triage.
