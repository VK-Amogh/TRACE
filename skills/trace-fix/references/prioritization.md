# TRACE fix prioritization

Input: the ACCEPT list from [triage](triage.md)
(if findings were not triaged, do that first). Output: a plan with tiers,
batches, owners-by-area, and exit criteria. Implementation is the job of
[playbooks](playbooks.md).

## Why not just sort by severity

CVSS, EPSS and CISA KEV rank *known CVEs in third-party software*. TRACE
finds flaws in your own routes, which have no CVE, so those feeds do not
apply. The same decision points still do, following the SSVC idea of
exploitation, exposure and impact, plus reachability. Use them:

| Decision point | TRACE signal |
|---|---|
| Exploitation evidence | `confidence` (CONFIRMED > HIGH > MEDIUM > POTENTIAL), `runtime_evidence`, chained findings |
| Exposure | Route needs no auth (`Declared auth required: False` in `static_evidence`), public prefix, reachable from the internet vs internal only |
| Impact | Category and data touched: cross-tenant read/write, admin takeover, credential storage, internal network reach |
| Reachability / leverage | `attack_path` length, choke points from the scan output, number of findings sharing one fix |

## Procedure

1. **Scope the list.** Drop `is_fixture` findings from the product plan (put
   them in a separate fixtures note). Keep only ACCEPT items.
2. **Score each finding** with the rubric in
   [priority-rubric.md](priority-rubric.md): start from the base tier
   (severity x confidence), then apply the modifiers. Show the arithmetic.
3. **Cluster by root cause.** One missing router-level auth guard, one
   unscoped repository helper, or one unvalidated URL fetcher often covers
   many findings. Use choke points (`trace_scan` returns `choke_points`; the
   CLI prints "Choke Points: fix these first") to confirm a shared node.
   A cluster takes the tier of its highest member.
4. **Order within a tier** by leverage (findings cleared per change), then
   by smallest blast radius of the change (least risk of regression).
5. **Attach exit criteria** to every batch: `trace verify <ID>` reaches
   `FIXED`, a regression test exists, and no new finding appears on rescan.
6. **State the gaps.** Say which classes were not assessed (secrets,
   dependencies, config; see [guide](guide.md)) so
   the plan is not read as a clean bill of health.

## Tiers and default time targets

| Tier | Meaning | Default target |
|---|---|---|
| P0 | Exploit reproduced or trivially reachable, high impact | Fix now; block release or merge |
| P1 | Strong evidence, high impact | Within days |
| P2 | Needs verification or lower impact | This iteration or next |
| P3 | Weak signal or low impact | Backlog, or dismiss with a recorded reason |

Time targets are defaults from common SLA practice (tightest for
internet-facing, high-impact items); replace them with the team's own policy
if one exists, and say you did.

## Plan format

Produce this and nothing longer unless asked. Template and a filled example:
[plan-template.md](plan-template.md).

```
Batch 1 (P0) - <root cause in one phrase>
  Findings: TR-BOLA-001, TR-BOLA-004, TR-CHAIN-001
  Change:   <single fix, where it goes (file or layer)>
  Verify:   trace verify <each ID> -> FIXED; test <name>
  Risk:     <what could break>
```

## Rules

- Never lower a tier because a fix is hard. Say it is hard and propose a
  mitigation (feature flag, WAF rule, disable route) as an interim step,
  labelled interim.
- Never promote on severity alone; a `MEDIUM`-confidence item gets a
  verification step before it gets a fix.
- A fix plan that touches auth, tenancy, or data models needs human review
  before merge. Say so in the plan.
- Do not commit `.trace/` output or `*.sarif` files as part of the plan.
