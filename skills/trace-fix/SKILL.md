---
name: trace-fix
description: Act on TRACE findings. Decide which are real, rank them, fix them by category and language, prove each fix, and report what was not covered. Use after a TRACE scan, when handed findings, a report or SARIF, when asked to fix TR-BOLA/BFLA/AUTH/SSRF/INJ/MASS/TRAV/SSTI/CORS/DESER issues, or for security guidance on API code.
license: Apache-2.0
compatibility: Needs TRACE findings (get them with the trace skill). Verification needs the app running locally. Patterns cover Python, Node, Java, Go and more.
metadata:
  author: TRACE Core Team
  version: "2.2.1"
---

# TRACE fix: what to do with findings

TRACE produces evidence, not verdicts. This skill turns that evidence into
safe, verified fixes and honest reporting. It assumes findings already exist;
if TRACE is not set up or no scan has run, use the
[`trace` skill](../trace/SKILL.md) first.

## The five steps

| # | Step | Do this | Detail |
|---|---|---|---|
| 1 | **Triage** | Decide ACCEPT / DISMISS / NEED-INFO for every finding, with a reason | [triage.md](references/triage.md) |
| 2 | **Prioritize** | Rank into P0-P3 and group by root cause | [prioritization.md](references/prioritization.md) |
| 3 | **Fix** | Invariant, right layer, test, minimal patch | [playbooks.md](references/playbooks.md) |
| 4 | **Verify** | Prove it with `trace verify`, in the right order | [verification-loop.md](references/verification-loop.md) |
| 5 | **Report** | Say what changed, what is proven, what was not assessed | [guide.md](references/guide.md) |

Work through one root-cause batch at a time. Do not skip triage: a finding is
a lead until the code and evidence agree.

## 1. Triage

- **Severity is impact if true; confidence is how sure TRACE is.** A
  `CRITICAL / MEDIUM` finding is a question, a `HIGH / CONFIRMED` one is a
  fact. `CONFIRMED` means a live probe reproduced it; static-only runs never
  reach it.
- Check the scan header first: scope (fixture/test findings are not product
  bugs), runtime ONLINE or OFFLINE (no runtime evidence means "not tested",
  never "safe"), and endpoint count (0 is a coverage gap, not a pass).
- Open `source_location` and try to refute each finding: is the route
  mounted, is there a guard TRACE could not see (global middleware, gateway,
  ORM scope), does the evidence match the code. Dismiss only by citing the
  guard at file:line.

## 2. Prioritize

Start from severity x confidence, then move up for: unauthenticated route,
cross-tenant or admin impact, chained escalation (`TR-CHAIN`), sensitive data,
internal-network reach; down for a verified compensating control. Tiers:
P0 fix now, P1 within days, P2 verify then schedule, P3 backlog or dismiss
with a reason. CVSS/EPSS/KEV do not apply to flaws in your own routes. One
shared fix (router-level auth, a scoped repository method) often clears many
findings: batch them. Rubric and plan template:
[priority-rubric.md](references/priority-rubric.md),
[plan-template.md](references/plan-template.md).

## 3. Fix

For each batch: state the invariant in one sentence ("a record is readable
only when it belongs to the caller's tenant"), enforce it where it covers the
most (central default-deny, then the data-access boundary, then the handler),
write one attacker test and one legitimate test, patch minimally.

| Finding | Invariant | Playbook |
|---|---|---|
| `TR-BOLA`, `TR-CHAIN` | Object access is constrained by caller identity or tenant | [authz.md](references/authz.md) |
| `TR-BFLA` | Privileged functions need the privileged role, checked server-side | [authz.md](references/authz.md) |
| `TR-AUTH` | Every non-public route authenticates; passwords use adaptive hashing | [authz.md](references/authz.md) |
| `TR-MASS` | Only allow-listed fields are bindable | [authz.md](references/authz.md) |
| `TR-INJ`, `TR-SSTI`, `TR-TRAV`, `TR-DESER` | Untrusted data never becomes code, query, template, path or object graph | [injection.md](references/injection.md) |
| `TR-SSRF`, `TR-CORS` | Outbound requests and cross-origin access go only to explicit allow-lists | [network-and-config.md](references/network-and-config.md) |

Never: hard-code the scanner's probe identities or payloads, return 200 with
an empty body to hide a leak, fix only the named route when siblings share
the flaw, rely on blocklists or hidden routes, or suppress findings to turn
the list green. Review auth, tenancy and data-model changes with a human.

## 4. Verify

Restart the target after patching, then run
`trace verify <ID> --target <local URL>` for each finding **before**
rescanning: scans overwrite the stored findings and renumber IDs. The result
is `FIXED` (a live probe reached the target and the exploit is dead),
`STILL_PRESENT` (back to step 3), or `INCONCLUSIVE` (target down or refused,
finding missing, or static analysis still flags it; never call this fixed).
Then rescan the same scope and confirm nothing new appeared.

## 5. Report

Give a short table (`ID | decision | tier | status | evidence`) and then:

- what is proven (`FIXED` with the test that guards it) and what is not;
- what TRACE does **not** assess: secrets, dependency CVEs, cloud/IaC
  configuration, business logic, resource limits. Offer the next checks from
  [coverage-gaps.md](references/coverage-gaps.md); run nothing new without
  approval.
- "No findings" always means "no findings in the checks performed".

## Start with the top risks

When there is no scan yet, or beyond what a scan reports, review in this
order (OWASP API Top 10 first, then injection):

1. Object-level authorization on every `GET/PUT/PATCH/DELETE /things/{id}` (BOLA).
2. Authentication on every non-public route; adaptive password hashing (AUTH).
3. Function-level authorization on admin and role-changing routes (BFLA).
4. Allow-listed fields on every write (mass assignment).
5. Parameterized queries, no shell, fixed templates, contained paths, no
   object deserialization of untrusted bytes.
6. Allow-listed outbound URLs (SSRF) and exact-origin CORS.
7. Secrets, dependencies and configuration: outside TRACE, so use the
   [checklist](references/secure-design-checklist.md) and
   [coverage-gaps.md](references/coverage-gaps.md).

OWASP/CWE mapping, per-pack blind spots and CI gating:
[owasp-api-top10-map.md](references/owasp-api-top10-map.md),
[ci-integration.md](references/ci-integration.md),
[finding-schema.md](references/finding-schema.md),
[confidence-and-severity.md](references/confidence-and-severity.md).

## Rules

- Only test systems the user owns or the bundled fixtures. `ScopeGuard`
  blocks non-local targets; never work around it or widen `allowed_hosts`.
- Do not commit `.trace/` output or `*.sarif`; do not echo secrets found
  during review (cite file and line, say to rotate).
- If a fix needs a migration, a new dependency or a client-visible behavior
  change, stop and put it in the plan instead of improvising.
