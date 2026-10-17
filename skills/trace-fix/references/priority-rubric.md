# Priority rubric

Deterministic so two reviewers get the same answer. Show the base tier, each
modifier, and the result for every finding.

## Step 1: base tier (severity x confidence)

| Severity \ Confidence | CONFIRMED | HIGH | MEDIUM | POTENTIAL |
|---|---|---|---|---|
| CRITICAL | P0 | P0 | P1 | P2 |
| HIGH | P0 | P1 | P2 | P3 |
| MEDIUM | P1 | P2 | P2 | P3 |
| LOW | P2 | P3 | P3 | P3 |
| INFO | P3 | P3 | P3 | P3 |

`MEDIUM` and `POTENTIAL` confidence items first get a **verify step**
("read code at file:line, or rescan with `--target`"); if that raises
confidence, re-score.

## Step 2: modifiers (apply each at most once; floor P0, ceiling P3)

Move **up one tier** when any of these hold:

| Modifier | Test |
|---|---|
| Unauthenticated | `static_evidence` shows `Declared auth required: False` or the route has no guard |
| Cross-tenant or admin impact | Category BOLA/BFLA touching another user's or tenant's data, or role escalation |
| Chained | Finding is, or feeds, a `TR-CHAIN-*` escalation |
| Sensitive data | Evidence or route concerns credentials, payment, PII, health, secrets, tokens |
| Internal reach | SSRF with no allow-list and an internal or metadata-reachable network |

Move **down one tier** when any of these hold:

| Modifier | Test |
|---|---|
| Existing mitigation | A sanitizer or validator is in the path but incomplete (confidence likely already reflects it); a compensating control is verified, not assumed |
| Internal-only | Route is only reachable from a trusted network and that is enforced |
| No sensitive data | Compute-only or public data (for example an unauthenticated stateless inference endpoint) |

Never move a CONFIRMED finding below P1 without written justification.

## Step 3: cluster and order

1. Group findings that one change resolves (same missing guard, same helper,
   same sink wrapper). The group inherits the highest tier of its members.
2. Within a tier, order by:
   1. findings cleared by the change (more first),
   2. choke-point betweenness of the node being fixed (higher first),
   3. smaller change surface (fewer files, no schema migration).

## Worked example

| ID | Sev/Conf | Base | Modifiers | Final |
|---|---|---|---|---|
| TR-BOLA-001 `GET /api/records/{id}` | HIGH / CONFIRMED | P0 | cross-tenant (cap P0) | P0 |
| TR-BOLA-004 `PUT /api/records/{id}` | HIGH / HIGH | P1 | cross-tenant (+1) | P0 |
| TR-CHAIN-001 | HIGH / HIGH | P1 | chained (+1) | P0 |
| TR-SSRF-002 `POST /api/preview` | HIGH / MEDIUM | P2 | internal reach (+1) | P1, verify first |
| TR-AUTH-006 stateless inference route | LOW / MEDIUM | P3 | no sensitive data (floor P3) | P3 |

Root-cause clusters: 001 + 004 + CHAIN-001 are one batch (scope the record
lookup to the caller's tenant in the repository layer). SSRF-002 is a
separate batch.

## Suggested time targets

| Tier | Target | Notes |
|---|---|---|
| P0 | Same day to 2 days | Mitigate first (disable route, tighten gateway) if the fix is not ready |
| P1 | About 1 week | |
| P2 | About 30 days | Includes the verify step |
| P3 | Quarterly review | Close with a written reason or keep in backlog |

These mirror common tiered-SLA practice; they are defaults, not policy.
