# Confidence and severity in TRACE

Source: `src/trace_engine/security/fusion.py` and `findings/correlate.py`.

## How confidence is computed

```
posterior = 1 - (1 - P_neural) * (1 - P_ast) * (1 - P_dynamic)
```

- `P_neural`: SecureBERT score, only when models are enabled and wired
  (currently not passed into correlation, so treat it as absent).
- `P_ast`: the hypothesis' static prior (0.55-0.90 depending on the rule).
  A detected sanitizer multiplies it by 0.15.
- `P_dynamic`: 0.99 when a probe confirmed the exploit, else the probe's own
  score, else 0.

Levels:

| Confidence | Rule | What it means for you |
|---|---|---|
| CONFIRMED | A live probe confirmed it (or three strong signals) | Exploit reproduced. Fix and verify |
| HIGH | Posterior >= 0.80, or two signals >= 0.4 with posterior >= 0.75 | Strong static evidence. Read the code, then act |
| MEDIUM | Posterior 0.50-0.80 | Hypothesis. Needs reading or a live run |
| POTENTIAL | Posterior < 0.50 | Mostly mitigated or weak |

A finding that is not live-confirmed and has posterior < 0.40 is **dropped**,
not reported. So an empty list can hide weak signals; it never proves safety.

## What the static prior implies

Static-only findings can reach HIGH when the rule is strong (for example an
unauthenticated admin route, or an unsafe SQL sink with evidence). They can
never reach CONFIRMED without a probe. If you can run the app locally, a scan
with `--target` is the cheapest way to turn MEDIUM/HIGH into CONFIRMED or to
learn that runtime blocks the exploit.

## Severity is contextual

The same category produces different severities. Examples from the rules:

- BFLA on an admin-evidence route: CRITICAL; on a general privileged route: HIGH.
- Client-assigned `role` on a create/register route: CRITICAL if the route
  needs no auth, HIGH if it does.
- Broken password hashing: CRITICAL with a plaintext-comparison fallback,
  else HIGH. Its `endpoint` reads "Authentication Module (...)", which is a
  code module, not an HTTP route.
- An unauthenticated stateless inference endpoint with no stored data: LOW
  (compute exhaustion only).
- An endpoint with `auth_required` true scores lower than the same route
  without it.

Severity is not CVSS. TRACE does not compute a CVSS vector, and app-logic
flaws have no CVE, so EPSS and CISA KEV do not apply to them. Use the
rubric in `prioritization.md` instead.

## Reading the two together

| Sev \ Conf | CONFIRMED | HIGH | MEDIUM | POTENTIAL |
|---|---|---|---|---|
| CRITICAL | Emergency | Fix first, read code to confirm | Verify before committing time | Check for a missed guard |
| HIGH | Fix now | Fix next | Verify first | Backlog or dismiss with reason |
| MEDIUM | Fix soon | Fix soon | Verify, then schedule | Backlog |
| LOW/INFO | Batch with related work | Batch | Batch or dismiss | Dismiss with reason |

## False-positive patterns to look for

- Decorated or defined function that is never mounted (the adapters mark
  these `registered=False` / low confidence).
- Auth enforced in a global middleware, gateway, or a parent router the
  adapter did not trace.
- Query already scoped by an ORM default manager or row-level security.
- Sink fed by a constant or a validated enum, not request data.
- Fixture or lab code (check `provenance`).

## False-negative reminders

- Unsupported framework or language: endpoint count will be low or zero.
- Offline run: no runtime proof, and dynamic-only flaws are invisible.
- The SQL-injection hypothesis only fires on routes whose path contains
  `search`, `filter`, or `query` and whose handler builds SQL by
  interpolation or concatenation. Injection in other routes is not flagged
  by that rule, so read data-access code by hand.
- Business-logic flaws (workflow abuse, race conditions, pricing) are outside
  the packs. Absence of findings says nothing about them.
- Large files are skipped by the MCP scan (`files_skipped_large`).
