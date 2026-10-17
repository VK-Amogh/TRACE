# TRACE security guide

The conceptual layer under the `trace-fix` workflow: what each finding
class is, what the tool can and cannot see, and how to wire results into
delivery.

Related: [triage](triage.md) (read it), [prioritization](prioritization.md)
(order it), [playbooks](playbooks.md) (fix it). Setup and running TRACE live
in the [`trace` skill](../../trace/SKILL.md).

## 1. What TRACE covers

Ten hypothesis classes on discovered HTTP routes, each backed by a test pack
for live confirmation:

| TRACE category | Finding ID | OWASP API 2023 | Typical CWE |
|---|---|---|---|
| BOLA | `TR-BOLA` | API1 Broken Object Level Authorization | 639 |
| AUTHENTICATION | `TR-AUTH` | API2 Broken Authentication | 306, 256/759/916 for password storage |
| MASS_ASSIGNMENT | `TR-MASS` | API3 Broken Object Property Level Authorization | 915 |
| BFLA | `TR-BFLA` | API5 Broken Function Level Authorization | 285 |
| SSRF | `TR-SSRF` | API7 Server Side Request Forgery | 918 |
| CORS | `TR-CORS` | API8 Security Misconfiguration (part) | 942 |
| INJECTION | `TR-INJ` | outside the API Top 10; OWASP Top 10 A03 | 89, 78 |
| PATH_TRAVERSAL | `TR-TRAV` | outside the API Top 10; OWASP Top 10 A01 | 22 |
| SSTI | `TR-SSTI` | outside the API Top 10; OWASP Top 10 A03 | 1336 |
| DESERIALIZATION | `TR-DESER` | outside the API Top 10; OWASP Top 10 A08 | 502 |

Full mapping, test intent per pack, and what each pack cannot see:
[owasp-api-top10-map.md](owasp-api-top10-map.md).

## 2. What TRACE does not cover (say it out loud)

Not assessed, and printed as *NOT ASSESSED* in the Markdown report:
hardcoded secrets, vulnerable dependencies (SCA), cloud/container/IaC
configuration. Also not covered by any pack: unrestricted resource
consumption (API4), sensitive business-flow abuse (API6), improper inventory
management (API9), unsafe consumption of third-party APIs (API10), race
conditions, pricing/workflow logic, and client-side issues.

Rules when reporting:
- "No findings" always reads "no findings in the checks performed".
- Zero detected endpoints is a coverage failure to investigate, not a pass.
- If the user asks for a "security review", list the uncovered areas and
  offer the complementary checks in
  [coverage-gaps.md](coverage-gaps.md). Install or run nothing
  without approval.

## 3. Secure-design baseline

Short checklist to apply when reviewing or writing API code beyond what a
scan reports: [secure-design-checklist.md](secure-design-checklist.md).
Core principles:

1. **Default deny.** Authentication and authorization are on unless a route
   is deliberately public.
2. **Authorize every object and every function** on the server, using
   identity from verified credentials.
3. **Treat all input as data.** Parameterize, encode, validate by allow-list.
4. **Least privilege** for DB accounts, tokens, service identities, and
   outbound network access.
5. **Fail closed and quietly.** Errors reveal no internals; denials are logged.
6. **Defense in depth.** Rate limits, egress controls, and monitoring cover
   the bug you have not found yet.

## 4. CI and delivery

TRACE's `scan`/`audit` never exit non-zero because findings exist, so a
pipeline must gate on the output. Recipe, SARIF upload, local-only target
rules and common mistakes: [ci-integration.md](ci-integration.md).

## 5. Safety and scope

- Test only systems the user owns, or the bundled fixtures (`testbed_hardcore/`,
  `test-repository/`, `labs/`). `ScopeGuard` refuses non-local targets;
  never work around it, and never widen `allowed_hosts` to reach a remote
  system.
- Never run exploit payloads against third-party or production systems.
- Do not paste secrets found during review into reports or commits;
  reference file and line only.
- Do not commit `.trace/` output, `*.sarif`, or model binaries.
