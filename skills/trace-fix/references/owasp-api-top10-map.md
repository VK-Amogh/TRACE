# OWASP API Security Top 10 (2023) vs TRACE

Reference: <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>.

| # | Risk | TRACE coverage |
|---|---|---|
| API1 | Broken Object Level Authorization | **Covered**: `bola` pack (dual-identity differential, canary markers) plus `TR-CHAIN` escalation |
| API2 | Broken Authentication | **Partial**: `authentication` pack and AST rules (unauthenticated routes, weak password hashing, session handling). No MFA, lockout, or token-lifecycle analysis |
| API3 | Broken Object Property Level Authorization | **Partial**: `mass_assignment` pack. Excessive data exposure (over-returning fields) is not tested |
| API4 | Unrestricted Resource Consumption | **Not covered** (only flags unauthenticated compute endpoints as LOW) |
| API5 | Broken Function Level Authorization | **Covered**: `bfla` pack; role-assignment and admin-evidence rules |
| API6 | Unrestricted Access to Sensitive Business Flows | **Not covered** |
| API7 | Server Side Request Forgery | **Covered**: `ssrf` pack |
| API8 | Security Misconfiguration | **Partial**: `cors` only. Headers, TLS, verbose errors, debug mode not assessed |
| API9 | Improper Inventory Management | **Not covered** as a risk, though endpoint discovery lists routes. Compare it with the API spec yourself |
| API10 | Unsafe Consumption of APIs | **Not covered** |

Non-API-Top-10 classes TRACE also tests: `injection`, `path_traversal`,
`ssti`, `deserialization`.

## Per-pack intent and likely blind spots

Blind spots are typical limits of this style of check, not an exhaustive
or tested list; confirm against the pack source in `src/trace_engine/testpacks/`.

| Pack | Detects | Likely blind spots |
|---|---|---|
| bola | Cross-identity object reads/writes | Needs a live target and two tokens the app honors; object ids it cannot guess; multi-step ownership |
| bfla | Privileged function reachable with a lesser token | Roles beyond admin/user; method-specific guards |
| authentication | Missing or weak authn on routes | Business-specific session rules |
| ssrf | URL parameters fetched server-side | Blind SSRF with no response signal; non-URL parameters (file import, webhooks configured out of band) |
| mass_assignment | Privileged properties accepted on write | Nested objects, per-role property rules |
| injection | Interpolated SQL on search/filter/query routes; error/timing signals | Injection on other routes, NoSQL, second-order, command injection beyond the rule |
| path_traversal | File parameters escaping a base dir | Archive extraction (zip-slip), indirect file reads |
| ssti | Template evaluation of input | Engines without simple arithmetic signals |
| cors | Reflected origins and wildcard with credentials | Per-route CORS differences behind proxies |
| deserialization | Unsafe object deserialization sinks | Gadget-chain exploitability |

Runtime packs use synthetic identities (`user-a`, `user-b`, `admin`) against
a local target. Apps that validate real tokens may need a test-mode identity
provider before runtime confirmation is meaningful.

## CWE quick map

| Topic | CWE |
|---|---|
| IDOR / BOLA | CWE-639 (also CWE-284, CWE-285) |
| Missing authentication | CWE-306 |
| Improper authorization | CWE-285, CWE-862, CWE-863 |
| Mass assignment | CWE-915 |
| SSRF | CWE-918 |
| SQL injection | CWE-89 |
| OS command injection | CWE-78 |
| Path traversal | CWE-22 |
| Template injection | CWE-1336 |
| Deserialization | CWE-502 |
| Permissive CORS | CWE-942 |
| Weak password hashing / storage | CWE-916, CWE-759, CWE-256 |

TRACE's SARIF attaches CWE tags only for BOLA, BFLA, AUTHENTICATION, SSRF,
PATH_TRAVERSAL and CORS. Add the others yourself when exporting.
