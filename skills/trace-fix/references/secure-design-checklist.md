# Secure API design checklist

Use when reviewing or writing endpoints, in addition to a TRACE scan. Each
line is a yes/no question; any "no" is a finding to triage.

## Identity and access
- [ ] Is authentication enforced by default, with public routes listed explicitly?
- [ ] Is every object lookup constrained by the caller's identity or tenant?
- [ ] Is every privileged function checked for the role on the server, for every HTTP method?
- [ ] Does the server derive identity and role from verified credentials, never from client-supplied fields or headers?
- [ ] Are tokens verified for signature, expiry, issuer, audience and algorithm?
- [ ] Are passwords hashed with argon2id/bcrypt/scrypt, with no plaintext fallback?
- [ ] Are login, password reset and token endpoints rate-limited?

## Input and output
- [ ] Are queries parameterized, with identifiers mapped through allow-lists?
- [ ] Are shell calls avoided, or run without a shell and with fixed arguments?
- [ ] Are request bodies validated against a schema that rejects unknown fields?
- [ ] Are response models explicit, so internal fields (hashes, tokens, other tenants' data) are never serialized?
- [ ] Are file paths resolved and checked against a base directory?
- [ ] Are templates fixed, with user data passed only as variables?
- [ ] Is untrusted data parsed with data-only formats (JSON), not object deserializers?

## Outbound and cross-origin
- [ ] Does any feature fetch a user-supplied URL? If so, allow-list, IP-range check, no redirects, timeouts.
- [ ] Is CORS an exact origin allow-list, with credentials only for those origins?
- [ ] Is egress from the service limited to what it needs?

## Resilience and operations
- [ ] Rate limits, pagination caps, body-size caps and timeouts on expensive routes?
- [ ] Do errors avoid stack traces, SQL text and internal paths?
- [ ] Are auth failures, permission denials and blocked outbound requests logged without secrets or tokens?
- [ ] Are secrets loaded from the environment or a secret manager, never committed?
- [ ] Is the route inventory current, with old versions and debug routes retired?
- [ ] Are dependencies and base images scanned on a schedule?

## Tests worth having
- Authorization matrix: each role x each route x each verb, expected status.
- Cross-tenant negatives for every object route.
- One malicious-input test per sink class used in the service.
- A test that fails if a new route is added without an auth decision.
