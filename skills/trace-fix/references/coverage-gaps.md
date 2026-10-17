# Coverage gaps and complementary checks

TRACE reports these as NOT ASSESSED. Offer them; do not run or install
anything without the user's approval, and keep any target local.

| Gap | What to check | Commonly used tools (user's choice) |
|---|---|---|
| Hardcoded secrets | API keys, tokens, private keys in code and git history | gitleaks, trufflehog; rotate anything found, do not just delete it |
| Dependency vulnerabilities | Known CVEs in lockfiles and manifests | `pip-audit`, `npm audit`, `osv-scanner`, GitHub Dependabot |
| Container and IaC config | Dockerfile, Kubernetes, Terraform posture | trivy, checkov |
| Broader SAST | Patterns across languages beyond TRACE's rules | Semgrep, CodeQL |
| DAST / API fuzzing | Schema-driven negative testing | OWASP ZAP, Schemathesis (local targets only) |
| Resource consumption (API4) | Rate limits, pagination caps, payload size, timeouts | Review gateway and framework config; load-test locally |
| Business flows (API6) | Abuse of purchase, signup, referral, booking flows | Threat-model the flow; add per-user quotas and anti-automation |
| Inventory (API9) | Undocumented, old, or debug routes | Diff `trace endpoints` against the OpenAPI spec; retire stale versions |
| Third-party APIs (API10) | Trusting upstream responses | Validate and size-limit upstream data like user input |
| Logging and detection | Auth failures, privilege changes, SSRF blocks logged | Review logging config; alert on repeated 403/401 patterns |

## How to report gaps

Add one block to any summary:

```
Not assessed by TRACE: secrets, dependency CVEs, cloud/IaC config,
API4/API6/API9/API10, business logic. Suggested next checks: <2-3 relevant ones>.
```

If a secret is found while reading code: report file and line, state that it
must be rotated, and do not echo the value in chat, reports or commits.

TRACE can list its own registered external adapters with `trace tools`; use
that output rather than assuming which tools are installed.
