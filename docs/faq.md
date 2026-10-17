# FAQ

**Does TRACE send my code anywhere?**
No. Audits run on local CPU with zero tokens. Only live probes you explicitly
target receive HTTP requests, and `ScopeGuard` refuses non-local targets.

**Why do I need the full install?**
You usually don't. Lite (`pip install -e .`) covers scanning, findings, MCP,
and verification. Full (`requirements.txt`) adds neural scoring.

**Which devices are supported?**
Windows x64, Linux x64, macOS Intel and Apple Silicon; Python 3.11–3.13;
Node 18/20 for the NPM shim. See [Installation](installation.md).

**Where do results live?**
`.trace/findings.json`, `.trace/findings.md`, `.trace/graph.db`,
`.trace/reports/`. Never commit these. Each scan overwrites the findings file.

**Which files does TRACE read?**
Source code in Python, JavaScript/TypeScript, Java/Kotlin, Go, PHP, Ruby,
Rust, C# and Dart. HTML, CSS, JSON, YAML, TOML, SQL, Swift, C/C++, assets
and build output are skipped. See [What TRACE scans](ingestion.md).

**Why did a scan find 0 endpoints?**
Either the framework is not supported yet or the path is wrong. Zero
endpoints is a coverage gap, not a clean result. Check
`trace endpoints <path>` and your `--scope`.

**Does a short findings list mean the code is secure?**
No. TRACE checks routes for ten vulnerability classes. Secrets, dependency
CVEs, cloud/IaC configuration and business logic are not assessed. The
`trace-fix` skill lists the gaps and complementary checks.

**Why is a finding `POTENTIAL` or `MEDIUM` instead of `CONFIRMED`?**
`CONFIRMED` needs a live probe to reproduce the exploit. Static-only runs
(no reachable `--target`) top out below that. See the
`trace-fix` skill for how to read confidence versus severity.

**`trace verify` says `INCONCLUSIVE`. Is the fix good?**
Unknown. The target was down or refused, the finding is no longer in the
stored scan, or static analysis still flags the code. Restart the target and
rerun `verify` before rescanning, because scans renumber finding IDs.

**How do I give my AI agent TRACE?**
Install the `trace` skill: `npx skills add VK-Amogh/TRACE --skill trace` for any
harness. The agent then installs and configures TRACE itself. See
[Agent skills](skills.md).
