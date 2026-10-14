# Security harness skill

The agent runbook lives at `.agents/skills/trace-security-harness/SKILL.md`.
Five phases, each backed by MCP tools and CLI equivalents:

1. **Ingest** — `trace_findings` / `trace findings`; pick a task via
   `trace_harness_task`.
2. **Diagnose** — `trace_explain <id>` plus `trace_attack_path`; read the
   static evidence, runtime evidence, and APM hops. Never guess the fix.
3. **Plan** — minimal invariant patch per category (BOLA: tenant-scoped
   lookup + 403; BFLA: role gate; SSRF: block internal destinations).
4. **Patch** — small, idiomatic edit; keep behavior otherwise identical.
5. **Verify** — `trace verify <id>` must report `FIXED` with the runtime
   check passing; otherwise roll back (`SafePatcher` keeps timestamped
   backups under `.trace/backups/`).
