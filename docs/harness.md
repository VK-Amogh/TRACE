# Security harness skill

The agent runbook is the `trace-fix` skill (`.agents/skills/trace-fix/SKILL.md`,
installed by `trace install-skill`); the plugin bundle also carries a short
`trace-security-harness` runbook for harnesses that load plugins. The phases,
each backed by MCP tools and CLI equivalents:

1. **Ingest** — `trace_findings` / `trace findings`; pick a task via
   `trace_harness_task`.
2. **Diagnose** — `trace_explain <id>` plus `trace_attack_path`; read the
   static evidence, runtime evidence, and APM hops. Never guess the fix.
3. **Plan** — minimal invariant patch per category (BOLA: tenant-scoped
   lookup + 403; BFLA: role gate; SSRF: block internal destinations).
4. **Patch** — small, idiomatic edit; keep behavior otherwise identical.
5. **Verify** — restart the target, then `trace verify <id>` must report
   `FIXED` (a live probe reached the target and the exploit is dead).
   `STILL_PRESENT` means return to diagnosis; `INCONCLUSIVE` is never a pass.
   On failure roll back (`SafePatcher` keeps timestamped backups under
   `.trace/backups/`).

`trace-fix` goes deeper on every phase: triage, prioritization, per-language
remediation playbooks and the security guide. See [agent skills](skills.md).
