# Changelog

The full changelog lives in [`CHANGELOG.md`](https://github.com/VK-Amogh/TRACE/blob/main/CHANGELOG.md)
(Keep a Changelog + Semantic Versioning).

## Unreleased highlights

- Two harness-agnostic agent skills: `trace` (the agent installs, configures
  and runs TRACE) and `trace-fix` (triage, prioritize, fix, verify, report),
  shipped in the npm package and the wheel, with a refreshed `install-skill`.
- Scans skip file formats TRACE cannot analyze (HTML, CSS, JSON, YAML,
  TOML, SQL, ...) before opening them.

- OSS contributor kit (contributing, conduct, security, accessibility,
  templates, license, changelog, citation, agent guide).
- Cross-OS CI matrix, SARIF self-audit gate, packaging build check, docs site.
- Source launchers work without install via `PYTHONPATH` fallback.
- Crash fixes: interactive doctor call, MCP handoff import, BOLA offline
  confidence, hardcoded model paths, forced terminal styling.
