# FAQ

**Does TRACE send my code anywhere?**
No. Audits run on local CPU with zero tokens. Only live probes you explicitly
target receive HTTP requests.

**Why do I need the full install?**
You usually don't. Lite (`pip install -e .`) covers scanning, findings, MCP,
and verification. Full (`requirements.txt`) adds neural scoring.

**Which devices are supported?**
Windows x64, Linux x64, macOS Intel and Apple Silicon; Python 3.11–3.13;
Node 18/20 for the NPM shim. See [Installation](installation.md).

**Where do results live?**
`.trace/findings.json`, `.trace/findings.md`, `.trace/graph.db`,
`.trace/reports/`. Never commit these.
