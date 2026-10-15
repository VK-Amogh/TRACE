<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-wordmark-dark.svg">
    <img src="docs/assets/logo-wordmark.svg" alt="TRACE — Security radar for agents" width="400">
  </picture>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/trace-sec"><img src="https://img.shields.io/npm/v/trace-sec?color=black" alt="NPM"></a>
  <a href="https://github.com/auraflaa/TRACE/actions/workflows/ci.yml"><img src="https://github.com/auraflaa/TRACE/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://auraflaa.github.io/TRACE/"><img src="https://img.shields.io/badge/docs-online-black" alt="docs"></a>
  <a href="https://github.com/auraflaa/TRACE/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-black" alt="license"></a>
  <a href="https://github.com/auraflaa/TRACE/stargazers"><img src="https://img.shields.io/github/stars/auraflaa/TRACE?style=social" alt="GitHub stars"></a>
</p>

<p align="center">Full-repo audit in 0.26 s on local CPU. Zero tokens. No cloud.<br>
If it is useful to you, a ⭐ helps other people find it.</p>

**TRACE** is the radar, your coding agent is the mechanic. TRACE parses the
repository into an Attack-Path Model, correlates real vulnerabilities
(BOLA, BFLA, SSRF, injection, …), and hands structured findings to
Claude Code, Cursor, or Codex over MCP — then *proves* each fix with a live
verification oracle instead of assuming it worked.

```bash
npx trace-sec audit .
```

```bash
trace scan ./backend --target http://localhost:8000
trace explain TR-BOLA-001
trace verify TR-BOLA-001
```

```bash
claude mcp add trace -- npx -y trace-sec mcp
```

Every command on one page: **[CLI reference](https://auraflaa.github.io/TRACE/cli/)**.
AI agents start at [`AGENTS.md`](AGENTS.md) and the
[security harness skill](https://auraflaa.github.io/TRACE/harness/).

## Agent skills

Install TRACE skills into any coding agent with the
[`skills`](https://github.com/vercel-labs/skills) CLI — no npm publish needed:

```bash
npx skills add auraflaa/TRACE --list
npx skills add auraflaa/TRACE --skill trace
```

One skill, three workflows: `trace` teaches the agent to run audits,
fix findings with live verification, and connect over MCP.

## What it catches

| ID | Category | Root cause it proves |
|---|---|---|
| `TR-BOLA` | Broken Object-Level Authorization | `id` lookup without tenant scoping, shown via dual-identity differential test |
| `TR-BFLA` | Broken Function-Level Authorization | Admin endpoint reachable without role check |
| `TR-AUTH` | Missing / broken authentication | State-changing endpoint with no auth middleware |
| `TR-SSRF` | Server-Side Request Forgery | User-controlled URL dispatched without validation |
| `TR-INJ` | Injection (SQLi / command) | Unparameterized query or shell execution, triple-signal confirmed |
| `TR-MASS` | Mass assignment | Untrusted dict bound straight onto an ORM model |
| `TR-TRAV` | Path traversal | File operation on an unsanitized user path |
| `TR-SSTI` | Template injection | Unescaped user input rendered server-side |
| `TR-CORS` | CORS misconfiguration | Wildcard origin reflected with credentials |

## Benchmarks

Onecrew production repo (189 files, 39 endpoints), offline, zero tokens —
recorded in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md):

| Stage | Time |
|---|---|
| AST ingestion | 0.049 s |
| APM graph assembly | 0.071 s |
| Vulnerability analysis | 0.141 s |
| **End-to-end audit** | **0.261 s** |

Hardcore multi-service testbed (15 endpoints, 12 planted flaws):
**15.79 ms static pipeline, 100% precision / 100% recall.**
Every `trace audit` prints per-stage timings, so these numbers are
reproducible on your machine — no lab-only claims.

Covered by **124 automated tests** (`pytest tests/`).

## Lite or Full

| | **Lite** (default) | **Full** |
|---|---|---|
| Install | `pip install -e .` | `pip install -r requirements.txt` |
| Size | ~2 MB, no torch | ~1 GB (torch, transformers, onnxruntime) |
| Runs on | any CPU, 4 GB RAM | 8 GB RAM recommended |
| Detection | AST dataflow + live probes | + SecureBERT 2.0 neural scoring and Laya router |
| Choose it | contributors, CI, quick audits | maximum confidence on your own machine |

`trace doctor` reports which mode is active on your machine.

## Why trust a finding

```text
Confidence = 1 − (1 − P_SecureBERT) × (1 − P_AST) × (1 − P_dynamic)
```

- **Triple match (~99.8%)**: AST dataflow finds the sink, SecureBERT flags the
  pattern, and a live probe confirms exploitation.
- **Sanitizer attenuation**: an existing guard cuts the AST signal by 85%,
  suppressing false positives.
- **Verification oracle**: after a patch, `trace verify` replays the exploit.
  `FIXED` means the attack is actually dead — not that a linter is happy.

## Runs everywhere

| Platform | What you get |
|---|---|
| Linux x64 / Windows x64 / macOS Intel + Apple Silicon | identical CLI, CI-tested on all three |
| Python 3.11 – 3.13, Node 18 / 20 | pinned support window (`requires-python = >=3.11`) |
| CPU-only / 4 GB / offline | lite install; neural scoring degrades gracefully |
| Air-gapped | models resolve from `~/.trace/models` or repo-local `models/` |

`trace doctor` shows what is active on your machine.

## Installation

```bash
npm install -g trace-sec        # global CLI: trace, trace-sec
```

```bash
pip install -e ".[dev]"         # contributors: lite + test/lint tooling
pip install -r requirements.txt # + full AI inference (torch, ~8 GB RAM)
```

```bash
trace doctor
trace audit ./testbed_hardcore --format table
```

From a source checkout without installing, the `trace.bat` / `trace.cmd` /
`trace.ps1` launchers set `PYTHONPATH` automatically. Only test systems you own
or the bundled fixtures (`testbed_hardcore/`, `test-repository/`, `labs/`).

## Releases

TRACE ships through GitHub releases:

- Pushing a `v*` tag (or publishing a release) runs `npm-publish.yml`, which
  tests, then publishes `trace-sec` to NPM and GitHub Packages.
- Python installs track git tags directly — there is no PyPI upload yet:
  `pip install git+https://github.com/auraflaa/TRACE.git@v2.1.18`.
- The single version source is `src/trace_engine/__init__.py:__version__`
  (read dynamically by `pyproject.toml`). Bump it together with `package.json`.

## Documentation

[Installation](https://auraflaa.github.io/TRACE/installation/) ·
[Quick start](https://auraflaa.github.io/TRACE/quickstart/) ·
[CLI reference](https://auraflaa.github.io/TRACE/cli/) ·
[MCP setup](https://auraflaa.github.io/TRACE/mcp/) ·
[FAQ](https://auraflaa.github.io/TRACE/faq/) ·
[Troubleshooting](https://auraflaa.github.io/TRACE/troubleshooting/)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately per
[SECURITY.md](SECURITY.md); accessibility barriers are tracked as bugs, see
[ACCESSIBILITY.md](ACCESSIBILITY.md). Bug reports and feature requests use the
issue templates; pull requests follow the PR template checklist.

<details>
<summary>Citation</summary>

```bibtex
@software{trace_sec,
  title  = {TRACE: Threat Reconnaissance and Attack-path Correlation Engine},
  author = {{TRACE Core Team}},
  year   = {2026},
  url    = {https://github.com/auraflaa/TRACE}
}
```

See [`CITATION.cff`](CITATION.cff).

</details>

## Star history

<a href="https://star-history.com/#auraflaa/TRACE&Date">
  <img src="https://api.star-history.com/svg?repos=auraflaa/TRACE&type=Date" alt="Star history of TRACE" width="600">
</a>

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
