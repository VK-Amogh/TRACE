# TRACE finding schema and report formats

Source of truth: `src/trace_engine/findings/model.py` (`Finding`).

## Fields

| Field | Meaning | Use it to |
|---|---|---|
| `id` | `TR-<CAT>-NNN` where NNN is one counter shared across categories (a scan can yield `TR-CORS-003`, `TR-BFLA-002`, `TR-CORS-006`); unstable across scans | Reference within one scan only |
| `title` | One-line description | Summaries |
| `category` | `BOLA BFLA AUTHENTICATION SSRF INJECTION MASS_ASSIGNMENT PATH_TRAVERSAL SSTI CORS DESERIALIZATION` (chains reuse `BOLA`) | Pick the playbook |
| `severity` | `CRITICAL HIGH MEDIUM LOW INFO` | Impact if true |
| `confidence` | `CONFIRMED HIGH MEDIUM POTENTIAL` | Trust level |
| `endpoint` | `METHOD /path` as discovered | Locate the route |
| `source_location` | file, line and column range, may be null | Open the code |
| `attack_path` | Ordered hops from entrypoint to sink (APM traversal) | Find where a guard belongs |
| `static_evidence` | AST facts that raised the hypothesis | Verify against code |
| `runtime_evidence` | Probe results (empty if offline or not probed) | Judge confirmation |
| `observations` | Raw request/response records from probes | Reproduce |
| `correlation_notes` | How static and runtime evidence were combined | Explain confidence |
| `root_cause` | Tailored explanation of the flaw | Write the invariant |
| `remediation` | Concrete steps | Starting point, not the patch |
| `short_action` | One-line action | Plan table cells |
| `reproduction_steps` | Ordered HTTP steps | `trace replay <ID>` prints them |
| `provenance` / `is_fixture` | `application` or `fixture/test` | Filter test assets |

`remediation` and `root_cause` are generated from the endpoint, title and
evidence, and some are written for specific known apps. Treat them as strong
hints; confirm against the code you are actually looking at.

## Output formats

| Format | Command | Notes |
|---|---|---|
| Table | `trace scan .` | Human glance only |
| JSON | `trace scan . --format json -o f.json` or `trace report -f json` | Full `Finding.model_dump()` list |
| Markdown | `trace report -f markdown` | Adds scope block, coverage table, per-finding sections. Also written to `.trace/findings.md` on every scan |
| HTML | `trace report -f html` | Shareable |
| SARIF 2.1.0 | `trace scan . --format sarif -o trace-results.sarif` or `trace report -f sarif` | For code-scanning UIs and CI |

`trace report` reads the stored findings from the last scan; it does not
rescan. Default output path is `.trace/reports/trace_report.<ext>`.

`trace audit` / `test-all` accepts `table`, `markdown`, `json`.
Neither `scan` nor `audit` exits non-zero when findings exist, so a CI gate
must inspect the output itself (see `ci-integration.md`).

## SARIF mapping

- `ruleId` = `TRACE-<CATEGORY>`; `properties.trace_finding_id` = the TR id.
- `level`: CRITICAL/HIGH -> `error`, MEDIUM -> `warning`, LOW/INFO -> `note`.
- `properties`: `confidence`, `severity`, `endpoint`, `remediation`,
  `staticEvidence`, `runtimeEvidence`.
- Rule `precision`: `very-high` only for CONFIRMED, else `high`.
- Findings with no source file are anchored to the repo root (`.`, line 1).
  Do not interpret that as the real location; use `endpoint` instead.
- `codeFlows` reuse the finding's single location for every hop, so the hop
  names live in the message text, not in distinct source positions.
- CWE tags are attached only for these categories: BOLA (CWE-639),
  BFLA (CWE-285), AUTHENTICATION (CWE-306), SSRF (CWE-918),
  PATH_TRAVERSAL (CWE-22), CORS (CWE-942). INJECTION, SSTI,
  MASS_ASSIGNMENT and DESERIALIZATION carry **no CWE** in the SARIF; add one
  yourself when reporting (SQLi CWE-89, command CWE-78, SSTI CWE-1336,
  mass assignment CWE-915, deserialization CWE-502).

## Where output lives

```
<repo>/.trace/
  findings.json      latest scan, overwritten each run
  findings.md        Markdown rendering of the same
  graph.db           attack-path model (SQLite)
  reports/           trace report output
  config.toml        target allow-list and runtime settings
```

If `trace findings` shows nothing, `resolve_finding_store` also tries the
last-scan pointer (`.trace/last_scan_repo.txt` in the cwd) and a
`test-repository/` subfolder. Pass the repo path explicitly to avoid
reading the wrong store. `.trace/` and `*.sarif` must never be committed.
