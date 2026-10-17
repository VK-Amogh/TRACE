# What TRACE scans

TRACE only reads files that a parser or framework adapter can turn into
routes, symbols or sinks. Everything else is skipped before it is opened, so
it costs no I/O, hashing or graph nodes.

## Analyzed languages

| Languages | Extensions |
|---|---|
| Python | `.py`, `.pyi` |
| JavaScript / TypeScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx` |
| Java / Kotlin | `.java`, `.kt`, `.kts` |
| Go, PHP, Ruby, Rust, C#, Dart | `.go`, `.php`, `.rb`, `.rs`, `.cs`, `.dart` |

## Skipped formats

Markup, styles, data/config files and similar formats yield no routes or
sinks today and are not ingested: HTML, CSS and preprocessors (`.scss`,
`.sass`, `.less`), JSON, YAML, TOML, SQL, Swift and C/C++. Images, fonts,
archives, binaries, logs and databases were never ingested.

Also pruned without descending: `.git`, `node_modules`, virtualenvs,
`dist`, `build`, `target`, `vendor`, `.next`, `.cache`, and tool caches such
as `.pytest_cache`, `.ruff_cache`, `.mypy_cache`, `.tox`, `.gradle`,
`.dart_tool`, `Pods`, `site-packages`. File-level skips include minified and
bundled assets (`*.min.js`, `*.bundle.js`, `*.chunk.js`), TypeScript
declarations (`*.d.ts`), source maps and `*.egg-info`. Files over 2 MB are
skipped.

## Customizing

- **`.traceignore`** at the repo root: one glob per line, `#` for comments.
  Applied in every scan scope.
- **`--scope app`** removes test and fixture directories from a scan;
  `--scope fixtures` scans only those. See [CLI reference](cli.md).
- **From Python**, opt formats back in:

  ```python
  from pathlib import Path
  from trace_engine.ingest.repository import RepositoryScanner

  scanner = RepositoryScanner(Path("."), languages={"python", "json", "yaml"})
  files = scanner.scan()
  print(scanner.skipped_by_language)   # Counter of known-but-skipped formats
  ```

!!! note "Config files"
    Endpoint discovery reads source code. API definitions in JSON or YAML
    (for example an OpenAPI file) are not analyzed yet; skipping them does not
    change today's findings.
