# Troubleshooting

## `ModuleNotFoundError: No module named 'trace_engine'`

The package isn't installed in the active interpreter. Either install it
(`pip install -e .`) or set `PYTHONPATH=src`. The repo launchers
(`trace.bat`, `trace.cmd`, `trace.ps1`) set the fallback automatically, and
pytest reads it from `pyproject.toml`.

## Colorama `reset_all` noise after green tests

`Exception ignored in atexit callback ... ValueError: I/O operation on closed
file` comes from colorama touching pytest's closed capture file during
interpreter shutdown. It happens *after* the pass — check `%ERRORLEVEL%`
(`cmd.exe`) or `$?` (PowerShell/bash). `0` means green.

## Model download stalls first run

`SecureBERT`/`Laya` resolve `~/.trace/models` first, then download once (~1 GB
total). On metered machines, stay on lite or pre-seed the directory. Never
commit model binaries; they travel via Git LFS.

## A scan is slow or seems to stall

- Pass `--no-models` to skip neural model provisioning.
- Add noisy directories (datasets, generated code) to `.traceignore`, or use
  `--scope app` to leave out tests and fixtures. Non-code formats and common
  cache/build directories are already skipped; see [What TRACE scans](ingestion.md).
- Without a reachable `--target` the scan is static-only and finishes fast.
  A dead target is probed once and then skipped.

## `verify` keeps saying `INCONCLUSIVE` or `STILL_PRESENT`

Restart the target after patching so it runs the new code, pass the same
`--target` you scanned, and run `verify` before rescanning (a rescan
overwrites the stored findings and can renumber IDs).

## Skills do not show up in my agent

Run `npx trace-sec install-skill --list` to see what is available, then
install: `npx skills add VK-Amogh/TRACE --skill trace` (any harness) or
`npx trace-sec install-skill`. Restart the agent session so it rescans its
skills directory. Harnesses other than Claude Code read `.agents/skills/` or
their own directory; the universal command above handles those.

## `'#' is not recognized` in cmd.exe

`#` comments are PowerShell/bash syntax. In `cmd.exe`, use `REM` lines or
plain commands without comment lines.
