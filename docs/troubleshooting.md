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

## `'#' is not recognized` in cmd.exe

`#` comments are PowerShell/bash syntax. In `cmd.exe`, use `REM` lines or
plain commands without comment lines.
