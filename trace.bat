@echo off
setlocal
if exist "%~dp0.venv\Scripts\trace.exe" (
    "%~dp0.venv\Scripts\trace.exe" %*
) else (
    python -m trace_engine.cli %*
)
