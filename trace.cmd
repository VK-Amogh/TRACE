@echo off
setlocal
if exist "%~dp0.venv\Scripts\trace.exe" (
    "%~dp0.venv\Scripts\trace.exe" %*
) else (
    if not defined PYTHONPATH set "PYTHONPATH=%~dp0src"
    python -m trace_engine.cli %*
)
