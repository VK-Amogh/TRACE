$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path "$dir\.venv\Scripts\trace.exe") {
    & "$dir\.venv\Scripts\trace.exe" $args
} else {
    & python -m trace_engine.cli $args
}
