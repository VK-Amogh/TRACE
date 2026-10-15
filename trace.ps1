$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path "$dir\.venv\Scripts\trace.exe") {
    & "$dir\.venv\Scripts\trace.exe" $args
} else {
    if (-not $env:PYTHONPATH) { $env:PYTHONPATH = Join-Path $dir 'src' }
    & python -m trace_engine.cli $args
}
