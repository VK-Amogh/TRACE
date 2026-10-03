@echo off
set "TRACE_DIR=%~dp0"
set "TRACE_DIR=%TRACE_DIR:~0,-1%"
echo Registering TRACE in user PATH...
powershell -NoProfile -Command "$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($currentPath -notlike '*%TRACE_DIR%*') { [Environment]::SetEnvironmentVariable('Path', $currentPath + ';%TRACE_DIR%', 'User'); Write-Host 'Successfully added %TRACE_DIR% to user PATH!' -ForegroundColor Green } else { Write-Host 'TRACE is already in user PATH.' -ForegroundColor Yellow }"
echo You can now open any terminal and type 'trace' or 'Trace' from any folder!
pause
