# TRACE Universal One-Line Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/VK-Amogh/TRACE/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host "   TRACE - Threat Reconnaissance & Attack-path Correlation Engine" -ForegroundColor Cyan
Write-Host "   Autonomous AI Security Verification for Coding Agents & CLI" -ForegroundColor Yellow
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host ""

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "  › Installing TRACE globally via npm..." -ForegroundColor Yellow
    npm install -g trace-sec
    Write-Host "  ✓ Installed global 'trace' and 'trace-sec' CLI." -ForegroundColor Green
} elseif (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "  › Installing TRACE via pip from GitHub..." -ForegroundColor Yellow
    pip install git+https://github.com/VK-Amogh/TRACE.git
    Write-Host "  ✓ Installed TRACE Python package." -ForegroundColor Green
} else {
    Write-Host "  [!] Neither npm nor pip was found. Please install Node.js or Python 3.10+." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  ✓ TRACE successfully installed!" -ForegroundColor Green
Write-Host "  Run 'trace' to start the interactive security audit wizard." -ForegroundColor Cyan
Write-Host "  Run 'trace --help' to view all commands." -ForegroundColor Cyan
Write-Host ""
