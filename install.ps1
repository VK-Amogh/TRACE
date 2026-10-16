# TRACE Universal One-Line Installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/VK-Amogh/TRACE/main/install.ps1 | iex

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host "   TRACE — Threat Reconnaissance & Attack-path Correlation Engine" -ForegroundColor Cyan
Write-Host "   Autonomous AI Security Verification for Coding Agents & CLI" -ForegroundColor Yellow
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host ""

function Refresh-EnvPath {
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$userPath;$machinePath"
}

# 1. Resolve or Install Node.js / npm
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "  › Node.js not detected. Installing LTS automatically via winget..." -ForegroundColor Yellow
        winget install -e --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
        Refresh-EnvPath
    }
}

# 2. Install TRACE globally
$installed = $false

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "  › Installing TRACE globally via npm (trace-sec)..." -ForegroundColor Yellow
    npm install -g trace-sec
    if ($LASTEXITCODE -eq 0) {
        $installed = $true
        # Ensure npm global prefix is in User PATH
        try {
            $npmPrefix = (npm prefix -g).Trim()
            if ($npmPrefix -and (Test-Path $npmPrefix)) {
                $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
                if ($userPath -notlike "*$npmPrefix*") {
                    [Environment]::SetEnvironmentVariable('Path', "$userPath;$npmPrefix", 'User')
                    Write-Host "  ✓ Added npm global bin ($npmPrefix) to User PATH." -ForegroundColor Green
                }
                if ($env:Path -notlike "*$npmPrefix*") {
                    $env:Path = "$npmPrefix;$env:Path"
                }
            }
        } catch {
            # non-fatal
        }
    }
}

if (-not $installed) {
    if (Get-Command pip -ErrorAction SilentlyContinue) {
        Write-Host "  › Installing TRACE Python package via pip..." -ForegroundColor Yellow
        pip install --upgrade trace-sec
        if ($LASTEXITCODE -ne 0) {
            pip install git+https://github.com/VK-Amogh/TRACE.git
        }
        $installed = $true
    } elseif (Get-Command pip3 -ErrorAction SilentlyContinue) {
        Write-Host "  › Installing TRACE Python package via pip3..." -ForegroundColor Yellow
        pip3 install --upgrade trace-sec
        if ($LASTEXITCODE -ne 0) {
            pip3 install git+https://github.com/VK-Amogh/TRACE.git
        }
        $installed = $true
    }
}

if (-not $installed) {
    Write-Host "  [!] Could not automatically complete installation." -ForegroundColor Red
    Write-Host "      Please ensure Node.js 18+ (https://nodejs.org/) or Python 3.11+ is installed." -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "  ✓ TRACE successfully installed!" -ForegroundColor Green
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host "  Type 'trace' in any terminal to launch the interactive UI." -ForegroundColor Cyan
Write-Host "  Type 'trace --help' to see all available CLI commands." -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Green
Write-Host ""
