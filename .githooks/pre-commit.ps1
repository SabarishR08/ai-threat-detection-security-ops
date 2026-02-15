#!/bin/powershell
# Pre-commit hook - Runs before git commit to catch errors early
# Setup: Copy this to .git/hooks/pre-commit.ps1
# Or run: cp .githooks/pre-commit.ps1 .git/hooks/pre-commit

# Allow non-0 exit codes
$ErrorActionPreference = "Continue"

Write-Host "🔍 Running pre-commit checks..." -ForegroundColor Cyan

# 1. Check for uncommitted staged files
$staged = git diff --cached --name-only
if ([string]::IsNullOrWhiteSpace($staged)) {
    Write-Host "⚠ No staged files to commit" -ForegroundColor Yellow
    exit 1
}

Write-Host "Staged files:" -ForegroundColor Gray
$staged | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
Write-Host ""

# 2. Quick syntax check on Python files
Write-Host "Checking Python syntax..." -ForegroundColor Yellow
$pyFiles = $staged | Where-Object { $_ -match "\.py$" } | Where-Object { -not $_.EndsWith(".skip") }
$syntaxOk = $true

foreach ($file in $pyFiles) {
    if (Test-Path $file) {
        python -m py_compile $file 2>&1 | Out-Null
        if ($?) {
            Write-Host "  ✓ $file" -ForegroundColor Green
        } else {
            Write-Host "  ✗ $file - Syntax error!" -ForegroundColor Red
            $syntaxOk = $false
        }
    }
}

if (-not $syntaxOk) {
    Write-Host ""
    Write-Host "❌ Commit blocked: Fix syntax errors" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Pre-commit checks passed" -ForegroundColor Green
exit 0
