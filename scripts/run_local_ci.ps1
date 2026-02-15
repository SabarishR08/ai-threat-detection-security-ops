# Local CI Test Runner
# Run this before pushing to GitHub to catch errors early
# Usage: .\scripts\run_local_ci.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Running Local CI Pipeline Tests" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Change to project root
Set-Location $PSScriptRoot\..

$failed = @()
$passed = @()

# 1. Check Python version
Write-Host "[1/5] Checking Python version..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($pythonVersion -match "3\.(11|12)") {
    Write-Host "✓ Python version OK: $pythonVersion" -ForegroundColor Green
    $passed += "Python version"
} else {
    Write-Host "✗ Python version mismatch: $pythonVersion (need 3.11 or 3.12)" -ForegroundColor Red
    $failed += "Python version"
}
Write-Host ""

# 2. Check dependencies
Write-Host "[2/5] Checking dependencies..." -ForegroundColor Yellow
$depsOk = $true
@("flask", "pytest", "sqlalchemy", "nest_asyncio") | ForEach-Object {
    $dep = $_
    python -c "import $dep" 2>&1 | Out-Null
    if ($?) {
        Write-Host "  ✓ $dep" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $dep - MISSING! Run: pip install -r backend/requirements.txt" -ForegroundColor Red
        $depsOk = $false
    }
}
if ($depsOk) { $passed += "Dependencies" } else { $failed += "Dependencies" }
Write-Host ""

# 3. Run unit tests
Write-Host "[3/5] Running unit tests..." -ForegroundColor Yellow
python -m pytest -c backend/pytest.ini backend/tests/unit/test_threat_services.py -v --tb=short 2>&1 | Select-Object -Last 3
$unitStatus = $LASTEXITCODE
if ($unitStatus -eq 0) {
    Write-Host "✓ Unit tests passed" -ForegroundColor Green
    $passed += "Unit tests"
} else {
    Write-Host "✗ Unit tests failed (exit code: $unitStatus)" -ForegroundColor Red
    $failed += "Unit tests"
}
Write-Host ""

# 4. Run integration tests
Write-Host "[4/5] Running integration tests..." -ForegroundColor Yellow
python -m pytest -c backend/pytest.ini backend/tests/integration/test_routes.py -v --tb=short 2>&1 | Select-Object -Last 3
$intStatus = $LASTEXITCODE
if ($intStatus -eq 0) {
    Write-Host "✓ Integration tests passed" -ForegroundColor Green
    $passed += "Integration tests"
} else {
    Write-Host "✗ Integration tests failed (exit code: $intStatus)" -ForegroundColor Red
    $failed += "Integration tests"
}
Write-Host ""

# 5. Validate git state
Write-Host "[5/5] Validating git state..." -ForegroundColor Yellow
$status = git status --short
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host "✓ Working tree clean" -ForegroundColor Green
    $passed += "Git state"
} else {
    Write-Host "⚠ Uncommitted changes detected:" -ForegroundColor Yellow
    Write-Host $status
    Write-Host ""
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✓ Passed: $($passed.Count)" -ForegroundColor Green
Write-Host "✗ Failed: $($failed.Count)" -ForegroundColor $(if ($failed.Count -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($failed.Count -gt 0) {
    Write-Host "Failed checks:" -ForegroundColor Red
    $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "⚠ DO NOT PUSH - Fix the above issues first" -ForegroundColor Red
    exit 1
} else {
    Write-Host "✓ All checks passed!" -ForegroundColor Green
    Write-Host "✓ Ready to push" -ForegroundColor Green
    exit 0
}
