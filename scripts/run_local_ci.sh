#!/bin/bash
# Local CI Test Runner (for Linux/macOS)
# Run this before pushing to GitHub to catch errors early
# Usage: ./scripts/run_local_ci.sh

set -e

echo "========================================"
echo "Running Local CI Pipeline Tests"
echo "========================================"
echo ""

cd "$(dirname "$0")/.."

passed=0
failed=0

# 1. Check Python version
echo "[1/5] Checking Python version..."
python_version=$(python --version 2>&1 | grep -oP '\d+\.\d+')
if [[ $python_version =~ ^3\.(11|12)$ ]]; then
    echo "✓ Python version OK: $python_version"
    ((passed++))
else
    echo "✗ Python version mismatch: $python_version (need 3.11 or 3.12)"
    ((failed++))
fi
echo ""

# 2. Check dependencies
echo "[2/5] Checking dependencies..."
deps_ok=0
for dep in flask pytest sqlalchemy nest_asyncio; do
    if python -c "import $dep" 2>/dev/null; then
        echo "  ✓ $dep"
    else
        echo "  ✗ $dep - MISSING! Run: pip install -r backend/requirements.txt"
        deps_ok=1
    fi
done
if [ $deps_ok -eq 0 ]; then
    ((passed++))
else
    ((failed++))
fi
echo ""

# 3. Run unit tests
echo "[3/5] Running unit tests..."
if python -m pytest -c backend/pytest.ini backend/tests/unit/test_threat_services.py -v --tb=short 2>&1 | tail -3; then
    echo "✓ Unit tests passed"
    ((passed++))
else
    echo "✗ Unit tests failed"
    ((failed++))
fi
echo ""

# 4. Run integration tests
echo "[4/5] Running integration tests..."
if python -m pytest -c backend/pytest.ini backend/tests/integration/test_routes.py -v --tb=short 2>&1 | tail -3; then
    echo "✓ Integration tests passed"
    ((passed++))
else
    echo "✗ Integration tests failed"
    ((failed++))
fi
echo ""

# 5. Validate git state
echo "[5/5] Validating git state..."
if [ -z "$(git status --short)" ]; then
    echo "✓ Working tree clean"
    ((passed++))
else
    echo "⚠ Uncommitted changes detected:"
    git status --short
    echo ""
fi
echo ""

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "✓ Passed: $passed"
echo "✗ Failed: $failed"
echo ""

if [ $failed -gt 0 ]; then
    echo "⚠ DO NOT PUSH - Fix the above issues first"
    exit 1
else
    echo "✓ All checks passed!"
    echo "✓ Ready to push"
    exit 0
fi
