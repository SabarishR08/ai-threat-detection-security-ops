#!/usr/bin/env python
"""
Local CI Test Runner
Run this before pushing to GitHub to catch errors early

Usage:
    python scripts/run_local_ci.py
"""

import subprocess
import sys
import re
import os
from pathlib import Path

def run_command(cmd, description=""):
    """Run a shell command and return exit code."""
    if description:
        print(f"  {description}...", end=" ", flush=True)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        if description:
            print("✓")
        return True
    else:
        if description:
            print("✗")
        return False

def main():
    print("=" * 50)
    print("Running Local CI Pipeline Tests")
    print("=" * 50)
    print()
    
    os.chdir(Path(__file__).parent.parent)
    
    passed = []
    failed = []
    
    # 1. Check Python version
    print("[1/5] Checking Python version...")
    result = subprocess.run("python --version", shell=True, capture_output=True, text=True)
    version = result.stdout.strip()
    if re.search(r"3\.(11|12)", version):
        print(f"  ✓ Python version OK: {version}")
        passed.append("Python version")
    else:
        print(f"  ✗ Python version mismatch: {version} (need 3.11 or 3.12)")
        failed.append("Python version")
    print()
    
    # 2. Check dependencies
    print("[2/5] Checking dependencies...")
    deps_ok = True
    for dep in ["flask", "pytest", "sqlalchemy", "nest_asyncio"]:
        if run_command(f'python -c "import {dep}"', f"{dep}"):
            pass  # Already printed ✓
        else:
            print(f"    ✗ {dep} - MISSING! Run: pip install -r backend/requirements.txt")
            deps_ok = False
    if deps_ok:
        passed.append("Dependencies")
    else:
        failed.append("Dependencies")
    print()
    
    # 3. Run unit tests
    print("[3/5] Running unit tests...")
    if subprocess.run(
        "python -m pytest -c backend/pytest.ini backend/tests/unit/test_threat_services.py -v --tb=short",
        shell=True,
        capture_output=True
    ).returncode == 0:
        print("  ✓ Unit tests passed")
        passed.append("Unit tests")
    else:
        print("  ✗ Unit tests failed")
        failed.append("Unit tests")
    print()
    
    # 4. Run integration tests
    print("[4/5] Running integration tests...")
    if subprocess.run(
        "python -m pytest -c backend/pytest.ini backend/tests/integration/test_routes.py -v --tb=short",
        shell=True,
        capture_output=True
    ).returncode == 0:
        print("  ✓ Integration tests passed")
        passed.append("Integration tests")
    else:
        print("  ✗ Integration tests failed")
        failed.append("Integration tests")
    print()
    
    # 5. Validate git state
    print("[5/5] Validating git state...")
    result = subprocess.run("git status --short", shell=True, capture_output=True, text=True)
    if not result.stdout.strip():
        print("  ✓ Working tree clean")
        passed.append("Git state")
    else:
        print("  ⚠ Uncommitted changes detected:")
        for line in result.stdout.strip().split("\n"):
            print(f"    {line}")
        print()
    print()
    
    # Summary
    print("=" * 50)
    print("Test Summary")
    print("=" * 50)
    print(f"✓ Passed: {len(passed)}")
    print(f"✗ Failed: {len(failed)}")
    print()
    
    if failed:
        print("Failed checks:")
        for check in failed:
            print(f"  - {check}")
        print()
        print("⚠ DO NOT PUSH - Fix the above issues first")
        return 1
    else:
        print("✓ All checks passed!")
        print("✓ Ready to push")
        return 0

if __name__ == "__main__":
    sys.exit(main())
