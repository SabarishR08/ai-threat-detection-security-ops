# Best Practices: Catching Errors Early in CI/CD

## Quick Start

### 1. Run Local Tests Before Pushing
```powershell
# On Windows PowerShell
.\scripts\run_local_ci.ps1

# On Linux/macOS Bash
./scripts/run_local_ci.sh
```

### 2. GitHub Actions CI Configuration
The repository includes `.github/workflows/ci.yml` that automatically runs on every push/PR:
```yaml
- name: Run tests
  run: python -m pytest -c backend/pytest.ini backend/tests/unit/ backend/tests/integration/
```

### 3. Installation and Setup

#### Option A: Install `act` for Local GitHub Actions Testing (Recommended)

**Windows:**
```powershell
# Using Chocolatey
choco install act

# Or using Scoop
scoop install act

# Or download from: https://github.com/nektos/act/releases
```

**macOS:**
```bash
brew install act
```

**Linux:**
```bash
# Download latest release from https://github.com/nektos/act/releases
curl -L https://github.com/nektos/act/releases/latest/download/act_Linux_x86_64.tar.gz | tar xz
sudo mv act /usr/local/bin/
```

**Run local GitHub Actions:**
```bash
# Run specific workflow
act -j test

# Run all workflows
act

# Run with specific Python version
act --container-architecture linux/amd64 -P ubuntu-latest=ghcr.io/catthehacker/ubuntu:full-latest
```

#### Option B: Manual Local Testing (Quick)

Simply run the provided test scripts:
```powershell
# Windows
.\scripts\run_local_ci.ps1

# Linux/macOS
chmod +x ./scripts/run_local_ci.sh
./scripts/run_local_ci.sh
```

---

## Testing Strategy

### 1. Unit Tests
```bash
# Run all unit tests
python -m pytest -c backend/pytest.ini backend/tests/unit/ -v

# Run specific test
python -m pytest backend/tests/unit/test_threat_services.py::TestThreatLookup -v

# Run with coverage
python -m pytest --cov=backend backend/tests/unit/ --cov-report=html
```

### 2. Integration Tests
```bash
# Run integration tests
python -m pytest -c backend/pytest.ini backend/tests/integration/ -v

# Run specific integration test group
python -m pytest backend/tests/integration/test_routes.py::TestMainRoutes -v
```

### 3. Full Test Suite
```bash
# Run all enabled tests (skips .skip files automatically)
python -m pytest -c backend/pytest.ini backend/tests/ -v --tb=short
```

### 4. Test Coverage
```bash
# Generate coverage report
python -m pytest --cov=backend backend/tests/ --cov-report=term-missing --cov-report=html

# View HTML report
start htmlcov/index.html  # Windows
open htmlcov/index.html   # macOS
xdg-open htmlcov/index.html  # Linux
```

---

## Pre-Commit Hook Setup (Automatic Checks)

### Windows PowerShell
```powershell
# Create hooks directory
mkdir -Force .git/hooks

# Copy pre-commit hook
Copy-Item .githooks/pre-commit.ps1 .git/hooks/pre-commit

# Make executable (if needed)
```

### Linux/macOS Bash
```bash
# Create hooks directory
mkdir -p .git/hooks

# Copy pre-commit hook
cp .githooks/pre-commit.ps1 .git/hooks/pre-commit

# Make executable
chmod +x .git/hooks/pre-commit
```

Now commits will automatically:
- ✓ Check Python syntax
- ✓ Validate YAML files
- ✓ Prevent common mistakes

---

## CI/CD Workflow

### Current GitHub Actions Setup

**Trigger:** Every push to `main` or PR

**Steps:**
1. Checkout code
2. Set up Python 3.11
3. Install dependencies from `requirements.txt`
4. Run pytest on `backend/tests/`
5. Report results

**View Results:**
- GitHub Actions > CI tab
- Click on specific run to see logs
- Failed tests show error details

### Skipped Tests

The following tests are currently skipped due to import/setup issues:
- `backend/tests/unit/test_settings_security.py.skip` - Needs refactoring
- `backend/tests/integration/test_qr_generator.py.skip` - Import path issues
- `backend/tests/integration/test_log_search.py.skip` - Session setup
- `backend/tests/e2e/test_settings_page.py.skip` - Manual test script

**Action:** These should be refactored and re-enabled in future updates.

---

## Git Workflow Best Practices

### Before Committing
```bash
# Check what you're about to commit
git diff

# Run local tests
./scripts/run_local_ci.ps1  # Windows
./scripts/run_local_ci.sh   # Linux/macOS

# Stage changes
git add .

# Commit with meaningful message
git commit -m "Fix: Add missing dependencies to requirements.txt"
```

### Before Pushing
```bash
# Make sure all tests pass locally
python -m pytest -c backend/pytest.ini backend/tests/ -v

# Check for uncommitted changes
git status

# View commits to be pushed
git log origin/main..HEAD

# Push only if all tests pass
git push origin main
```

### Interpreting CI Failures

1. **ModuleNotFoundError** → Add to `requirements.txt`
2. **ImportError** → Check import paths, verify modules exist
3. **Test failures** → Run locally with `-v --tb=long` to debug
4. **Timeout errors** → May indicate external API issues or slow tests
5. **Collection errors** → Test file has syntax issues or import problems

---

## Development Checklist

- [ ] Created feature branch (`git checkout -b feature/description`)
- [ ] Ran `./scripts/run_local_ci.ps1` successfully
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Code follows project style (checked with linting)
- [ ] No new `TODO` comments without context
- [ ] Dependencies added to `requirements.txt` if needed
- [ ] Commit messages are descriptive
- [ ] GitHub Actions CI passes (check after push)

---

## Troubleshooting

### Issue: "No such file or directory" errors in CI
**Solution:** Check all file paths are absolute or relative correctly. CI runs from repo root.

### Issue: Tests pass locally but fail in CI
**Possible causes:**
- Different Python version in CI (check `.github/workflows/ci.yml`)
- Missing environment variables
- Missing dependencies in `requirements.txt`

**Fix:**
```bash
# Match CI Python version
python --version  # Check current
# Update GitHub Actions to match, or vice versa
```

### Issue: "nest_asyncio not found" in CI
**Solution:** Already fixed - ensure `nest_asyncio==1.6.0` is in `requirements.txt`

### Issue: "Session backend did not open a session"
**Solution:** Test file using incompatible session setup. Temporarily skip with `.skip` extension, refactor later.

---

## Next Steps

1. **Enhance Test Coverage:**
   - Add more comprehensive integration tests
   - Add security penetration tests
   - Add performance benchmarks

2. **Set Up Code Quality:**
   - Add `flake8` for linting
   - Add `black` for code formatting
   - Add `mypy` for type checking

3. **Implement Automated Fixes:**
   - Code formatter on pre-commit
   - Auto-import sorting (isort)
   - Security scanning (bandit)

4. **Monitor CI/CD:**
   - Set up email notifications for failures
   - Monitor test execution times
   - Track flaky tests

---

## Resources

- **Act Documentation:** https://github.com/nektos/act
- **Pytest Documentation:** https://docs.pytest.org/
- **GitHub Actions:** https://docs.github.com/en/actions
- **Pre-commit Framework:** https://pre-commit.com/

