# Test Suite Documentation

This directory contains the comprehensive test suite for the Threat Detection Platform.

## Directory Structure

```
tests/
├── conftest.py              # Pytest fixtures and configuration
├── __init__.py              # Test package initialization
├── README.md                # This file
│
├── unit/                    # Unit Tests
│   ├── test_url_intelligence.py       # URL preprocessing and threat detection
│   ├── test_threat_services.py        # Individual threat service tests
│   ├── test_threat_lookup_service.py  # Threat lookup service tests
│   └── test_all_enhancements.py       # Dashboard, browser, SOC enhancements
│
├── integration/             # Integration Tests
│   ├── test_api.py                      # API endpoint integration tests
│   ├── test_api_routes_new.py           # New API routes tests
│   ├── test_routes.py                   # Route integration tests
│   ├── test_email_scanner_pipeline.py   # Email scanner workflow tests
│   ├── test_qr_payloads.py              # QR code payload tests
│   └── test_qr_generator.py             # QR generator integration
│
├── e2e/                     # End-to-End Tests
│   ├── test_suite.py                    # Comprehensive test suite
│   ├── test_endpoint.py                 # Real endpoint testing
│   ├── test_phishing_realworld.py       # Real phishing URL tests
│   ├── test_phishing_urls_realworld.py  # Extended phishing tests
│   ├── test_threat_checker_automated.py # Automated threat checker tests
│   └── test_threat_checker_direct.py    # Direct threat checker tests
│
├── debug/                   # Debug & Manual Testing
│   ├── test_gsb_debug.py      # Google Safe Browsing debug
│   ├── test_phishtank_debug.py # PhishTank debug
│   └── test_smtp.py           # SMTP email testing
│
└── fixtures/                # Test Data & Fixtures
    └── test_log_data-soc_analyzer.log  # Sample log data
```

## Running Tests

### Run All Tests
```bash
# From backend directory
pytest tests/

# With coverage report
pytest tests/ --cov=backend --cov-report=html
```

### Run Specific Test Categories

**Unit Tests (Fast, No External Dependencies)**
```bash
pytest tests/unit/ -v
```

**Integration Tests (Database & API Testing)**
```bash
pytest tests/integration/ -v
```

**E2E Tests (Real API Calls - Requires API Keys)**
```bash
pytest tests/e2e/ -v
```

### Run Specific Test Files
```bash
pytest tests/unit/test_url_intelligence.py -v
pytest tests/integration/test_api_routes_new.py -v
pytest tests/e2e/test_phishing_realworld.py -v
```

### Debug Scripts (Manual Execution)
Debug scripts are not part of automated testing:
```bash
python tests/debug/test_gsb_debug.py
python tests/debug/test_phishtank_debug.py
```

## Test Categories Explained

### Unit Tests
- Test individual functions and classes in isolation
- Use mocks for external dependencies
- Fast execution (< 1s per test)
- No external API calls
- No database dependencies

### Integration Tests
- Test component interactions
- Use test database (SQLite in-memory)
- May mock external APIs
- Test API endpoints and routes
- Moderate execution time (1-5s per test)

### End-to-End Tests
- Full system testing
- Real external API calls
- Requires valid API keys in `.env`
- Tests complete workflows
- Slower execution (5-30s per test)

### Debug Scripts
- Manual testing tools
- Service-specific debugging
- Not run in CI/CD
- Used for troubleshooting

## Prerequisites

### Environment Setup
1. **Python Environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

2. **Environment Variables**
   Create `.env` file with required API keys:
   ```env
   VIRUSTOTAL_API_KEY=your_key_here
   GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
   GEMINI_API_KEY=your_key_here
   PHISHTANK_API_KEY=your_key_here
   ABUSEIPDB_API_KEY=your_key_here
   BREVO_API_KEY=your_key_here
   ```

### For Email Scanner Tests
- Gmail OAuth credentials in `backend/credentials/credentials.json`
- First run will create `token.pickle`

## Pytest Configuration

The `conftest.py` file provides shared fixtures:

- `app` - Flask application instance with test config
- `app_ctx` - Flask application context
- `client` - Test client for API requests

## Writing New Tests

### Unit Test Template
```python
import pytest
from backend.services.your_service import YourService

def test_your_function():
    """Test description."""
    result = YourService.your_function("input")
    assert result == "expected_output"
```

### Integration Test Template
```python
def test_your_endpoint(client):
    """Test API endpoint."""
    response = client.post('/api/endpoint', json={"key": "value"})
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'success'
```

### E2E Test Template
```python
import requests

def test_full_workflow():
    """Test complete user workflow."""
    # Setup
    url = "https://example.com"
    
    # Execute
    response = requests.post("http://localhost:5000/check-url", 
                           json={"url": url})
    
    # Verify
    assert response.status_code == 200
    assert response.json()['final_status'] in ['safe', 'malicious']
```

## Test Naming Conventions

- Test files: `test_*.py`
- Test functions: `test_*` or `def test_*`
- Test classes: `Test*` or `class Test*`
- Use descriptive names: `test_url_validation_rejects_invalid_format`

## CI/CD Integration

Tests are organized for staged CI/CD execution:

1. **PR Checks** - Run unit tests only (fast feedback)
2. **Merge to Dev** - Run unit + integration tests
3. **Deploy to Staging** - Run all tests including E2E
4. **Production** - Smoke tests only

## Coverage Goals

- **Unit Tests**: > 80% coverage
- **Integration Tests**: Critical paths covered
- **E2E Tests**: Happy path + major error scenarios

## Troubleshooting

### Common Issues

**Import Errors**
```bash
# Ensure backend is in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Database Errors**
- Tests use in-memory SQLite
- Check `conftest.py` fixture setup

**API Rate Limits**
- Use mocks for unit/integration tests
- E2E tests may hit rate limits
- Add delays between E2E test runs

**Missing API Keys**
- Check `.env` file exists
- Verify all required keys are set
- Use `.env.example` as template

## Best Practices

1. ✅ **Keep unit tests fast** - Use mocks for external dependencies
2. ✅ **One assertion per test** - Makes failures clear
3. ✅ **Use fixtures** - Share common setup in conftest.py
4. ✅ **Test edge cases** - Not just happy paths
5. ✅ **Clean test data** - Each test should be independent
6. ✅ **Meaningful names** - Test name should describe what's being tested
7. ✅ **Document complex tests** - Add docstrings explaining the test

## Contributing

When adding new features:
1. Write unit tests first (TDD approach)
2. Add integration tests for API changes
3. Update E2E tests for workflow changes
4. Update this README if adding new test categories
5. Ensure all tests pass before submitting PR

## Support

For test-related questions:
- Check existing test files for examples
- Review pytest documentation: https://docs.pytest.org/
- See project architecture docs in `/docs/architecture/`
