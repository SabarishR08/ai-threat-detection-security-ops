# 🛠️ TEST IMPLEMENTATION GUIDE
**Step-by-Step Instructions for Fixing & Expanding Tests**

---

## QUICK START

### Step 1: Review Current State (5 min)
```bash
cd backend
pytest --collect-only -q  # See all tests
pytest tests/ --tb=no -q  # See summary
```

### Step 2: Fix pytest.ini (2 min)
Update `backend/pytest.ini` - Add asyncio config

### Step 3: Fix conftest.py (10 min)
Add missing fixtures for Gmail, Gemini, SMTP, SocketIO

### Step 4: Run Tests (2 min)
```bash
pytest tests/ -v --tb=short
```

### Step 5: Add Coverage (2 min)
```bash
pytest tests/ --cov=backend --cov-report=html
```

---

## IMPLEMENTATION TEMPLATES

### Template 1: Unit Test for Service

```python
# tests/unit/test_my_service.py
import pytest
from unittest.mock import MagicMock, patch
from backend.services.my_service import MyService

class TestMyService:
    """Test MyService functionality."""
    
    def test_function_success(self):
        """Test function with valid input."""
        result = MyService.my_function("valid_input")
        assert result == "expected_output"
    
    def test_function_error(self):
        """Test function error handling."""
        with pytest.raises(ValueError):
            MyService.my_function("invalid_input")
    
    def test_function_with_external_call(self, monkeypatch):
        """Test function that calls external service."""
        mock_external = MagicMock(return_value="mocked")
        monkeypatch.setattr(
            "backend.services.my_service.external_api_call",
            mock_external
        )
        
        result = MyService.my_function("input")
        assert result == "expected_with_mock"
        mock_external.assert_called_once()
```

### Template 2: Integration Test for API Endpoint

```python
# tests/integration/test_my_endpoint.py
import pytest
import json

@pytest.mark.integration
class TestMyEndpoint:
    """Test API endpoint."""
    
    def test_endpoint_success(self, client):
        """Test endpoint with valid request."""
        response = client.post(
            "/api/my_endpoint",
            json={"param": "value"},
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "success"
        assert "result" in data
    
    def test_endpoint_error(self, client):
        """Test endpoint error handling."""
        response = client.post(
            "/api/my_endpoint",
            json={}  # Missing required param
        )
        
        assert response.status_code == 400
        data = response.get_json()
        assert "error" in data
    
    def test_endpoint_database(self, client, app_ctx):
        """Test endpoint with database."""
        from backend.models import MyModel
        
        # Create test data
        obj = MyModel(param="value")
        db.session.add(obj)
        db.session.commit()
        
        # Test endpoint
        response = client.get("/api/my_endpoint")
        
        # Verify response
        assert response.status_code == 200
        # Verify database
        assert MyModel.query.count() >= 1
```

### Template 3: Async Test

```python
# tests/unit/test_async_service.py
import pytest
import asyncio

@pytest.mark.asyncio
async def test_async_function():
    """Test async function."""
    from backend.services.async_service import async_function
    
    result = await async_function("input")
    assert result == "output"

@pytest.mark.asyncio
async def test_async_with_mock(monkeypatch):
    """Test async with mocked external call."""
    async def fake_external(param):
        return "mocked"
    
    monkeypatch.setattr(
        "backend.services.async_service.external_call",
        fake_external
    )
    
    result = await async_function("input")
    assert result == "expected_with_mock"
```

### Template 4: Fixture for Mocking External Service

```python
# tests/conftest.py - Add to existing file

from unittest.mock import MagicMock, AsyncMock

@pytest.fixture()
def virustotal_mock(monkeypatch):
    """Mock VirusTotal API responses."""
    
    async def fake_check_url(url, use_cache=True):
        # Return malicious for known bad URLs
        if "bad" in url:
            return "Malicious"
        return "Safe"
    
    mock_module = MagicMock()
    mock_module.check_url_virustotal_async = AsyncMock(side_effect=fake_check_url)
    
    monkeypatch.setattr(
        "backend.services.virustotal_service",
        mock_module
    )
    
    return mock_module

@pytest.fixture()
def gemini_mock(monkeypatch):
    """Mock Gemini LLM responses."""
    
    def fake_detect_phishing(email_text):
        return {
            "category": "Phishing" if "click here" in email_text.lower() else "Legitimate",
            "confidence": 0.95,
            "reason": "Detected phishing indicators"
        }
    
    monkeypatch.setattr(
        "backend.services.gemini_service.detect_phishing_in_email",
        fake_detect_phishing
    )

@pytest.fixture()
def email_mock(monkeypatch):
    """Mock email sending."""
    from unittest.mock import MagicMock
    
    mock_send = MagicMock(return_value=True)
    monkeypatch.setattr(
        "backend.email_alerts.send_alert_email",
        mock_send
    )
    
    return mock_send
```

### Template 5: Database Test

```python
# tests/integration/test_models.py
import pytest
from backend.models import ThreatLog, Alert
from backend.extensions import db

@pytest.mark.integration
class TestThreatLogModel:
    """Test ThreatLog database model."""
    
    def test_create_threat_log(self, app_ctx):
        """Test creating a threat log."""
        log = ThreatLog(
            url="https://example.com",
            status="Malicious",
            severity="High",
            category="url_scan"
        )
        
        db.session.add(log)
        db.session.commit()
        
        # Retrieve and verify
        retrieved = ThreatLog.query.filter_by(url="https://example.com").first()
        assert retrieved is not None
        assert retrieved.status == "Malicious"
        assert retrieved.severity == "High"
    
    def test_threat_log_relationships(self, app_ctx):
        """Test relationships between models."""
        # Create alert
        alert = Alert(
            type="url_malicious",
            severity="High",
            message="Malicious URL detected"
        )
        db.session.add(alert)
        db.session.commit()
        
        # Verify
        retrieved_alert = Alert.query.first()
        assert retrieved_alert is not None
```

### Template 6: Email Scanner Test

```python
# tests/integration/test_email_scanner.py
import pytest
from backend.email_scanner import process_email
from backend.models import ThreatLog
from backend.extensions import db

@pytest.mark.integration
def test_email_scanner_detects_malicious_urls(app_ctx, monkeypatch):
    """Test email scanner detects malicious URLs."""
    
    # Mock threat lookup
    async def fake_check_urls(urls, use_cache=True):
        return {
            "https://malicious.example": "Malicious",
            "https://safe.example": "Safe"
        }
    
    monkeypatch.setattr(
        "backend.email_scanner.check_urls_async",
        fake_check_urls
    )
    
    # Process email
    email_text = """
    Click here: https://malicious.example
    Or visit: https://safe.example
    """
    
    result = asyncio.run(process_email(email_text, user_id=1))
    
    # Verify results
    assert result["flagged_count"] >= 1
    assert result["urls"]["https://malicious.example"]["status"] == "Malicious"
    
    # Verify database
    log = ThreatLog.query.filter_by(url="https://malicious.example").first()
    assert log is not None
    assert log.status == "Malicious"

def test_email_scanner_safe_email(app_ctx, monkeypatch):
    """Test email scanner passes safe emails."""
    
    async def fake_check_urls(urls, use_cache=True):
        return {}  # All safe
    
    monkeypatch.setattr(
        "backend.email_scanner.check_urls_async",
        fake_check_urls
    )
    
    email_text = "Hello, this is a safe email"
    result = asyncio.run(process_email(email_text, user_id=1))
    
    assert result["flagged_count"] == 0
```

### Template 7: SOC Analyzer Test

```python
# tests/integration/test_soc_analyzer.py
import pytest
from backend.soc_analyzer import analyze_logs

@pytest.mark.integration
def test_soc_analyzer_detects_threats():
    """Test SOC analyzer detects threats in logs."""
    
    log_content = """
    2024-12-14 10:15:23 192.168.1.100 - - "GET /admin HTTP/1.1" 401
    2024-12-14 10:15:25 192.168.1.100 - - "GET /admin HTTP/1.1" 401
    2024-12-14 10:15:27 192.168.1.100 - - "GET /admin HTTP/1.1" 401
    2024-12-14 10:15:29 192.168.1.100 - - "GET /admin HTTP/1.1" 401
    2024-12-14 10:15:31 192.168.1.100 - - "GET /admin HTTP/1.1" 401
    """
    
    result = analyze_logs(log_content)
    
    # Should detect brute force
    assert len(result["threats"]) >= 1
    assert "brute_force" in result["threat_types"] or "multiple_failures" in str(result).lower()
    
    # Should extract IPs
    assert "192.168.1.100" in result["ips_found"]

def test_soc_analyzer_extracts_ips():
    """Test IP extraction."""
    
    log_content = """
    Connection from 10.0.0.1
    Access from 192.168.1.50
    Alert: 8.8.8.8 attempted login
    """
    
    result = analyze_logs(log_content)
    
    # Should extract IPs
    ips = result.get("ips_found", [])
    assert "10.0.0.1" in ips or "10.0.0.1" in str(ips)
    assert "192.168.1.50" in ips or "192.168.1.50" in str(ips)
    assert "8.8.8.8" in ips or "8.8.8.8" in str(ips)
```

### Template 8: Risk Scoring Test

```python
# tests/unit/test_risk_scoring.py
import pytest
from backend.services.risk_scoring import RiskScorer

class TestRiskScoring:
    """Test risk scoring logic."""
    
    def test_low_risk_safe_url(self):
        """Test low risk for safe URL."""
        threat_data = {
            "final_status": "Safe",
            "sources": {
                "virustotal": "Safe",
                "safebrowsing": "Safe",
                "phishtank": "Safe"
            }
        }
        
        score = RiskScorer.calculate_score(threat_data)
        assert score <= 30  # Low risk
    
    def test_high_risk_malicious(self):
        """Test high risk for malicious URL."""
        threat_data = {
            "final_status": "Malicious",
            "sources": {
                "virustotal": "Malicious",
                "safebrowsing": "Malware",
                "phishtank": "Malicious"
            }
        }
        
        score = RiskScorer.calculate_score(threat_data)
        assert score >= 70  # High risk
    
    def test_medium_risk_suspicious(self):
        """Test medium risk for suspicious URL."""
        threat_data = {
            "final_status": "Suspicious",
            "sources": {
                "virustotal": "Safe",
                "safebrowsing": "Safe",
                "phishtank": "Suspicious"
            }
        }
        
        score = RiskScorer.calculate_score(threat_data)
        assert 30 <= score <= 70  # Medium risk
```

---

## FIXING EXISTING TESTS

### Fix 1: Import Paths

```python
# BEFORE (in all test files)
from services.threat_lookup_service import lookup_url
from models import ThreatLog

# AFTER
from backend.services.threat_lookup_service import lookup_url
from backend.models import ThreatLog
```

### Fix 2: Async Configuration

```ini
# pytest.ini - Add these lines
[pytest]
asyncio_mode = auto
asyncio_default_fixture_scope = function

# Add to markers
markers =
    asyncio: marks tests as async
```

### Fix 3: Test Isolation

```python
# conftest.py - Change app fixture

# BEFORE
@pytest.fixture(scope="session")
def app():
    # ...

# AFTER
@pytest.fixture(scope="function")  # Changed from session
def app():
    flask_app.config.update(TESTING=True, SQLALCHEMY_DATABASE_URI="sqlite:///:memory:")
    
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()  # Add this line
```

---

## VERIFICATION CHECKLIST

After applying fixes, verify:

- [ ] No import errors: `pytest --collect-only`
- [ ] No syntax errors: `python -m pytest --collect-only`
- [ ] Existing tests pass: `pytest tests/unit/ -v`
- [ ] Fixtures work: `pytest tests/ -v -k "fixture"`
- [ ] No network calls: All tests use mocks
- [ ] Coverage report: `pytest --cov=backend --cov-report=html`
- [ ] Coverage >50%: Check htmlcov/index.html

---

## COMMANDS REFERENCE

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=backend --cov-report=html

# Run specific category
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/e2e/ -v

# Run specific test
pytest tests/unit/test_my_module.py::TestClass::test_function -v

# Run with output
pytest tests/ -v -s

# Run parallel (faster)
pytest tests/ -n auto

# Run and debug
pytest tests/ -vv --tb=long

# Show test collection
pytest --collect-only -q
```

---

## SUCCESS METRICS

✅ **Phase 1 (Fixes)**
- All tests collect without errors
- No import errors
- >80% of existing tests pass

✅ **Phase 2 (New Tests)**
- +50 new tests
- Email scanner: 10 tests
- Threat services: 15 tests
- SOC analyzer: 12 tests
- Alert/Risk: 13 tests
- Coverage: 65%+

✅ **Phase 3 (Complete)**
- +36 additional tests
- All modules covered
- Coverage: 85%+
- All tests passing

---

## TROUBLESHOOTING

### Tests Hang
**Cause**: Network calls not blocked
**Fix**: Check conftest.py block_network fixture is applied

### Import Errors
**Cause**: Wrong import paths
**Fix**: Use `from backend.module import func` not `from module import func`

### Async Tests Fail
**Cause**: pytest-asyncio not configured
**Fix**: Add `asyncio_mode = auto` to pytest.ini

### Tests Share State
**Cause**: app fixture scope="session"
**Fix**: Change to scope="function" and add db.drop_all()

### Coverage Too Low
**Cause**: Untested code
**Fix**: Use --cov-report=html to identify gaps, add tests

---

## NEXT ACTIONS

1. Copy conftest.py additions (5 min)
2. Fix pytest.ini (2 min)
3. Fix import paths (10 min)
4. Run `pytest tests/ -v` (5 min)
5. Add new test files from templates (ongoing)
6. Run coverage report (2 min)
7. Increase coverage to 85%+ (ongoing)

**Total time estimate**: 30 min to get passing, 5+ hours to complete

