import io
import os
import sys
import pytest
import types
from unittest.mock import patch

# Ensure backend package is on path for direct module imports used inside app.py
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.extensions import db, limiter
from backend.app import app as flask_app


@pytest.fixture(scope="session")
def app():
    """Provide a Flask app configured for tests with in-memory DB and no rate limits."""
    flask_app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
        SERVER_NAME="localhost",
    )

    # Disable rate limiting during tests
    try:
        limiter.enabled = False
    except Exception:
        pass

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def app_ctx(app):
    """Push an app context for tests needing DB access."""
    with app.app_context():
        yield


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Prevent any real network calls via requests or httpx."""

    def _blocked(*args, **kwargs):  # pragma: no cover - defensive
        raise RuntimeError("Network access blocked in tests; mock external calls")

    # Block requests
    monkeypatch.setattr("requests.sessions.Session.request", _blocked, raising=True)

    # Block httpx
    try:
        import httpx
        monkeypatch.setattr("httpx.Client.request", _blocked, raising=True)
        monkeypatch.setattr("httpx.AsyncClient.request", _blocked, raising=True)
    except Exception:
        pass

    # Block whois network calls
    try:
        import whois

        def _fake_whois(domain):
            return type("W", (), {"creation_date": None})()

        monkeypatch.setattr(whois, "whois", _fake_whois, raising=True)
    except Exception:
        pass


@pytest.fixture()
def vt_safe_response():
    return {
        "final_status": "Safe",
        "severity": "Low",
        "detected_by": "MockVT",
        "sources": {"virustotal": "Safe"},
        "cache": {"virustotal": True},
        "ai": {"ai_final_verdict": "Safe", "reasoning": "mock"},
    }


@pytest.fixture()
def vt_malicious_response():
    return {
        "final_status": "Malicious",
        "severity": "High",
        "detected_by": "MockVT",
        "sources": {"virustotal": "Malicious"},
        "cache": {"virustotal": False},
        "ai": {"ai_final_verdict": "Malicious", "reasoning": "mock"},
    }


@pytest.fixture()
def sample_threat_log():
    """Sample threat log data for testing."""
    from backend.models import ThreatLog
    return ThreatLog(
        url="https://malicious.example.com",
        status="Malicious",
        severity="High",
        detected_by="VirusTotal",
        ai_verdict="Malicious",
        ai_reasoning="Multiple threat indicators detected"
    )


@pytest.fixture()
def sample_urls():
    """Common URLs for testing."""
    return {
        "safe": "https://google.com",
        "malicious": "https://malicious-phishing-test.com",
        "suspicious": "https://suspicious-site.xyz",
        "localhost": "http://localhost:5000",
    }
