"""
Integration tests for Flask routes.
Run with: pytest tests/test_routes.py -v
"""

import pytest
import json
from app_init import create_app
from extensions import db
from models import ThreatLog


@pytest.fixture
def app():
    """Create a test Flask app."""
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


class TestMainRoutes:
    """Test main blueprint routes."""

    def test_home_redirect(self, client):
        """Test home page redirects to dashboard."""
        response = client.get("/")
        assert response.status_code == 302
        assert "dashboard" in response.location.lower()

    def test_dashboard_loads(self, client):
        """Test dashboard page loads."""
        response = client.get("/dashboard")
        assert response.status_code == 200
        assert b"dashboard" in response.data.lower() or b"html" in response.data.lower()

    def test_logs_page(self, client):
        """Test logs page loads."""
        response = client.get("/logs")
        assert response.status_code == 200


class TestThreatLookupAPI:
    """Test threat lookup API endpoint."""

    def test_threat_lookup_missing_query(self, client):
        """Test threat lookup requires query."""
        response = client.post(
            "/api/threat_lookup",
            data=json.dumps({}),
            content_type="application/json"
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_threat_lookup_basic(self, client):
        """Test basic threat lookup."""
        response = client.post(
            "/api/threat_lookup",
            data=json.dumps({"query": "https://example.com"}),
            content_type="application/json"
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert "status" in data


class TestURLCheckAPI:
    """Test URL check endpoint."""

    def test_check_url_missing_url(self, client):
        """Test URL check requires URL."""
        response = client.post(
            "/check-url",
            data=json.dumps({}),
            content_type="application/json"
        )
        assert response.status_code == 400

    def test_check_url_empty_url(self, client):
        """Test URL check rejects empty URL."""
        response = client.post(
            "/check-url",
            data=json.dumps({"url": ""}),
            content_type="application/json"
        )
        assert response.status_code == 400


class TestQRScanAPI:
    """Test QR code scan endpoint."""

    def test_qr_scan_no_file(self, client):
        """Test QR scan requires file."""
        response = client.post(
            "/api/scan-qr",
            data={},
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_qr_scan_invalid_file_type(self, client):
        """Test QR scan rejects unsupported file types."""
        response = client.post(
            "/api/scan-qr",
            data={
                "qr_image": (b"not_an_image", "test.txt")
            }
        )
        assert response.status_code == 400


class TestThreatLogSaving:
    """Test threat log database operations."""

    def test_threat_log_creation(self, app):
        """Test creating threat log entries."""
        with app.app_context():
            log = ThreatLog(
                category="url_scan",
                url="https://example.com",
                status="Safe",
                severity="Low",
                flagged_reason="Test"
            )
            db.session.add(log)
            db.session.commit()

            fetched = ThreatLog.query.first()
            assert fetched is not None
            assert fetched.url == "https://example.com"
            assert fetched.status == "Safe"

    def test_threat_logs_query(self, app):
        """Test querying threat logs."""
        with app.app_context():
            for i in range(3):
                log = ThreatLog(
                    category="url_scan",
                    url=f"https://example{i}.com",
                    status="Safe",
                    severity="Low"
                )
                db.session.add(log)
            db.session.commit()

            logs = ThreatLog.query.all()
            assert len(logs) == 3
