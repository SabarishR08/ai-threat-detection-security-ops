import json
import os
import types
from unittest.mock import patch

import pytest

from backend.app import app, load_settings, save_settings
from backend.core.settings_cache import get_settings, invalidate_settings_cache
from backend.app import dispatch_alert
from backend.models import AuditLog, db


@pytest.fixture(autouse=True)
def app_client():
    app.config.update({"TESTING": True})
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client


def authenticate(client):
    resp = client.post("/api/settings/authenticate", json={"username": os.getenv("ADMIN_USERNAME", "admin"), "password": os.getenv("ADMIN_PASSWORD", "admin123")})
    data = resp.get_json()
    assert data and data.get("success")
    return data.get("csrf_token")


def test_cache_invalidation_on_update(client):
    token = authenticate(client)
    before = get_settings()
    # Toggle auto_scan
    payload = {"alerts": before.get("alerts"), "integrations": {}, "system": {"auto_scan": not before["system"]["auto_scan"], "log_retention_days": before["system"]["log_retention_days"]}}
    r = client.post("/api/update_settings", headers={"X-CSRF-Token": token}, json=payload)
    assert r.status_code == 200
    # After update, cache should reflect change immediately
    after = get_settings()
    assert after["system"]["auto_scan"] == payload["system"]["auto_scan"]


def test_auto_scan_disabled_skips_qr(client):
    token = authenticate(client)
    # Disable auto_scan
    current = get_settings()
    payload = {"alerts": current.get("alerts"), "integrations": {}, "system": {"auto_scan": False, "log_retention_days": current["system"]["log_retention_days"]}}
    r = client.post("/api/update_settings", headers={"X-CSRF-Token": token}, json=payload)
    assert r.status_code == 200
    # Call QR scan without file to hit guard quickly
    resp = client.post("/api/scan-qr")
    data = resp.get_json()
    # We expect early skip
    assert data["status"] == "skipped"
    assert data["reason"] == "auto_scan_disabled"
    assert data["skipped_by_config"] is True


def test_alerts_disabled_no_dispatch(client):
    token = authenticate(client)
    # Disable alerts
    current = get_settings()
    payload = {"alerts": {"enabled": False, "scope": current["alerts"]["scope"], "frequency": current["alerts"]["frequency"]}, "integrations": {}, "system": current["system"]}
    r = client.post("/api/update_settings", headers={"X-CSRF-Token": token}, json=payload)
    assert r.status_code == 200
    # Dispatch should skip
    with patch("backend.app.send_brevo_email", return_value=True) as send_mock:
        res = dispatch_alert({"client_ip": "127.0.0.1", "url": "http://evil", "status": "Malicious", "severity": "High"})
        assert res == "skipped_by_config"
        send_mock.assert_not_called()


def test_missing_csrf_returns_419(client):
    # Authenticate to set session, but omit CSRF on update
    authenticate(client)
    current = get_settings()
    payload = {"alerts": current["alerts"], "integrations": {}, "system": current["system"]}
    r = client.post("/api/update_settings", json=payload)
    assert r.status_code == 419
    # Ensure no audit log created
    with app.app_context():
        assert AuditLog.query.count() == 0


def test_audit_log_written_per_change_and_redacted_api_key(client):
    token = authenticate(client)
    # Change two fields and API key
    current = get_settings()
    payload = {
        "alerts": {"enabled": True, "scope": "critical", "frequency": current["alerts"]["frequency"]},
        "integrations": {"virustotal_api_key": "NEW-KEY-123"},
        "system": {"auto_scan": current["system"]["auto_scan"], "log_retention_days": 7}
    }
    r = client.post("/api/update_settings", headers={"X-CSRF-Token": token}, json=payload)
    assert r.status_code == 200
    with app.app_context():
        logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
        assert len(logs) >= 3  # scope, log_retention_days, api key
        # Find api key log
        api_logs = [l for l in logs if l.setting_name == "virustotal_api_key"]
        assert api_logs, "API key audit log missing"
        assert api_logs[0].old_value == "***REDACTED***"
        assert api_logs[0].new_value in ("***REDACTED***", "<cleared>")


def test_api_key_never_returned_in_get_settings(client):
    resp = client.get("/api/get_settings")
    data = resp.get_json()
    assert "integrations" in data
    assert "virustotal_configured" in data["integrations"]
    # Ensure actual key not present anywhere
    flat = json.dumps(data)
    assert "virustotal_api_key" not in flat
