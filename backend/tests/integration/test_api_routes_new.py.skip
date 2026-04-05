import io
import json
from unittest import mock

import pytest


def test_check_url_safe(client, vt_safe_response, monkeypatch):
    monkeypatch.setattr(
        "backend.services.threat_lookup_service.unified_check_url",
        lambda url, force_refresh=False, include_ip_enrichment=False: vt_safe_response,
    )

    resp = client.post("/check-url", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "Safe"
    assert data["severity"] == "Low"


def test_threat_lookup_basic(client, vt_safe_response, monkeypatch):
    monkeypatch.setattr(
        "backend.services.threat_lookup_service.unified_check_url",
        lambda url, force_refresh=False, include_ip_enrichment=False: vt_safe_response,
    )
    resp = client.post("/api/threat_lookup", json={"query": "https://example.com"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "Safe"


def test_threat_lookup_requires_url(client):
    resp = client.post("/api/threat_lookup", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


def test_tab_activity_logs(client):
    resp = client.post(
        "/api/tab-activity", json={"url": "https://example.com", "title": "Test", "action": "switch"}
    )
    assert resp.status_code == 200
    assert resp.get_json().get("ok") is True


def test_scan_qr_malicious(client, vt_malicious_response, monkeypatch):
    # Mock QR decode to return a URL
    mock_detector = mock.MagicMock()
    mock_detector.detectAndDecode.return_value = ("https://bad.example", None, None)
    monkeypatch.setattr("cv2.QRCodeDetector", lambda: mock_detector)

    # Mock VirusTotal HTTP calls used in the route
    class MockResp:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self._payload = payload

        def json(self):
            return self._payload

    def mock_post(url, headers=None, data=None, timeout=None):
        return MockResp(200, {"data": {"id": "analysis123"}})

    def mock_get(url, headers=None, timeout=None):
        return MockResp(200, {"data": {"attributes": {"stats": {"malicious": 1, "suspicious": 0}}}})

    monkeypatch.setattr("requests.post", mock_post)
    monkeypatch.setattr("requests.get", mock_get)

    # Upload a dummy PNG buffer
    dummy_png = b"\x89PNG\r\n\x1a\n"
    data = {"qr_image": (io.BytesIO(dummy_png), "test.png")}
    resp = client.post("/api/scan-qr", data=data, content_type="multipart/form-data")

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["urls_found"] == ["https://bad.example"]
    assert payload["results"]["https://bad.example"] in ("Malicious", "Suspicious", "Safe")
