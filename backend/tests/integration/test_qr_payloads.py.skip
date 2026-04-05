import os
import io
import json
from app_init import create_app


def load_test_image(name: str) -> bytes:
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    path = os.path.join(base, "dashboard", "static", "images", "tests", name)
    with open(path, "rb") as f:
        return f.read()


def setup_app_client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client(), app


def post_qr(client, img_bytes: bytes, filename: str):
    data = {"qr_image": (io.BytesIO(img_bytes), filename)}
    return client.post("/api/scan-qr", data=data, content_type="multipart/form-data")


def test_wifi_payload_high_risk():
    client, app = setup_app_client()
    img = load_test_image("wifi_evil_twin.png")
    resp = post_qr(client, img, "wifi.png")
    assert resp.status_code == 200
    data = resp.get_json()
    analysis = data.get("analysis", {})
    assert (analysis.get("risk_level") or "").lower() in ("high",)
    assert analysis.get("type") == "wifi"
    # DB log check: last QR entry should exist
    with app.app_context():
        from models import ThreatLog
        log = ThreatLog.query.filter_by(category="qr").order_by(ThreatLog.timestamp.desc()).first()
        assert log is not None
        assert log.status in ("Malicious", "Suspicious")


def test_sms_payload_medium_risk():
    client, _ = setup_app_client()
    img = load_test_image("sms_pay_now.png")
    resp = post_qr(client, img, "sms.png")
    assert resp.status_code == 200
    data = resp.get_json()
    analysis = data.get("analysis", {})
    assert (analysis.get("risk_level") or "").lower() in ("medium",)
    assert analysis.get("type") == "sms"


def test_upi_payload_high_risk():
    client, _ = setup_app_client()
    img = load_test_image("upi_scam.png")
    resp = post_qr(client, img, "upi.png")
    assert resp.status_code == 200
    data = resp.get_json()
    analysis = data.get("analysis", {})
    assert (analysis.get("risk_level") or "").lower() in ("high",)
    assert analysis.get("type") == "payment"
