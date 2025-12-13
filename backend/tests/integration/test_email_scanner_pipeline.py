import asyncio

from backend.email_scanner import process_email
from backend.models import ThreatLog


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_process_email_flags_malicious(app_ctx, monkeypatch):
    email_text = "Visit https://bad.example for prizes"
    url = "https://bad.example"

    async def fake_vt(urls, use_cache=True):
        return {url: "Malicious"}

    async def fake_gsb(urls):
        return [{"url": url, "status": "MALWARE"}]

    def fake_classify(text):
        return {"category": "Phishing", "reason": "mock"}

    async def fake_send_alert(subject, body):
        return None

    # Patch external dependencies
    monkeypatch.setattr("backend.email_scanner.check_urls_async", fake_vt)
    monkeypatch.setattr("backend.email_scanner.check_urls_safebrowsing_async", fake_gsb)
    monkeypatch.setattr("backend.email_scanner.classify_email_nlp", fake_classify)
    monkeypatch.setattr("backend.email_scanner.safe_send_alert", fake_send_alert)
    monkeypatch.setattr("backend.email_scanner.socketio", type("S", (), {"emit": lambda *a, **k: None})())

    result = _run(process_email(email_text, 1))

    assert result["flagged_count"] >= 1
    assert result["urls"][url]["virustotal"] == "Malicious"

    # DB should have a threat log entry
    log = ThreatLog.query.filter_by(url=url).first()
    assert log is not None
    assert log.status in ("Malicious", "Suspicious", "Safe")


def test_process_email_safe_no_urls(app_ctx, monkeypatch):
    email_text = "Hello this is a benign note"

    async def fake_vt(urls, use_cache=True):
        return {}

    async def fake_gsb(urls):
        return []

    def fake_classify(text):
        return {"category": "Safe", "reason": "mock"}

    async def fake_send_alert(subject, body):
        return None

    monkeypatch.setattr("backend.email_scanner.check_urls_async", fake_vt)
    monkeypatch.setattr("backend.email_scanner.check_urls_safebrowsing_async", fake_gsb)
    monkeypatch.setattr("backend.email_scanner.classify_email_nlp", fake_classify)
    monkeypatch.setattr("backend.email_scanner.safe_send_alert", fake_send_alert)
    monkeypatch.setattr("backend.email_scanner.socketio", type("S", (), {"emit": lambda *a, **k: None})())

    result = _run(process_email(email_text, 2))

    assert result["flagged_count"] == 0
    log = ThreatLog.query.filter_by(url="(no url)").first()
    assert log is not None
    assert log.status == "Safe"
