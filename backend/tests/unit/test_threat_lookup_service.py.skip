import asyncio

import pytest

from backend.services import threat_lookup_service as tls


@pytest.mark.asyncio
async def test_unified_check_url_vt_malicious(monkeypatch):
    url = "https://evil.example"

    async def fake_vt(u, use_cache=True):
        return "Malicious"

    async def fake_gsb(u):
        return {"status": "Safe"}

    async def fake_pt(u):
        return {"status": "Safe"}

    def fake_ai(payload):
        return {"ai_final_verdict": "Unknown", "confidence": 0.0, "reasoning": "mock"}

    monkeypatch.setattr(tls, "check_url_virustotal_async", fake_vt)
    monkeypatch.setattr(tls, "check_url_safebrowsing", fake_gsb)
    monkeypatch.setattr(tls, "check_url_phishtank", fake_pt)
    monkeypatch.setattr(tls, "analyze_threat_fusion", fake_ai)
    monkeypatch.setattr(tls, "url_cache", {url: "Malicious"})

    result = await tls.unified_check_url_async(url)
    assert result["final_status"] == "Malicious"
    assert result["severity"] == "High"
    assert result["detected_by"] == "VirusTotal"
    assert result["cache"]["virustotal"] is True


@pytest.mark.asyncio
async def test_unified_check_url_ai_override(monkeypatch):
    url = "https://safe.example"

    async def fake_vt(u, use_cache=True):
        return "Safe"

    async def fake_gsb(u):
        return {"status": "Safe"}

    async def fake_pt(u):
        return {"status": "Safe"}

    def fake_ai(payload):
        return {
            "ai_final_verdict": "Phishing",
            "confidence": 0.9,
            "reasoning": "mock ai verdict",
            "severity_score": 8,
        }

    monkeypatch.setattr(tls, "check_url_virustotal_async", fake_vt)
    monkeypatch.setattr(tls, "check_url_safebrowsing", fake_gsb)
    monkeypatch.setattr(tls, "check_url_phishtank", fake_pt)
    monkeypatch.setattr(tls, "analyze_threat_fusion", fake_ai)
    monkeypatch.setattr(tls, "url_cache", {})

    result = await tls.unified_check_url_async(url)
    assert result["final_status"] == "Phishing"
    assert result["severity"] == "High"
    assert result["detected_by"] == "Gemini"
    assert result["ai"]["ai_final_verdict"] == "Phishing"
