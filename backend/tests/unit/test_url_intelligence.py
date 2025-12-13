from backend.services.url_intelligence import URLPreprocessor, URLThreatDetector


def test_normalize_url_adds_scheme_and_strips_tracking():
    url = "example.com/path?utm_source=newsletter&ref=abc"
    normalized = URLPreprocessor.normalize_url(url)
    assert normalized.startswith("https://")
    assert "utm_source" not in normalized
    assert "ref" not in normalized


def test_extract_components_splits_domain():
    url = "https://sub.domain.example.com:443/a/b"
    components = URLPreprocessor.extract_components(url)
    assert components["domain"] == "sub.domain.example.com:443" or components["domain"] == "sub.domain.example.com"
    assert components["domain_name"] in ("example", "example.com")  # lenient for parsing differences


def test_detect_threats_flags_ip_and_tld():
    ip_url = "http://192.168.1.10/download.exe"
    result = URLThreatDetector.detect_threats(ip_url)
    assert result["risk_level"] in ("medium", "high")
    assert any("IP-based" in t or "Executable" in t or "download" in t.lower() for t in result["threats"])
