"""
Unit tests for threat lookup and VirusTotal services.
Run with: pytest tests/test_threat_services.py -v
"""

import pytest
import os
from unittest.mock import patch, MagicMock
from services.threat_lookup_service import lookup_url, extract_domain
from services.virustotal_service import check_url_virustotal
from utils.constants import VT_STATUS_SAFE, VT_STATUS_MALICIOUS


class TestExtractDomain:
    """Test domain extraction from URLs."""

    def test_extract_domain_from_https_url(self):
        """Extract domain from HTTPS URL."""
        url = "https://example.com/path"
        domain = extract_domain(url)
        assert domain == "example.com"

    def test_extract_domain_from_http_url(self):
        """Extract domain from HTTP URL."""
        url = "http://test.org/page"
        domain = extract_domain(url)
        assert domain == "test.org"

    def test_extract_domain_with_subdomain(self):
        """Extract domain with subdomain."""
        url = "https://sub.example.co.uk"
        domain = extract_domain(url)
        assert domain == "sub.example.co.uk"

    def test_extract_domain_malformed_url(self):
        """Fallback to raw input for malformed URL."""
        url = "not_a_url"
        domain = extract_domain(url)
        assert domain == "not_a_url"


class TestVirusTotalLookup:
    """Test VirusTotal URL scanning."""

    @patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""})
    def test_vt_missing_api_key(self):
        """Handle missing VirusTotal API key gracefully."""
        result = check_url_virustotal("https://example.com")
        assert result == "VT_API_MISSING"

    @patch("services.virustotal_service.check_urls_async")
    def test_vt_check_safe_url(self, mock_async):
        """Check detection of safe URL."""
        mock_async.return_value = {"https://google.com": VT_STATUS_SAFE}
        result = check_url_virustotal("https://google.com")
        assert result == VT_STATUS_SAFE

    @patch("services.virustotal_service.check_urls_async")
    def test_vt_check_malicious_url(self, mock_async):
        """Check detection of malicious URL."""
        mock_async.return_value = {"https://malware.test": VT_STATUS_MALICIOUS}
        result = check_url_virustotal("https://malware.test")
        assert result == VT_STATUS_MALICIOUS


class TestThreatLookup:
    """Test integrated threat lookup service."""

    @patch("services.virustotal_service.check_url_virustotal")
    @patch("services.google_safebrowsing_service.check_url_safebrowsing")
    @patch("services.rdap_service.rdap_lookup")
    def test_lookup_url_all_services(self, mock_rdap, mock_gsb, mock_vt):
        """Test lookup across all threat intelligence sources."""
        mock_vt.return_value = VT_STATUS_SAFE
        mock_gsb.return_value = {"url": "https://example.com", "status": "Safe"}
        mock_rdap.return_value = {"success": True, "data": {}}

        result = lookup_url("https://example.com")

        assert "virustotal" in result
        assert "google_safebrowsing" in result
        assert "rdap" in result
        assert result["virustotal"] == VT_STATUS_SAFE

    @patch("services.virustotal_service.check_url_virustotal")
    def test_lookup_url_vt_error_graceful(self, mock_vt):
        """Handle VirusTotal errors gracefully."""
        mock_vt.side_effect = Exception("API timeout")

        result = lookup_url("https://example.com")

        assert "virustotal" in result
        assert "error" in result["virustotal"]
