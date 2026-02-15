# backend/services/google_safebrowsing_service.py

import os
import httpx
import asyncio
import logging
from functools import lru_cache
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

# Persistent HTTP client for connection pooling
_GSB_CLIENT = None
_CLIENT_LIMITS = httpx.Limits(max_keepalive_connections=10, max_connections=50)
_CLIENT_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Threat types we want (v5)
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
    "THREAT_TYPE_UNSPECIFIED",
]

PLATFORM_TYPES = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


def get_gsb_client():
    """Get or create persistent HTTP client."""
    global _GSB_CLIENT
    if _GSB_CLIENT is None:
        _GSB_CLIENT = httpx.AsyncClient(
            limits=_CLIENT_LIMITS,
            timeout=_CLIENT_TIMEOUT,
            http2=True
        )
    return _GSB_CLIENT


async def close_gsb_client():
    """Close the GSB HTTP client."""
    global _GSB_CLIENT
    if _GSB_CLIENT is not None:
        await _GSB_CLIENT.aclose()
        _GSB_CLIENT = None


# Simple result cache (in-memory, 5-minute TTL)
_gsb_cache = {}
_CACHE_TTL_SECONDS = 300


@lru_cache(maxsize=512)
def _build_gsb_url() -> str:
    """Build GSB API URL (cached)."""
    return f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"


async def check_url_safebrowsing(url: str):
    """Google Safe Browsing v4 lookup for a single URL (with caching & connection pooling)."""

    if not SAFE_BROWSING_API_KEY or len(SAFE_BROWSING_API_KEY) < 10:
        return {"url": url, "status": "Unknown (No API Key)", "reason": "Safe Browsing API not configured"}

    # Check cache first
    from datetime import datetime, timedelta
    cache_key = url
    if cache_key in _gsb_cache:
        cached_result, cached_time = _gsb_cache[cache_key]
        if datetime.utcnow() - cached_time < timedelta(seconds=_CACHE_TTL_SECONDS):
            return cached_result
        else:
            del _gsb_cache[cache_key]

    try:
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": url}],
            },
        }

        # Use persistent client (connection pooling)
        client = get_gsb_client()
        response = await client.post(_build_gsb_url(), json=payload)

        if response.status_code == 403:
            logging.warning("Safe Browsing API key invalid or expired")
            return {"url": url, "status": "Unavailable", "reason": "API key invalid"}

        response.raise_for_status()
        data = response.json()

        matches = data.get("matches") or []
        if not matches:
            return {"url": url, "status": "Safe"}

        threat_types = {match.get("threatType", "UNKNOWN") for match in matches}
        threat_description = ", ".join(sorted(threat_types))
        return {"url": url, "status": threat_description, "matches": matches}

    except httpx.HTTPStatusError as e:
        logging.error(f"Safe Browsing HTTP error for {url}: {e}")
        return {"url": url, "status": "Error", "error": str(e)}
    except Exception as e:
        logging.error(f"Safe Browsing check failed for {url}: {e}")
        return {"url": url, "status": "Error", "error": str(e)}


async def check_urls_safebrowsing_async(urls: list[str]):
    """Check multiple URLs concurrently."""
    tasks = [check_url_safebrowsing(url) for url in urls]
    return await asyncio.gather(*tasks)
