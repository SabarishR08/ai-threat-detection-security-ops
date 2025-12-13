# backend/services/google_safebrowsing_service.py

import os
import httpx
import asyncio
import logging
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

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


async def check_url_safebrowsing(url: str):
    """Google Safe Browsing v4 lookup for a single URL."""

    if not SAFE_BROWSING_API_KEY or len(SAFE_BROWSING_API_KEY) < 10:
        return {"url": url, "status": "Unknown (No API Key)", "reason": "Safe Browsing API not configured"}

    try:
        # Use v4 endpoint (more reliable than v5)
        sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"

        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": PLATFORM_TYPES,
                "threatEntryTypes": THREAT_ENTRY_TYPES,
                "threatEntries": [{"url": url}],
            },
        }

        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(sb_url, json=payload)

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
