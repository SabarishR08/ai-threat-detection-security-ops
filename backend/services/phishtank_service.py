# backend/services/phishtank_service.py

import httpx
import asyncio
import logging
import os
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")  # Optional


async def check_url_phishtank(url: str) -> dict:
    """
    Check if URL is in PhishTank's verified phishing database.
    Uses public API (no key needed for basic checks).
    Returns status: phishing, safe, or error.
    """
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            # PhishTank requires form-encoded POST with specific user agent
            headers = {
                "User-Agent": "phishtank/ThreatDetection"
            }
            
            data = {
                "url": url,
                "format": "json"
            }
            
            if PHISHTANK_API_KEY:
                data["app_key"] = PHISHTANK_API_KEY
            
            response = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                data=data,
                headers=headers
            )
            
            # PhishTank returns 200 even for errors, check response
            if response.status_code == 403:
                logging.warning(f"PhishTank rate limited or blocked")
                return {"url": url, "status": "N/A", "error": "Rate limited"}
            
            response.raise_for_status()
            result = response.json()
            
            results = result.get("results", {})
            verified = results.get("verified", False)
            in_database = results.get("in_database", False)
            valid = results.get("valid", False)
            
            if verified and in_database:
                return {
                    "url": url,
                    "status": "Phishing",
                    "verified": True,
                    "phish_id": results.get("phish_id"),
                    "submission_time": results.get("submission_time")
                }
            elif in_database and not verified:
                return {
                    "url": url,
                    "status": "Suspicious",
                    "verified": False,
                    "in_database": True
                }
            else:
                return {
                    "url": url,
                    "status": "Safe",
                    "verified": False,
                    "in_database": False
                }
                
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            logging.warning(f"PhishTank API blocked (consider adding API key)")
            return {"url": url, "status": "N/A", "error": "API blocked"}
        logging.error(f"PhishTank HTTP error for {url}: {e}")
        return {"url": url, "status": "Error", "error": str(e)}
    except Exception as e:
        logging.error(f"PhishTank check failed for {url}: {e}")
        return {"url": url, "status": "N/A", "error": str(e)}


async def check_urls_phishtank_async(urls: list) -> list:
    """Check multiple URLs concurrently."""
    tasks = [check_url_phishtank(url) for url in urls]
    return await asyncio.gather(*tasks)
