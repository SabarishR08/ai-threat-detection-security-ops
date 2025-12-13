import os
import json
import asyncio
import httpx
import logging
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
CACHE_FILE = r"cache/url_cache.json"

# Load or initialize cache
url_cache = {}
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            url_cache = json.load(f)
    except Exception as e:
        logging.error(f"[VirusTotal] Failed to load cache: {e}")
        url_cache = {}

def save_cache():
    """Save cache to file with error handling."""
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump(url_cache, f)
    except Exception as e:
        logging.error(f"[VirusTotal] Failed to save cache: {e}")


async def fetch_vt_status(client, url, use_cache: bool = True):
    """Fetch the final VirusTotal analysis status for a URL (OPTIMIZED for speed).
    use_cache=True: Check cache only (instant, no API calls)
    use_cache=False: Submit for analysis and poll (slower but fresh)
    """
    env_key = os.getenv("VIRUSTOTAL_API_KEY")
    api_key = env_key if env_key is not None else VIRUSTOTAL_API_KEY

    # Step 1: Always check cache first (super fast)
    if url in url_cache and url_cache[url] not in ["Error", "VT_API_MISSING"]:
        return url, url_cache[url]
    
    # Step 2: If use_cache=True, return cached result or default, but honor missing API key
    if use_cache:
        if not api_key:
            url_cache[url] = "VT_API_MISSING"
            save_cache()
            return url, "VT_API_MISSING"
        result = url_cache.get(url, "Unknown")  # Neutral default if not cached
        return url, result

    # Step 3: Only submit/poll if use_cache=False (force fresh)
    if not api_key:
        url_cache[url] = "VT_API_MISSING"
        save_cache()
        return url, "VT_API_MISSING"

    try:
        # Step 4: Submit URL for analysis
        resp = await client.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            data={"url": url},
            timeout=10  # Reduced from 30
        )
        resp.raise_for_status()
        analysis_id = resp.json()["data"]["id"]

        # Step 5: Poll with SHORT timeout (3 attempts max = 6 seconds)
        final_status = "Pending"
        for attempt in range(3):  # Reduced from 10
            await asyncio.sleep(1 if attempt > 0 else 0)  # 1s wait between polls
            
            analysis_resp = await client.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers={"x-apikey": api_key, "Accept": "application/json"},
                timeout=10  # Reduced from 30
            )
            analysis_resp.raise_for_status()
            attributes = analysis_resp.json().get("data", {}).get("attributes", {})

            stats = attributes.get("stats", None)
            if stats:
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    final_status = "Malicious"
                elif suspicious > 0:
                    final_status = "Suspicious"
                else:
                    final_status = "Safe"
                break  # got final verdict
            
        url_cache[url] = final_status
        save_cache()
        return url, final_status

    except Exception as e:
        url_cache[url] = "Error"
        save_cache()
        logging.error(f"[VirusTotal] Error for {url}: {e}")
        return url, "Error"


async def check_urls_async(urls, use_cache: bool = True):
    valid_urls = [u for u in urls if u.startswith(('http://', 'https://'))]
    if not valid_urls:
        return {}
    async with httpx.AsyncClient() as client:
        tasks = [fetch_vt_status(client, url, use_cache=use_cache) for url in valid_urls]
        results = await asyncio.gather(*tasks)
    return dict(results)


async def check_url_virustotal_async(url: str, use_cache: bool = True):
    """Async version to check a single URL."""
    results = await check_urls_async([url], use_cache=use_cache)
    return results[url]


def check_url_virustotal(url: str, use_cache: bool = True):
    """Synchronous wrapper for a single URL using nest_asyncio."""
    try:
        loop = asyncio.get_running_loop()
        # Already in async context - return coroutine
        return loop.run_until_complete(check_urls_async([url], use_cache=use_cache))[url]
    except RuntimeError:
        # Not in async context - safe to use asyncio.run()
        return asyncio.run(check_urls_async([url], use_cache=use_cache))[url]
