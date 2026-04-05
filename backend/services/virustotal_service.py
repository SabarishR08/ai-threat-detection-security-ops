import os
import json
import asyncio
import httpx
import logging
from datetime import datetime, timedelta
from urllib.parse import urlparse
from functools import lru_cache
from collections import OrderedDict
from dotenv import load_dotenv

# Load environment variables from project root
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '..', '.env'))
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
CACHE_FILE = r"cache/url_cache.json"

# Enhanced cache with TTL (Time-To-Live) for stale data management
# Use OrderedDict for LRU behavior when cache exceeds max size
MAX_CACHE_SIZE = 10000  # Limit memory usage
url_cache = OrderedDict()  # LRU cache for URLs
domain_cache = OrderedDict()  # LRU cache for domains
CACHE_TTL_SAFE = timedelta(hours=24)  # Safe URLs cache for 24 hours
CACHE_TTL_MALICIOUS = timedelta(hours=72)  # Malicious URLs cache for 72 hours
CACHE_TTL_UNKNOWN = timedelta(hours=6)  # Unknown results cache for 6 hours

# Bloom filter for fast negative lookups (reduce cache checks)
bloom_filter = set()  # Simple set-based bloom filter for known URLs
BLOOM_MAX_SIZE = 50000

# Connection pooling for persistent connections (reduces handshake overhead)
HTTP_CLIENT = None  # Global persistent HTTP client
HTTP_LIMITS = httpx.Limits(max_keepalive_connections=20, max_connections=100)
HTTP_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Performance metrics
performance_metrics = {
    "cache_hits": 0,
    "cache_misses": 0,
    "api_calls": 0,
    "avg_response_time": 0.0,
    "bloom_hits": 0,
    "cache_evictions": 0
}

# Load or initialize cache
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            cache_data = json.load(f)
            # Load into OrderedDict for LRU behavior
            url_cache_data = cache_data.get("urls", {})
            domain_cache_data = cache_data.get("domains", {})
            
            # Limit size on load to prevent memory issues
            if len(url_cache_data) > MAX_CACHE_SIZE:
                # Keep only most recent entries
                items = list(url_cache_data.items())[-MAX_CACHE_SIZE:]
                url_cache_data = dict(items)
            
            url_cache.update(url_cache_data)
            domain_cache.update(domain_cache_data)
            performance_metrics.update(cache_data.get("metrics", {}))
            
            # Rebuild bloom filter from cache keys
            bloom_filter.update(url_cache.keys())
            bloom_filter.update(domain_cache.keys())
            
    except Exception as e:
        logging.error(f"[VirusTotal] Failed to load cache: {e}")
        url_cache.clear()
        domain_cache.clear()


def get_http_client():
    """Get or create persistent HTTP client with connection pooling."""
    global HTTP_CLIENT
    if HTTP_CLIENT is None:
        HTTP_CLIENT = httpx.AsyncClient(
            limits=HTTP_LIMITS,
            timeout=HTTP_TIMEOUT,
            http2=True,  # Enable HTTP/2 for better performance
            follow_redirects=False
        )
    return HTTP_CLIENT


async def close_http_client():
    """Close the global HTTP client."""
    global HTTP_CLIENT
    if HTTP_CLIENT is not None:
        await HTTP_CLIENT.aclose()
        HTTP_CLIENT = None

# Async cache save queue (batch writes to reduce I/O)
_cache_save_pending = False
_cache_save_lock = asyncio.Lock()


async def save_cache_async():
    """Save cache asynchronously with batching (reduces I/O operations)."""
    global _cache_save_pending
    
    async with _cache_save_lock:
        if _cache_save_pending:
            return  # Already scheduled
        
        _cache_save_pending = True
        await asyncio.sleep(2)  # Batch multiple updates within 2 seconds
        
        try:
            os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
            
            # Evict old entries if cache is too large (LRU)
            if len(url_cache) > MAX_CACHE_SIZE:
                evict_count = len(url_cache) - MAX_CACHE_SIZE
                for _ in range(evict_count):
                    url_cache.popitem(last=False)  # Remove oldest
                performance_metrics["cache_evictions"] += evict_count
            
            if len(domain_cache) > MAX_CACHE_SIZE // 2:
                evict_count = len(domain_cache) - (MAX_CACHE_SIZE // 2)
                for _ in range(evict_count):
                    domain_cache.popitem(last=False)
            
            cache_data = {
                "urls": dict(url_cache),
                "domains": dict(domain_cache),
                "metrics": performance_metrics,
                "last_updated": datetime.utcnow().isoformat()
            }
            
            # Use temporary file + rename for atomic write
            temp_file = f"{CACHE_FILE}.tmp"
            with open(temp_file, "w") as f:
                json.dump(cache_data, f)
            os.replace(temp_file, CACHE_FILE)
            
        except Exception as e:
            logging.error(f"[VirusTotal] Failed to save cache: {e}")
        finally:
            _cache_save_pending = False


def save_cache():
    """Synchronous cache save (legacy compatibility)."""
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        cache_data = {
            "urls": dict(url_cache),
            "domains": dict(domain_cache),
            "metrics": performance_metrics,
            "last_updated": datetime.utcnow().isoformat()
        }
        with open(CACHE_FILE, "w") as f:
            json.dump(cache_data, f, indent=2)
    except Exception as e:
        logging.error(f"[VirusTotal] Failed to save cache: {e}")


def is_cache_valid(cache_entry: dict) -> bool:
    """Check if cache entry is still valid based on TTL."""
    if not isinstance(cache_entry, dict) or "timestamp" not in cache_entry:
        return False
    
    cached_time = datetime.fromisoformat(cache_entry["timestamp"])
    status = cache_entry.get("status", "Unknown").lower()
    
    # Different TTL based on status
    if status in ["malicious", "phishing"]:
        ttl = CACHE_TTL_MALICIOUS
    elif status == "safe":
        ttl = CACHE_TTL_SAFE
    else:
        ttl = CACHE_TTL_UNKNOWN
    
    return (datetime.utcnow() - cached_time) < ttl


@lru_cache(maxsize=1024)
def extract_domain(url: str) -> str:
    """Extract domain from URL for domain-level caching (cached for performance)."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or url
    except:
        return url


async def fetch_vt_status(client, url, use_cache: bool = True):
    """Fetch the final VirusTotal analysis status for a URL (OPTIMIZED with TTL & Bloom Filter).
    use_cache=True: Check cache with TTL validation (instant, no API calls)
    use_cache=False: Submit for analysis and poll (slower but fresh)
    """
    start_time = datetime.utcnow()
    env_key = os.getenv("VIRUSTOTAL_API_KEY")
    api_key = env_key if env_key is not None else VIRUSTOTAL_API_KEY
    domain = extract_domain(url)

    # Step 0: Bloom filter check (O(1) fast negative lookup)
    if use_cache and url not in bloom_filter:
        # URL definitely not in cache, skip cache check
        performance_metrics["bloom_hits"] += 1
        if not api_key:
            return url, "VT_API_MISSING"
        performance_metrics["cache_misses"] += 1
        # Continue to API call
    else:
        # Step 1: Check URL-level cache with TTL validation
        if url in url_cache and isinstance(url_cache[url], dict):
            if is_cache_valid(url_cache[url]):
                # Move to end for LRU (mark as recently used)
                url_cache.move_to_end(url)
                performance_metrics["cache_hits"] += 1
                logging.debug(f"[VirusTotal] Cache HIT for {url}")
                return url, url_cache[url]["status"]
            else:
                logging.debug(f"[VirusTotal] Cache EXPIRED for {url}")
                del url_cache[url]  # Remove stale entry
                bloom_filter.discard(url)
        
        # Step 2: Check domain-level cache (fallback for subdomains)
        if domain in domain_cache and isinstance(domain_cache[domain], dict):
            if is_cache_valid(domain_cache[domain]):
                domain_cache.move_to_end(domain)  # LRU update
                performance_metrics["cache_hits"] += 1
                logging.debug(f"[VirusTotal] Domain cache HIT for {domain}")
                # Use domain verdict for URL
                status = domain_cache[domain]["status"]
                url_cache[url] = {"status": status, "timestamp": datetime.utcnow().isoformat(), "source": "domain_cache"}
                bloom_filter.add(url)
                return url, status
    
    # Step 3: If use_cache=True, return Unknown rather than calling API
    if use_cache:
        if not api_key:
            return url, "VT_API_MISSING"
        performance_metrics["cache_misses"] += 1
        return url, "Unknown"  # Not in cache, but we're not forcing refresh

    # Step 4: Only submit/poll if use_cache=False (force fresh)
    if not api_key:
        return url, "VT_API_MISSING"
    
    performance_metrics["cache_misses"] += 1
    performance_metrics["api_calls"] += 1

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
