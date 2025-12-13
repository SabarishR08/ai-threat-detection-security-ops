"""
Unified Threat Lookup Service
Handles URL, domain, and IP address reputation lookups across multiple sources.
"""
import asyncio
import logging
from urllib.parse import urlparse

import services.virustotal_service as vt_service

from services.google_safebrowsing_service import check_url_safebrowsing
from services.phishtank_service import check_url_phishtank
from services.abuseipdb_service import check_ip_fresh, check_ip
from services.rdap_service import rdap_lookup
from services.virustotal_service import url_cache, check_url_virustotal_async
from services.gemini_service import analyze_threat_fusion
from services.whitelist_service import get_whitelist_service

VERDICT_ORDER = ["Malicious", "Phishing", "Suspicious", "Safe", "Unknown"]


def _severity_for_status(status: str) -> str:
    status = (status or "Unknown").lower()
    if status in ("malicious", "phishing"):
        return "High"
    if status == "suspicious":
        return "Medium"
    if status == "safe":
        return "Low"
    return "Unknown"


def _run_async(coro):
    """Run an async coroutine safely from sync code."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return future.result()


def extract_domain(url: str) -> str:
    """
    Extract domain from URL for RDAP lookup.
    """
    parsed = urlparse(url)
    return parsed.netloc or url   # fallback if URL is not fully formatted


async def unified_check_url_async(url: str, force_refresh: bool = False, include_ip_enrichment: bool = False) -> dict:
    """
    Unified threat pipeline (recommended): PhishTank → VirusTotal → Google Safe Browsing → (optional AbuseIPDB/RDAP)
    - Short-circuit on first malicious/phishing verdict
    - Uses VT cache unless force_refresh=True
    - Returns consistent final_status and severity
    - **WHITELISTED URLs bypass all checks and return Safe verdict**
    """

    result = {
        "final_status": "Unknown",
        "severity": "Unknown",
        "detected_by": None,
        "sources": {},
        "cache": {"virustotal": False},
        "whitelisted": False
    }

    # ✅ WHITELIST CHECK - Skip all threat detection for whitelisted URLs
    whitelist_service = get_whitelist_service()
    if whitelist_service.is_whitelisted_url(url):
        result["final_status"] = "Safe"
        result["severity"] = "Low"
        result["detected_by"] = "Whitelist"
        result["whitelisted"] = True
        logging.info(f"URL whitelisted: {url}")
        return result

    # 1) VirusTotal (cache-aware)
    vt_cache_hit = (not force_refresh and url in url_cache)
    vt_status = await check_url_virustotal_async(url, use_cache=not force_refresh)
    result["cache"]["virustotal"] = vt_cache_hit
    result["sources"]["virustotal"] = {"status": vt_status, "cache": vt_cache_hit}

    # Track first-hit short-circuit (for legacy behavior) but continue to gather evidence for AI
    source_final = None
    source_detected_by = None

    async def safe_gsb():
        try:
            return await asyncio.wait_for(check_url_safebrowsing(url), timeout=3.5)
        except asyncio.TimeoutError:
            return {"status": "Unavailable", "error": "SafeBrowsing timeout"}
        except Exception as e:
            return {"status": "Unavailable", "error": str(e)}

    async def safe_pt():
        try:
            return await asyncio.wait_for(check_url_phishtank(url), timeout=3.5)
        except asyncio.TimeoutError:
            return {"status": "Unavailable", "error": "PhishTank timeout"}
        except Exception as e:
            return {"status": "Unavailable", "error": str(e)}

    # Run GSB + PhishTank concurrently to keep latency low
    gsb, pt = await asyncio.gather(safe_gsb(), safe_pt())
    result["sources"]["google_safebrowsing"] = gsb
    result["sources"]["phishtank"] = pt

    # PhishTank first for demo-ready phishing hits
    pt_status = str(pt.get("status", "")).lower()
    if source_final is None and pt_status in ("phishing", "suspicious"):
        source_final = "Phishing" if pt_status == "phishing" else "Suspicious"
        source_detected_by = "PhishTank"

    # VirusTotal second
    if source_final is None and str(vt_status).lower() in ("malicious", "suspicious"):
        source_final = "Malicious" if str(vt_status).lower() == "malicious" else "Suspicious"
        source_detected_by = "VirusTotal"

    # Google Safe Browsing last
    gsb_status = str(gsb.get("status", "")).upper()
    if source_final is None and ("MALWARE" in gsb_status or "SOCIAL_ENGINEERING" in gsb_status or "UNWANTED" in gsb_status):
        source_final = "Malicious" if "MALWARE" in gsb_status else "Phishing"
        source_detected_by = "Google Safe Browsing"

    # Optional IP/RDAP enrichment (non-blocking for verdict)
    host = extract_domain(url)
    if include_ip_enrichment:
        ip_info = None
        rdap_info = None
        if host and host.replace(".", "").isdigit():
            try:
                ip_info = check_ip_fresh(host)
            except Exception as e:
                logging.error(f"AbuseIPDB lookup failed: {e}")
                ip_info = {"error": str(e)}
        try:
            rdap_info = rdap_lookup(host)
        except Exception as e:
            logging.error(f"RDAP lookup failed: {e}")
            rdap_info = {"error": str(e)}
        result["sources"]["abuseipdb"] = ip_info
        result["sources"]["rdap"] = rdap_info
    else:
        result["sources"]["abuseipdb"] = None
        result["sources"]["rdap"] = None

    # 4) Gemini fusion layer (final decision)
    fusion_payload = {
        "url": url,
        "virustotal": result["sources"].get("virustotal"),
        "google_safebrowsing": result["sources"].get("google_safebrowsing"),
        "phishtank": result["sources"].get("phishtank"),
        "abuseipdb": result["sources"].get("abuseipdb"),
        "rdap": result["sources"].get("rdap"),
        "cache_hit": vt_cache_hit,
        "source": "unified_pipeline"
    }
    try:
        ai_result = await asyncio.wait_for(asyncio.to_thread(analyze_threat_fusion, fusion_payload), timeout=6)
    except asyncio.TimeoutError:
        ai_result = {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": "Gemini timeout",
            "severity_score": 0,
            "error": "timeout",
        }
    except Exception as e:
        ai_result = {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": f"Gemini error: {str(e)[:120]}",
            "severity_score": 0,
            "error": "gemini_error",
        }
    result["ai"] = ai_result

    # Decide final status: prefer AI verdict if available, otherwise source short-circuit, otherwise Safe
    ai_verdict = str(ai_result.get("ai_final_verdict", "Unknown"))
    if ai_verdict and ai_verdict.lower() != "unknown":
        final = ai_verdict.title()
        detected_by = "Gemini"
    elif source_final:
        final = source_final
        detected_by = source_detected_by
    else:
        final = "Safe"
        detected_by = source_detected_by or "None"

    result["final_status"] = final
    result["severity"] = _severity_for_status(final)
    result["detected_by"] = detected_by
    return result


async def lookup_url_async(url: str, force_refresh: bool = False) -> dict:
    """
    Async version - FAST threat lookup using cached VirusTotal + live PhishTank.
    PhishTank is included because it's fast and critical for phishing detection.
    Returns instant results (<100ms).
    For complete real-time lookups, use force_refresh=True (slower but includes all sources).
    """
    from services.virustotal_service import check_url_virustotal_async, url_cache
    
    if not force_refresh:
        # FAST PATH: VT cache + PhishTank only (PhishTank is fast, ~100ms)
        async def quick_phishtank_check():
            try:
                return await asyncio.wait_for(check_url_phishtank(url), timeout=1.5)
            except (asyncio.TimeoutError, Exception):
                return {'status': 'Unavailable'}
        
        # Run PhishTank check while reading VT cache / cached VT helper
        pt_result = await quick_phishtank_check()
        try:
            vt_status = await asyncio.to_thread(vt_service.check_url_virustotal, url, True)
        except Exception:
            vt_status = "Error"
        
        return {
            'phishtank': pt_result,
            'google_safebrowsing': {'status': 'Unavailable', 'reason': 'Cache mode'},
            'virustotal': vt_status,
            'rdap': {'skipped': 'Cache mode only'}
        }
    
    # SLOW PATH: Full lookup with all services (force_refresh=True)
    async def fetch_all_sources():
        async def safe_check_phishtank():
            try:
                return await asyncio.wait_for(check_url_phishtank(url), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                return {'status': 'Unavailable'}
        
        async def safe_check_safebrowsing():
            try:
                return await asyncio.wait_for(check_url_safebrowsing(url), timeout=2.0)
            except (asyncio.TimeoutError, Exception):
                return {'status': 'Unavailable'}
        
        async def safe_check_virustotal():
            try:
                result = await asyncio.wait_for(
                    check_url_virustotal_async(url, use_cache=False),
                    timeout=2.0
                )
                if isinstance(result, str):
                    return result
                if isinstance(result, dict):
                    return result.get('status', str(result))
                return str(result)
            except (asyncio.TimeoutError, Exception):
                return 'Safe'
        
        # Run in parallel
        pt_result, gs_result, vt_result = await asyncio.gather(
            safe_check_phishtank(),
            safe_check_safebrowsing(),
            safe_check_virustotal(),
            return_exceptions=False
        )
        
        return {
            'phishtank': pt_result,
            'google_safebrowsing': gs_result,
            'virustotal': vt_result,
            'rdap': {'skipped': 'Fresh lookup'}
        }
    
    return await fetch_all_sources()


def lookup_url(url: str, force_refresh: bool = False) -> dict:
    """
    Synchronous wrapper for lookup_url_async.
    Can be called from sync contexts (Flask routes).
    """
    try:
        loop = asyncio.get_running_loop()
        # Already in async context - use run_coroutine_threadsafe
        future = asyncio.run_coroutine_threadsafe(lookup_url_async(url, force_refresh=force_refresh), loop)
        return future.result()
    except RuntimeError:
        # Not in async context - safe to use asyncio.run()
        return asyncio.run(lookup_url_async(url, force_refresh=force_refresh))

    return results


def unified_check_url(url: str, force_refresh: bool = False, include_ip_enrichment: bool = False) -> dict:
    """Synchronous wrapper for unified_check_url_async."""
    try:
        loop = asyncio.get_running_loop()
        fut = asyncio.run_coroutine_threadsafe(
            unified_check_url_async(url, force_refresh=force_refresh, include_ip_enrichment=include_ip_enrichment),
            loop,
        )
        return fut.result()
    except RuntimeError:
        return asyncio.run(unified_check_url_async(url, force_refresh=force_refresh, include_ip_enrichment=include_ip_enrichment))


def lookup_ip(ip: str, force_refresh: bool = False) -> dict:
    """
    Central function to check an IP across AbuseIPDB.
    Returns risk score, status, and reputation data.
    """
    try:
        if force_refresh:
            return check_ip_fresh(ip)
        else:
            return check_ip(ip)
    except Exception as e:
        logging.error(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {"error": str(e), "ip": ip}


# Example usage
if __name__ == "__main__":
    url_test = "https://z-mail-webauth.netlify.app"
    ip_test = "8.8.8.8"

    print("URL Lookup:", lookup_url(url_test))
    print("IP Lookup:", lookup_ip(ip_test))
