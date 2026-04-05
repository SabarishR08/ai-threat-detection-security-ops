"""
Unified Threat Lookup Service
Handles URL, domain, and IP address reputation lookups across multiple sources.

ENHANCEMENTS:
- Early detection circuit breaker (stop on first threat)
- Threat correlation and trending detection
- Performance metrics and monitoring
- Smart caching with TTL validation
- Batch processing optimization
"""
import asyncio
import logging
from urllib.parse import urlparse
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional

from backend.services import virustotal_service as vt_service
from backend.services.google_safebrowsing_service import check_url_safebrowsing
from backend.services.phishtank_service import check_url_phishtank
from backend.services.abuseipdb_service import check_ip_fresh, check_ip
from backend.services.rdap_service import rdap_lookup
from backend.services.virustotal_service import url_cache, check_url_virustotal_async
from backend.services.gemini_service import analyze_threat_fusion
from backend.services.whitelist_service import get_whitelist_service

VERDICT_ORDER = ["Malicious", "Phishing", "Suspicious", "Safe", "Unknown"]

# Threat correlation tracking (in-memory, production should use Redis)
threat_correlation = {
    "domain_threats": defaultdict(list),  # Track threats per domain
    "recent_scans": [],  # Recent scan history
    "trending_threats": defaultdict(int),  # Threat frequency counter
}

# Performance monitoring
pipeline_metrics = {
    "total_scans": 0,
    "threats_detected": 0,
    "avg_scan_time": 0.0,
    "source_performance": {
        "virustotal": {"calls": 0, "hits": 0, "avg_time": 0.0},
        "phishtank": {"calls": 0, "hits": 0, "avg_time": 0.0},
        "google_safebrowsing": {"calls": 0, "hits": 0, "avg_time": 0.0},
    }
}


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


def track_threat_correlation(url: str, status: str, detected_by: str) -> Dict:
    """
    Track threat patterns and correlations for trending detection.
    Returns correlation insights if patterns detected.
    """
    domain = extract_domain(url)
    insights = {"correlated": False, "trend": "normal", "previous_detections": 0}
    
    if status in ["Malicious", "Phishing", "Suspicious"]:
        # Track by domain
        threat_correlation["domain_threats"][domain].append({
            "url": url,
            "status": status,
            "detected_by": detected_by,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Track trending threats
        threat_correlation["trending_threats"][domain] += 1
        
        # Check for patterns (multiple threats from same domain in 24h)
        recent_threats = [
            t for t in threat_correlation["domain_threats"][domain]
            if datetime.fromisoformat(t["timestamp"]) > datetime.utcnow() - timedelta(hours=24)
        ]
        
        if len(recent_threats) > 1:
            insights["correlated"] = True
            insights["previous_detections"] = len(recent_threats) - 1
            insights["trend"] = "escalating" if len(recent_threats) >= 3 else "recurring"
            logging.warning(f"Correlated threat detected: {domain} has {len(recent_threats)} threats in 24h")
    
    # Cleanup old data (keep last 7 days)
    cutoff = datetime.utcnow() - timedelta(days=7)
    for dom in list(threat_correlation["domain_threats"].keys()):
        threat_correlation["domain_threats"][dom] = [
            t for t in threat_correlation["domain_threats"][dom]
            if datetime.fromisoformat(t["timestamp"]) > cutoff
        ]
        if not threat_correlation["domain_threats"][dom]:
            del threat_correlation["domain_threats"][dom]
    
    return insights


def check_recent_scan(url: str) -> Optional[Dict]:
    """
    Check if URL was recently scanned (within last 5 minutes).
    Returns cached result if found, None otherwise.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=5)
    for scan in reversed(threat_correlation["recent_scans"]):
        if scan["url"] == url and datetime.fromisoformat(scan["timestamp"]) > cutoff:
            logging.info(f"Recent scan found for {url}, reusing result")
            return scan["result"]
    return None


def cache_scan_result(url: str, result: Dict):
    """
    Cache scan result in recent scans (limit to 1000 entries).
    """
    threat_correlation["recent_scans"].append({
        "url": url,
        "result": result,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    # Keep only recent 1000 scans
    if len(threat_correlation["recent_scans"]) > 1000:
        threat_correlation["recent_scans"] = threat_correlation["recent_scans"][-1000:]


def _rule_based_url_checks(url: str) -> dict:
    """
    Lightweight deterministic rule-based checks to catch obvious phishing patterns.
    These rules always run locally and can elevate risk when deterministic sources are
    unavailable or inconclusive. They are fast and do not rely on external APIs.

    Returns a dict: { 'flag': bool, 'status': 'Phishing'|'Suspicious'|'Malicious'|'Safe', 'reason': str }
    """
    host = extract_domain(url).lower()
    rule = {"flag": False, "status": "Safe", "reason": ""}

    # Quick checks
    suspicious_tlds = {"click", "xyz", "top", "site", "online", "icu", "pw", "club"}
    digits_count = sum(c.isdigit() for c in host)
    subparts = host.split('.')
    subdomain_count = max(0, len(subparts) - 2)
    has_ip = all(part.isdigit() for part in host.split(':')[0].split('.'))
    contains_hyphens = host.count('-')

    # Rule: IP-based host (numeric) -> Malicious
    if has_ip:
        rule.update({"flag": True, "status": "Malicious", "reason": "Host is numeric IP address"})
        return rule

    # Rule: suspicious TLDs
    tld = subparts[-1] if len(subparts) > 0 else ""
    if tld in suspicious_tlds:
        # If also contains digits, escalate to Phishing
        if digits_count >= 3:
            rule.update({"flag": True, "status": "Phishing", "reason": f"Suspicious TLD .{tld} with numeric tokens"})
            return rule
        rule.update({"flag": True, "status": "Suspicious", "reason": f"Suspicious TLD .{tld}"})

    # Rule: many digits in domain (likely autogenerated)
    if digits_count >= 5:
        rule.update({"flag": True, "status": "Suspicious", "reason": "High numeric content in domain"})

    # Rule: unusually long host
    if len(host) > 40:
        rule.update({"flag": True, "status": "Suspicious", "reason": "Unusually long host name"})

    # Rule: many subdomains (deeplink phishing) or many hyphens
    if subdomain_count >= 4 or contains_hyphens >= 3:
        rule.update({"flag": True, "status": "Suspicious", "reason": "Complex subdomain structure / many hyphens"})

    return rule


async def unified_check_url_async(url: str, force_refresh: bool = False, include_ip_enrichment: bool = False) -> dict:
    """
    🔍 UNIFIED THREAT INTELLIGENCE PIPELINE (SOC-Accurate)
    
    ARCHITECTURE:
    ┌─────────────────────────────────────────────────────────────┐
    │ INPUT (URL / IP / DOMAIN)                                   │
    └──────────────────┬──────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
    PhishTank    VirusTotal    Google Safe Browsing
        │              │              │
        └──────────────┼──────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Optional Enrichment  │ (if include_ip_enrichment=True)
            ├──────────────────────┤
            │ • AbuseIPDB (IP rep) │
            │ • RDAP (ASN/owner)   │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  DETERMINISTIC       │
            │  VERDICT DECISION    │ ← PhishTank/VT/GSB decides
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  Gemini LLM          │
            │  (EXPLANATION ONLY)  │ ← Never overrides verdict
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │   FINAL RESULT       │
            │ • Status (Safe/Mal)  │
            │ • Severity (Low/High)│
            │ • AI Explanation     │
            │ • Sources Details    │
            └──────────────────────┘
    
    CRITICAL RULES:
    ⚠️  1. Gemini EXPLAINS, never DECIDES
    ⚠️  2. Deterministic sources (VT/PT/GSB) make the verdict
    ⚠️  3. If Gemini fails → verdict unchanged (safe degradation)
    ⚠️  4. Parallel enrichment for speed (GSB + PhishTank concurrent)
    ⚠️  5. Whitelisted URLs bypass all checks
    
    PARAMETERS:
    - url: Target URL/domain/IP to analyze
    - force_refresh: Skip cache, force fresh lookups (default: False)
    - include_ip_enrichment: Add AbuseIPDB + RDAP data (default: False)
    
    RETURNS:
    {
        "final_status": "Malicious|Phishing|Suspicious|Safe|Unknown",
        "severity": "Critical|High|Medium|Low|Unknown",
        "detected_by": "PhishTank|VirusTotal|Google Safe Browsing|All sources",
        "sources": {
            "virustotal": {...},
            "phishtank": {...},
            "google_safebrowsing": {...},
            "abuseipdb": {...} or None,
            "rdap": {...} or None
        },
        "ai": {
            "reasoning": "LLM explanation",
            "confidence": 0.0-1.0,
            "recommendation": "..."
        },
        "cache": {"virustotal": true/false}
    }
    """

    result = {
        "final_status": "Unknown",
        "severity": "Unknown",
        "detected_by": None,
        "sources": {},
        "cache": {"virustotal": False},
        "whitelisted": False
    }

    # ========================================================================
    # STEP 0: PERFORMANCE TRACKING
    # ========================================================================
    scan_start = datetime.utcnow()
    pipeline_metrics["total_scans"] += 1
    
    # ========================================================================
    # STEP 0.5: CHECK RECENT SCANS (5-minute deduplication)
    # ========================================================================
    recent = check_recent_scan(url)
    if recent and not force_refresh:
        logging.info(f"Returning recent scan result for {url}")
        return recent
    
    # ========================================================================
    # STEP 1: WHITELIST CHECK (Fast path - bypass all threat checks)
    # ========================================================================
    whitelist_service = get_whitelist_service()
    if whitelist_service.is_whitelisted_url(url):
        result["final_status"] = "Safe"
        result["severity"] = "Low"
        result["detected_by"] = "Whitelist"
        result["whitelisted"] = True
        result["scan_time_ms"] = int((datetime.utcnow() - scan_start).total_seconds() * 1000)
        logging.info(f"URL whitelisted: {url}")
        cache_scan_result(url, result)
        return result

    # ========================================================================
    # STEP 2: DETERMINISTIC THREAT CHECKS (Parallel execution for speed)
    # ========================================================================
    
    # 2a) VirusTotal (cache-aware for performance)
    vt_cache_hit = (not force_refresh and url in url_cache)
    vt_status = await check_url_virustotal_async(url, use_cache=not force_refresh)
    result["cache"]["virustotal"] = vt_cache_hit
    result["sources"]["virustotal"] = {"status": vt_status, "cache": vt_cache_hit}

    # Track deterministic verdict (used later for final decision)
    source_final = None
    source_detected_by = None

    # 2b) Google Safe Browsing + PhishTank (parallel for low latency)
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

    # PARALLEL EXECUTION: Run GSB + PhishTank concurrently
    gsb, pt = await asyncio.gather(safe_gsb(), safe_pt())
    result["sources"]["google_safebrowsing"] = gsb
    result["sources"]["phishtank"] = pt

    # ========================================================================
    # STEP 2.5: EARLY DETECTION CIRCUIT BREAKER (Performance Optimization)
    # ========================================================================
    # If PhishTank detects verified phishing, STOP immediately and return
    # This saves API calls and reduces response time by ~2-3 seconds
    pt_status = str(pt.get("status", "")).lower()
    if pt_status == "phishing" and pt.get("verified", False):
        source_final = "Phishing"
        source_detected_by = "PhishTank (Early Detection)"
        result["final_status"] = source_final
        result["severity"] = "High"
        result["detected_by"] = source_detected_by
        result["early_detection"] = True
        result["scan_time_ms"] = int((datetime.utcnow() - scan_start).total_seconds() * 1000)
        
        # Track correlation
        correlation = track_threat_correlation(url, source_final, source_detected_by)
        result["threat_correlation"] = correlation
        
        pipeline_metrics["threats_detected"] += 1
        logging.warning(f"EARLY DETECTION: {url} flagged as Phishing by PhishTank")
        cache_scan_result(url, result)
        return result

    # ========================================================================
    # STEP 3: DETERMINISTIC VERDICT AGGREGATION (Priority order)
    # ========================================================================
    # Priority: PhishTank → VirusTotal → Google Safe Browsing
    # First malicious/phishing hit wins (short-circuit for performance)
    
    # 3a) PhishTank (highest priority for phishing)
    if source_final is None and pt_status in ("phishing", "suspicious"):
        source_final = "Phishing" if pt_status == "phishing" else "Suspicious"
        source_detected_by = "PhishTank"

    # 3b) VirusTotal (multi-engine consensus)
    if source_final is None and str(vt_status).lower() in ("malicious", "suspicious"):
        source_final = "Malicious" if str(vt_status).lower() == "malicious" else "Suspicious"
        source_detected_by = "VirusTotal"

    # 3c) Google Safe Browsing (Google's threat intelligence)
    gsb_status = str(gsb.get("status", "")).upper()
    if source_final is None and ("MALWARE" in gsb_status or "SOCIAL_ENGINEERING" in gsb_status or "UNWANTED" in gsb_status):
        source_final = "Malicious" if "MALWARE" in gsb_status else "Phishing"
        source_detected_by = "Google Safe Browsing"

    # ========================================================================
    # STEP 3.5: RULE-BASED DETERMINISTIC CHECKS (Local, fast heuristics)
    # ========================================================================
    # Run local rule engine to catch obvious phishing patterns (suspicious TLDs,
    # numeric host parts, IP-based hosts, excessive subdomains). Rules are
    # deterministic and can set the verdict if no higher-priority source matched.
    rule_result = _rule_based_url_checks(url)
    result["sources"]["rules"] = rule_result

    if source_final is None and rule_result.get("flag"):
        # If rules flagged, use that verdict (Phishing/Malicious/Suspicious)
        source_final = rule_result.get("status", "Suspicious")
        source_detected_by = "RuleEngine"

    # ========================================================================
    # STEP 4: OPTIONAL IP/RDAP ENRICHMENT (Non-blocking, for context only)
    # ========================================================================
    host = extract_domain(url)
    if include_ip_enrichment:
        ip_info = None
        rdap_info = None
        
        # 4a) AbuseIPDB (IP reputation check)
        if host and host.replace(".", "").isdigit():
            try:
                ip_info = check_ip_fresh(host)
            except Exception as e:
                logging.error(f"AbuseIPDB lookup failed: {e}")
                ip_info = {"error": str(e)}
        
        # 4b) RDAP (ownership/ASN lookup)
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

    # ========================================================================
    # STEP 5: GEMINI LLM ANALYSIS (EXPLANATION ONLY - NOT DECISION)
    # ⚠️  CRITICAL: LLM TRUST BOUNDARY ENFORCED
    # ========================================================================
    # Rules:
    # 1. Gemini receives all source data for context
    # 2. Gemini provides explanation, confidence, recommendation
    # 3. Gemini's verdict is STORED but NOT USED for final decision
    # 4. If Gemini fails/times out → verdict unchanged (safe degradation)
    
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
        ai_result = await asyncio.wait_for(
            asyncio.to_thread(analyze_threat_fusion, fusion_payload),
            timeout=6
        )
    except asyncio.TimeoutError:
        ai_result = {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": "Gemini timeout - verdict unaffected",
            "severity_score": 0,
            "error": "timeout",
        }
    except Exception as e:
        ai_result = {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": f"Gemini error: {str(e)[:120]} - verdict unaffected",
            "severity_score": 0,
            "error": "gemini_error",
        }
    
    result["ai"] = ai_result

    # ========================================================================
    # STEP 6: FINAL VERDICT DECISION (Deterministic sources decide)
    # ⚠️  CRITICAL: This is where the trust boundary is enforced
    # ========================================================================
    # Decision logic:
    # 1. If ANY deterministic source flagged → Use that verdict
    # 2. If NO deterministic flags → Safe verdict
    # 3. Gemini's opinion is in result["ai"] but does NOT override
    #
    # Example scenarios:
    # - VT=Malicious, Gemini=Safe → Final=Malicious (VT wins)
    # - VT=Safe, Gemini=Malicious → Final=Safe (Gemini ignored)
    # - VT=Safe, PT=Safe, GSB=Safe → Final=Safe (all clean)
    
    if source_final:
        # Deterministic source found a threat → Use that verdict
        final = source_final
        detected_by = source_detected_by
        logging.info(f"Threat detected by {detected_by}: {url} → {final}")
    else:
        # No deterministic threat found → Safe verdict
        # Gemini can add context but cannot change this to "Malicious"
        final = "Safe"
        detected_by = "All sources (deterministic)"
        logging.info(f"URL verified safe: {url}")
    
    # NOTE: We store Gemini's opinion in result["ai"] for transparency
    # but it does NOT influence the final_status. This is the correct
    # trust boundary for LLM-augmented security systems.

    result["final_status"] = final
    result["severity"] = _severity_for_status(final)
    result["detected_by"] = detected_by
    
    # Add performance metrics
    scan_duration = (datetime.utcnow() - scan_start).total_seconds()
    result["scan_time_ms"] = int(scan_duration * 1000)
    pipeline_metrics["avg_scan_time"] = (
        (pipeline_metrics["avg_scan_time"] * (pipeline_metrics["total_scans"] - 1) + scan_duration)
        / pipeline_metrics["total_scans"]
    )
    
    # Track threat correlation
    if final in ["Malicious", "Phishing", "Suspicious"]:
        correlation = track_threat_correlation(url, final, detected_by)
        result["threat_correlation"] = correlation
        pipeline_metrics["threats_detected"] += 1
    
    # Cache the result
    cache_scan_result(url, result)
    
    logging.info(f"Threat scan completed for {url}: {final} (detected by {detected_by}) in {scan_duration:.2f}s")
    return result


def get_pipeline_metrics() -> Dict:
    """Return current pipeline performance metrics."""
    return {
        "pipeline": pipeline_metrics,
        "virustotal": vt_service.performance_metrics,
        "threat_correlation": {
            "tracked_domains": len(threat_correlation["domain_threats"]),
            "trending_threats": dict(threat_correlation["trending_threats"]),
            "recent_scans_cached": len(threat_correlation["recent_scans"])
        }
    }


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
