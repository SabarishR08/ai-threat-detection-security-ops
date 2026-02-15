"""
AbuseIPDB Service - IP Reputation Lookup
Provides IP abuse/threat scoring and reporting status.
"""
import os
import logging
import requests
from functools import lru_cache

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_TIMEOUT = 5.0
ABUSEIPDB_MAX_AGE_DAYS = 90  # Return results from last 90 days


@lru_cache(maxsize=256)
def check_ip_cached(ip: str) -> dict:
    """
    Check IP reputation on AbuseIPDB (with caching).
    Returns risk score (0-100) and abuse category info.
    """
    if not ABUSEIPDB_API_KEY:
        logging.warning("AbuseIPDB API key not configured")
        return {"error": "AbuseIPDB API key not configured"}
    
    try:
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': ABUSEIPDB_MAX_AGE_DAYS,
            'verbose': ''
        }
        
        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=ABUSEIPDB_TIMEOUT
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get('data'):
            abuse_data = data['data']
            risk_score = abuse_data.get('abuseConfidenceScore', 0)
            is_whitelisted = abuse_data.get('isWhitelisted', False)
            
            # Determine status based on risk score
            if is_whitelisted:
                status = "Safe"
            elif risk_score >= 75:
                status = "Malicious"
            elif risk_score >= 25:
                status = "Suspicious"
            else:
                status = "Safe"
            
            return {
                "ip": ip,
                "status": status,
                "risk_score": risk_score,
                "is_whitelisted": is_whitelisted,
                "total_reports": abuse_data.get('totalReports', 0),
                "last_reported_at": abuse_data.get('lastReportedAt', None),
                "usage_type": abuse_data.get('usageType', 'Unknown'),
                "isp": abuse_data.get('isp', 'Unknown'),
                "domain": abuse_data.get('domain', 'Unknown'),
                "country_code": abuse_data.get('countryCode', 'Unknown'),
                "categories": abuse_data.get('reports', [])
            }
        else:
            # IP not found in database (likely safe)
            return {
                "ip": ip,
                "status": "Safe",
                "risk_score": 0,
                "is_whitelisted": False,
                "total_reports": 0,
                "last_reported_at": None,
                "message": "IP not found in AbuseIPDB database"
            }
            
    except requests.Timeout:
        logging.warning(f"AbuseIPDB timeout for IP: {ip}")
        return {"error": "AbuseIPDB request timeout", "ip": ip}
    except requests.HTTPError as e:
        if e.response.status_code == 401:
            logging.error("AbuseIPDB API key invalid")
            return {"error": "Invalid AbuseIPDB API key"}
        elif e.response.status_code == 429:
            logging.warning("AbuseIPDB rate limit exceeded")
            return {"error": "AbuseIPDB rate limit exceeded", "ip": ip}
        else:
            logging.error(f"AbuseIPDB HTTP error for {ip}: {e}")
            return {"error": f"AbuseIPDB error: {e}", "ip": ip}
    except Exception as e:
        logging.error(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {"error": str(e), "ip": ip}


def check_ip(ip: str) -> dict:
    """
    Check IP reputation without forcing cache refresh.
    """
    return check_ip_cached(ip)


def check_ip_fresh(ip: str) -> dict:
    """
    Check IP reputation with cache bypass (fresh lookup).
    """
    # Clear cache for this IP and re-query
    check_ip_cached.cache_clear()
    return check_ip_cached(ip)
