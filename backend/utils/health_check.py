# backend/utils/health_check.py
"""
Comprehensive health check utilities
Validates system components and returns detailed status
"""
import os
import logging
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


def check_database_health() -> Dict:
    """Check database connectivity and status"""
    try:
        from backend.extensions import db
        from backend.models import ThreatLog
        
        # Test query
        count = ThreatLog.query.count()
        
        return {
            "status": "healthy",
            "records": count,
            "last_check": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "last_check": datetime.utcnow().isoformat()
        }


def check_api_keys() -> Dict:
    """Check if required API keys are configured"""
    keys_status = {}
    
    required_keys = [
        ("VIRUSTOTAL_API_KEY", "VirusTotal"),
        ("SAFE_BROWSING_API_KEY", "Google Safe Browsing"),
        ("GEMINI_API_KEY", "Gemini AI"),
    ]
    
    optional_keys = [
        ("PHISHTANK_API_KEY", "PhishTank"),
        ("ABUSEIPDB_API_KEY", "AbuseIPDB"),
        ("BREVO_API_KEY", "Brevo Email"),
    ]
    
    for key_name, service_name in required_keys:
        key_value = os.getenv(key_name)
        keys_status[service_name] = {
            "configured": bool(key_value and len(key_value) > 10),
            "required": True
        }
    
    for key_name, service_name in optional_keys:
        key_value = os.getenv(key_name)
        keys_status[service_name] = {
            "configured": bool(key_value and len(key_value) > 10),
            "required": False
        }
    
    # Check if all required keys are present
    all_required_present = all(
        v["configured"] for k, v in keys_status.items() if v["required"]
    )
    
    return {
        "status": "healthy" if all_required_present else "degraded",
        "services": keys_status,
        "missing_required": [
            k for k, v in keys_status.items() 
            if v["required"] and not v["configured"]
        ]
    }


def check_disk_space() -> Dict:
    """Check available disk space"""
    try:
        import shutil
        
        # Check workspace root
        total, used, free = shutil.disk_usage("/")
        
        free_gb = free // (1024 ** 3)
        total_gb = total // (1024 ** 3)
        used_percent = (used / total) * 100
        
        status = "healthy"
        if free_gb < 1:
            status = "critical"
        elif free_gb < 5:
            status = "warning"
        
        return {
            "status": status,
            "free_gb": free_gb,
            "total_gb": total_gb,
            "used_percent": round(used_percent, 2),
            "warning": "Low disk space" if free_gb < 5 else None
        }
    except Exception as e:
        logger.error(f"Disk space check failed: {e}")
        return {
            "status": "unknown",
            "error": str(e)
        }


def check_cache_health() -> Dict:
    """Check cache performance and status"""
    try:
        from backend.services.virustotal_service import performance_metrics, url_cache
        
        cache_size = len(url_cache)
        cache_hits = performance_metrics.get("cache_hits", 0)
        cache_misses = performance_metrics.get("cache_misses", 0)
        
        total_requests = cache_hits + cache_misses
        hit_rate = (cache_hits / total_requests * 100) if total_requests > 0 else 0
        
        status = "healthy"
        if hit_rate < 30 and total_requests > 100:
            status = "degraded"
        
        return {
            "status": status,
            "hit_rate_percent": round(hit_rate, 2),
            "cache_size": cache_size,
            "total_requests": total_requests,
            "recommendation": "Consider increasing cache size" if hit_rate < 50 else None
        }
    except Exception as e:
        logger.error(f"Cache health check failed: {e}")
        return {
            "status": "unknown",
            "error": str(e)
        }


def get_system_health() -> Dict:
    """Comprehensive system health check"""
    components = {
        "database": check_database_health(),
        "api_keys": check_api_keys(),
        "disk_space": check_disk_space(),
        "cache": check_cache_health()
    }
    
    # Determine overall status
    statuses = [comp["status"] for comp in components.values()]
    
    if "critical" in statuses or "unhealthy" in statuses:
        overall_status = "unhealthy"
    elif "degraded" in statuses or "warning" in statuses:
        overall_status = "degraded"
    else:
        overall_status = "healthy"
    
    # Collect warnings
    warnings = []
    for component_name, component_data in components.items():
        if component_data.get("warning"):
            warnings.append(f"{component_name}: {component_data['warning']}")
        if component_data.get("error"):
            warnings.append(f"{component_name}: {component_data['error']}")
        if component_data.get("missing_required"):
            for missing in component_data["missing_required"]:
                warnings.append(f"Missing required API key: {missing}")
    
    return {
        "status": overall_status,
        "timestamp": datetime.utcnow().isoformat(),
        "components": components,
        "warnings": warnings,
        "version": "1.0.0"
    }
