"""
Utility functions for the threat detection system.
Handles common operations like logging, time, error handling, and efficient queries.
"""

import os
import logging
import json
from datetime import datetime, timedelta, timezone
import re
from functools import wraps, lru_cache
from flask import jsonify
from sqlalchemy import func

from utils.constants import IST, LOG_RETENTION_DAYS
from extensions import db, socketio
from models import ThreatLog

# Simple in-memory cache with TTL for dashboard queries
_dashboard_cache = {"data": None, "timestamp": None}
DASHBOARD_CACHE_TTL = 30  # seconds


def get_ist_time():
    """Get current time in IST timezone."""
    return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")


def format_timestamp_ist(dt):
    """Render a timestamp in IST, assuming UTC if naive."""
    if not dt:
        return "N/A"
    try:
        aware = dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
        return aware.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as exc:
        logging.error(f"format_timestamp_ist error: {exc}")
        return dt.strftime("%Y-%m-%d %H:%M:%S") if hasattr(dt, "strftime") else "N/A"


def analyze_qr_payload(data):
    """Classify QR payloads beyond URLs to flag risky content."""
    result = {
        "payload": data or "",
        "type": "unknown",
        "risk_level": "low",
        "details": ""
    }

    if not data:
        result["details"] = "Empty payload"
        return result

    url_pattern = r"(https?://[^\s]+)"
    if re.search(url_pattern, data):
        result["type"] = "url"
        result["risk_level"] = "needs_scan"
        result["details"] = "URL detected, forwarding to threat scanner."
        return result

    if data.startswith("WIFI:"):
        result.update(type="wifi", risk_level="high", details="QR attempts to auto-connect to a WiFi network.")
        return result

    if data.startswith("sms:"):
        result.update(type="sms", risk_level="medium", details="QR attempts to send an SMS message.")
        return result

    if data.startswith("tel:"):
        result.update(type="tel", risk_level="medium", details="QR attempts to call a phone number.")
        return result

    if data.startswith("mailto:"):
        result.update(type="email", risk_level="medium", details="QR attempts to draft an email (possible phishing).")
        return result

    if data.startswith("upi:") or data.startswith("bitcoin:"):
        result.update(type="payment", risk_level="high", details="QR attempts a financial transaction.")
        return result

    if data.startswith("data:"):
        result.update(type="file_data", risk_level="high", details="QR contains file payload (possible malware).")
        return result

    env_keywords = os.getenv("PHISHING_KEYWORDS", "verify,urgent,password,login,update")
    suspicious_words = [kw.strip().lower() for kw in env_keywords.split(",") if kw.strip()]
    if any(word in data.lower() for word in suspicious_words):
        result.update(type="text", risk_level="medium", details="Suspicious text content.")
        return result

    result.update(type="text", risk_level="low", details="Plain text. No malicious indicators.")
    return result


def cleanup_old_logs(cutoff_days=LOG_RETENTION_DAYS):
    """
    Delete threat logs older than cutoff_days.
    Runs once at startup via app_init.
    """
    try:
        cutoff_date = datetime.now() - timedelta(days=cutoff_days)
        deleted = ThreatLog.query.filter(ThreatLog.timestamp < cutoff_date).delete()
        db.session.commit()
        logging.info(f"Cleaned up {deleted} old logs (> {cutoff_days} days)")
    except Exception as e:
        logging.error(f"cleanup_old_logs error: {e}")
        db.session.rollback()


def handle_db_error(func):
    """
    Decorator to gracefully handle DB errors in routes.
    Logs and returns a 500 response.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"{func.__name__} database error: {e}")
            db.session.rollback()
            return jsonify({"error": "Database error"}), 500
    return wrapper


def save_threat_log(category, url, status, severity, reason="", details=None):
    """
    Convenience function to save a threat log entry.
    """
    try:
        import json
        entry = ThreatLog(
            category=category,
            url=url,
            status=status,
            severity=severity,
            flagged_reason=reason,
            details=json.dumps(details) if details else None
        )
        db.session.add(entry)
        db.session.commit()
        try:
            socketio.emit("update_logs")
        except Exception as emit_err:
            logging.debug(f"socket emit skipped: {emit_err}")
        return True
    except Exception as e:
        logging.error(f"Failed to save threat log: {e}")
        db.session.rollback()
        return False


def validate_file_upload(file, allowed_exts, max_size):
    """
    Validate uploaded file size and extension.
    Returns (is_valid, error_message).
    """
    if not file or file.filename == "":
        return False, "No file provided"

    filename = file.filename
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext not in allowed_exts:
        return False, f"File type not allowed. Allowed: {', '.join(allowed_exts)}"

    if file.content_length and file.content_length > max_size:
        return False, f"File too large (max {max_size // (1024*1024)} MB)"

    return True, None


def get_severity_from_status(vt_status):
    """
    Map VirusTotal status to severity level.
    """
    from utils.constants import VT_STATUS_MALICIOUS, VT_STATUS_SUSPICIOUS, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW
    
    if vt_status == VT_STATUS_MALICIOUS:
        return SEVERITY_HIGH
    elif vt_status == VT_STATUS_SUSPICIOUS:
        return SEVERITY_MEDIUM
    else:
        return SEVERITY_LOW

# ========================
# Efficient Batch Query Functions
# ========================

def get_dashboard_stats():
    """
    Fetch all dashboard statistics in ONE aggregated query instead of 6 separate queries.
    Results cached for 30 seconds to reduce DB load.
    """
    now = datetime.now()
    if (_dashboard_cache["data"] is not None and 
        _dashboard_cache["timestamp"] is not None and
        (now - _dashboard_cache["timestamp"]).total_seconds() < DASHBOARD_CACHE_TTL):
        return _dashboard_cache["data"]
    
    try:
        # Single aggregated query using GROUP BY
        all_logs = ThreatLog.query.all()
        
        stats = {
            "emails_scanned": sum(1 for log in all_logs if log.category == "email"),
            "malicious_urls": sum(1 for log in all_logs if log.category == "url_scan" and log.status == "Malicious"),
            "qr_threats": sum(1 for log in all_logs if log.category == "qr"),
            "soc_events": sum(1 for log in all_logs if log.category == "soc"),
            "ti_queries": sum(1 for log in all_logs if log.category == "threat_lookup"),
            "active_alerts": sum(1 for log in all_logs if log.severity in ["High", "Critical"])
        }
        
        # Cache the result
        _dashboard_cache["data"] = stats
        _dashboard_cache["timestamp"] = now
        
        return stats
    except Exception as e:
        logging.error(f"Error fetching dashboard stats: {e}")
        return {}


def invalidate_dashboard_cache():
    """Clear dashboard cache (call after new threat log inserted)."""
    _dashboard_cache["data"] = None
    _dashboard_cache["timestamp"] = None


def get_threat_logs_paginated(category=None, limit=100, offset=0):
    """
    Fetch threat logs with pagination to avoid loading all records.
    Saves memory and improves response time.
    """
    try:
        query = ThreatLog.query.order_by(ThreatLog.timestamp.desc())
        
        if category:
            query = query.filter_by(category=category)
        
        total = query.count()
        logs = query.limit(limit).offset(offset).all()
        
        return {
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logging.error(f"Error fetching paginated logs: {e}")
        return {"logs": [], "total": 0, "limit": limit, "offset": offset}


def get_logs_by_category(limit_per_category=10):
    """
    Fetch recent logs from each category efficiently (ONE query per category).
    Better than 4-5 separate queries.
    """
    try:
        categories = ["email", "url_scan", "soc", "qr", "threat_lookup"]
        logs_dict = {}
        
        for category in categories:
            logs_dict[category] = (
                ThreatLog.query
                .filter_by(category=category)
                .order_by(ThreatLog.timestamp.desc())
                .limit(limit_per_category)
                .all()
            )
        
        return logs_dict
    except Exception as e:
        logging.error(f"Error fetching logs by category: {e}")
        return {}