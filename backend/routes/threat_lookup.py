"""
Threat Lookup Routes - URL/IP threat intelligence lookups
CRITICAL FIX: LLM trust boundary enforced - Gemini explains, never decides
ENHANCEMENTS: URL monitoring, auto-closure, and threat correlation
"""
import json
import logging
from flask import Blueprint, render_template, request, jsonify
from backend.extensions import limiter, db
from backend.models import ThreatLog
from backend.services.threat_lookup_service import unified_check_url
from backend.middleware.security import validate_url_input, validate_json_input
from backend.services.url_monitoring_service import (
    add_url_to_monitor, rescan_monitored_url, scan_all_monitored_urls,
    get_monitoring_statistics, get_url_monitor
)
from backend.alerts.email_alerts_service import send_brevo_email_async
from backend.alerts.sound_alerts import play_alert_sound
from backend.utils.helpers import get_client_ip
from urllib.parse import urlparse
from datetime import datetime, timedelta

threat_lookup_bp = Blueprint("threat_lookup", __name__)

@threat_lookup_bp.route("/threat_lookup")
def threat_lookup():
    return render_template("threat_lookup.html")


@threat_lookup_bp.route("/api/threat_lookup", methods=["POST"])
@limiter.limit("5 per second")
@validate_json_input(max_size=10240)  # 10KB max
def threat_lookup_api():
    """
    Threat intelligence lookup API
    Returns threat intel data without logging
    """
    data = request.get_json() or {}
    url = data.get("query") or data.get("url") or ""
    force_refresh = bool(data.get("force_refresh", False))
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Validate URL input
    is_valid, error_msg = validate_url_input(url)
    if not is_valid:
        return jsonify({"error": error_msg}), 400
    
    try:
        # CRITICAL: unified_check_url enforces LLM trust boundary
        # - Deterministic checks decide status
        # - Gemini only provides explanation/confidence
        ti = unified_check_url(
            url,
            force_refresh=force_refresh,
            include_ip_enrichment=False
        )
        
        return jsonify({
            "status": ti.get("final_status", "Unknown"),
            "severity": ti.get("severity", "Unknown"),
            "detected_by": ti.get("detected_by"),
            "sources": ti.get("sources", {}),
            "cache": ti.get("cache", {}),
            "ai": ti.get("ai", {}),
        })
    except Exception as e:
        logging.error(f"Error during threat lookup: {e}")
        return jsonify({"error": "Error during threat lookup"}), 500


@threat_lookup_bp.route("/check-url", methods=["POST"])
@limiter.limit("5 per second")
@validate_json_input(max_size=10240)  # 10KB max
def check_url():
    """
    URL scanning endpoint with logging and alerting
    CRITICAL FIX: Non-blocking alerts via threading
    """
    data = request.get_json() or {}
    url = data.get("url")
    force_refresh = bool(data.get("force_refresh", False))
    include_ip_enrichment = bool(
        data.get("include_ip_enrichment") or 
        data.get("include_ip") or 
        False
    )
    
    if not url:
        return jsonify({"error": "URL is required"}), 400
    
    # Validate URL input
    is_valid, error_msg = validate_url_input(url)
    if not is_valid:
        return jsonify({"error": error_msg}), 400

    try:
        client_ip = get_client_ip(request)

        # CRITICAL: Deterministic verdict, Gemini only explains
        ti = unified_check_url(
            url,
            force_refresh=force_refresh,
            include_ip_enrichment=include_ip_enrichment,
        )

        # Defensive fix: if recent ThreatLog shows a deterministic Phishing/Malicious
        # result for the same domain (within the last 10 minutes), prefer that
        # verdict. This avoids race conditions where an intermittent external
        # API timeout returns 'Safe' after a prior PhishTank detection.
        try:
            parsed = urlparse(url)
            host = parsed.netloc or url
            window = datetime.utcnow() - timedelta(minutes=10)
            recent = (
                ThreatLog.query
                .filter(ThreatLog.timestamp >= window)
                .filter(ThreatLog.url.contains(host))
                .order_by(ThreatLog.timestamp.desc())
                .limit(10)
                .all()
            )
            for r in recent:
                if (r.status or "").lower() in ("phishing", "malicious"):
                    # Promote current TI to match earlier deterministic detection
                    ti["final_status"] = r.status
                    ti["severity"] = r.severity or ti.get("severity")
                    ti["detected_by"] = r.flagged_reason or ti.get("detected_by")
                    break
        except Exception:
            # If anything goes wrong here, don't block the response
            pass

        # Save to ThreatLog
        entry = ThreatLog(
            category="url_scan",
            url=url,
            flagged_reason=f"{ti.get('detected_by') or 'TI Pipeline'} ({ti.get('final_status')})",
            severity=ti.get("severity", "Unknown"),
            status=ti.get("final_status", "Unknown"),
            details=json.dumps({
                "sources": ti.get("sources", {}),
                "ai": ti.get("ai", {}),
                "cache": ti.get("cache", {})
            })
        )
        db.session.add(entry)
        try:
            db.session.commit()
            
            # AUTO-ENROLL in monitoring if threat detected
            if ti.get("final_status") in ("Malicious", "Phishing", "Suspicious"):
                try:
                    monitor_result = add_url_to_monitor(
                        url=url,
                        status=ti.get("final_status"),
                        severity=ti.get("severity"),
                        threat_log_id=entry.id
                    )
                    if monitor_result.get("success"):
                        logging.info(f"Auto-enrolled {url} in monitoring queue")
                except Exception as monitor_err:
                    logging.error(f"Monitoring enrollment error: {monitor_err}")
        
        except Exception as db_err:
            logging.error(f"Database commit error: {db_err}")
            db.session.rollback()

        # CRITICAL FIX: Non-blocking alerts
        # Alert runs in background thread, doesn't block response
        if ti.get("final_status") in ("Malicious", "Phishing"):
            send_brevo_email_async(
                client_ip,
                url,
                ti.get("final_status"),
                ti.get("severity")
            )
            play_alert_sound()

        return jsonify({
            "status": ti.get("final_status", "Unknown"),
            "severity": ti.get("severity", "Unknown"),
            "detected_by": ti.get("detected_by"),
            "sources": ti.get("sources", {}),
            "cache": ti.get("cache", {}),
            "ai": ti.get("ai", {}),
        })

    except Exception as e:
        logging.error(f"Error during URL check: {e}")
        return jsonify({"error": "Error checking URL"}), 500


@threat_lookup_bp.route("/api/pipeline_metrics", methods=["GET"])
def pipeline_metrics():
    """
    Return real-time pipeline performance metrics and threat intelligence.
    Useful for monitoring dashboards and SOC operations.
    """
    try:
        from backend.services.threat_lookup_service import get_pipeline_metrics
        metrics = get_pipeline_metrics()
        return jsonify({
            "status": "success",
            "metrics": metrics,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logging.error(f"Error fetching pipeline metrics: {e}")
        return jsonify({"error": "Failed to fetch metrics"}), 500


@threat_lookup_bp.route("/api/recent_threats", methods=["GET"])
def recent_threats():
    """
    Return recent threat log entries for syncing with clients (e.g. browser extension).
    Query params:
      - limit: number of entries to return (default 20)
    """
    try:
        limit = int(request.args.get("limit", 20))
        logs = (
            ThreatLog.query
            .filter_by(category="url_scan")
            .order_by(ThreatLog.timestamp.desc())
            .limit(limit)
            .all()
        )
        out = []
        for l in logs:
            try:
                details = json.loads(l.details) if l.details else None
            except Exception:
                details = None
            out.append({
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "url": l.url,
                "status": l.status,
                "severity": l.severity,
                "flagged_reason": l.flagged_reason,
                "details": details,
            })
        return jsonify({"results": out})
    except Exception as e:
        logging.error(f"Error fetching recent threats: {e}")
        return jsonify({"error": "Error fetching recent threats"}), 500
