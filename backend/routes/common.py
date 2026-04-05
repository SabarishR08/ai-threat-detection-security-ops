"""
Common Routes - Settings, logs, API endpoints
CRITICAL FIX: Hardcoded credentials moved to env, CSV uses BytesIO
"""
import os
import json
import csv
import logging
import requests
from io import BytesIO
from datetime import timedelta
from flask import Blueprint, render_template, request, jsonify, send_file
from sqlalchemy import func
from backend.extensions import limiter, db
from backend.models import ThreatLog
from backend.utils.settings_service import (
    get_settings,
    update_settings,
    mark_vt_available,
)

common_bp = Blueprint("common", __name__)

@common_bp.route("/settings")
def settings():
    current_settings = get_settings()
    return render_template(
        "settings.html",
        settings=current_settings,
    )


@common_bp.route("/logs")
def logs():
    logs_tabs = ThreatLog.query.filter_by(category="tabs").order_by(ThreatLog.timestamp.desc()).all()
    logs_url = ThreatLog.query.filter_by(category="url_scan").order_by(ThreatLog.timestamp.desc()).all()
    logs_email = ThreatLog.query.filter_by(category="email").order_by(ThreatLog.timestamp.desc()).all()
    logs_soc = ThreatLog.query.filter_by(category="soc").order_by(ThreatLog.timestamp.desc()).all()
    logs_qr = ThreatLog.query.filter_by(category="qr").order_by(ThreatLog.timestamp.desc()).all()

    return render_template(
        "logs.html",
        logs_tabs=logs_tabs,
        logs_url=logs_url,
        logs_email=logs_email,
        logs_soc=logs_soc,
        logs_qr=logs_qr,
        active_page="logs"
    )


@common_bp.route("/system-health")
def system_health():
    return render_template("system_health.html")


@common_bp.route("/reports")
def reports():
    return render_template("reports.html")


@common_bp.route("/api/get_settings", methods=["GET"])
def api_get_settings():
    current_settings = get_settings()
    return jsonify({
        "email_alerts": current_settings.email_alerts,
        "notification_frequency": current_settings.notification_frequency,
        "auto_scan": current_settings.auto_scan,
        "log_retention": current_settings.log_retention_days,
        "vt_source": current_settings.vt_source,
        "vt_configured": current_settings.vt_configured,
    })


@common_bp.route("/api/update_settings", methods=["POST"])
def api_update_settings():
    try:
        data = request.get_json() or {}
        # Try to get user info for audit (if available)
        user = None
        if hasattr(request, 'user') and getattr(request, 'user', None):
            user = getattr(request, 'user', None)
        elif hasattr(request, 'remote_user') and getattr(request, 'remote_user', None):
            user = getattr(request, 'remote_user', None)
        else:
            user = request.headers.get('X-User', None)
        updated = update_settings(data, changed_by=user)
        return jsonify({
            "success": True,
            "message": "Settings updated",
            "settings": {
                "email_alerts": updated.email_alerts,
                "notification_frequency": updated.notification_frequency,
                "auto_scan": updated.auto_scan,
                "log_retention": updated.log_retention_days,
                "vt_source": updated.vt_source,
                "vt_configured": updated.vt_configured,
            }
        })
    except Exception as e:
        logging.error(f"api_update_settings error: {e}")
        return jsonify({"success": False, "error": "Failed to save settings"}), 500


@common_bp.route("/api/test_virustotal", methods=["POST"])
def api_test_virustotal():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return jsonify({"success": False, "error": "Not configured; set on server"}), 400

    try:
        resp = requests.get(
            "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        if resp.status_code == 200:
            mark_vt_available(True)
            return jsonify({"success": True})
        if resp.status_code == 401:
            mark_vt_available(False)
            return jsonify({"success": False, "error": "Unauthorized API key"}), 401
        return jsonify({"success": False, "error": f"VT error {resp.status_code}"}), resp.status_code
    except Exception as e:
        logging.error(f"api_test_virustotal error: {e}")
        return jsonify({"success": False, "error": "Connection error"}), 500


@common_bp.route("/api/clear-logs", methods=["POST"])
@limiter.limit("5 per minute")
def clear_logs():
    """
    CRITICAL FIX: Use environment variables for credentials
    For production: Hash passwords, use proper auth
    """
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    category = (data.get("category") or "").strip()

    # CRITICAL FIX: Move to environment variables
    ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")  # TODO: Remove default for production
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")  # TODO: Hash password for production

    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        if category:
            deleted = ThreatLog.query.filter_by(category=category).delete()
        else:
            deleted = ThreatLog.query.delete()
        db.session.commit()
        return jsonify({"ok": True, "deleted": deleted, "category": category or "all"})
    except Exception as e:
        db.session.rollback()
        logging.error(f"clear_logs error: {e}")
        return jsonify({"error": "Failed to clear logs"}), 500


@common_bp.route("/api/threat_logs")
@limiter.limit("10 per second")
def get_threat_logs():
    logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
    return jsonify([
        {
            "timestamp": log.timestamp,
            "url": log.url,
            "status": log.status,
            "flagged_reason": log.flagged_reason,
            "severity": log.severity
        }
        for log in logs
    ])


@common_bp.route("/api/threat_trends")
def get_threat_trends():
    try:
        data = (
            db.session.query(
                func.date(ThreatLog.timestamp).label("date"),
                func.count().label("count")
            )
            .group_by(func.date(ThreatLog.timestamp))
            .order_by(func.date(ThreatLog.timestamp).desc())
            .all()
        )
        trends_dict = {str(row.date): row.count for row in data}
        return jsonify(trends_dict)
    except Exception as e:
        logging.error(f"Error fetching threat trends: {e}")
        return jsonify({"error": "Failed to fetch threat trends"}), 500


@common_bp.route('/threat-trends')
def threat_trends():
    return jsonify({"message": "Threat Trends Data"})


@common_bp.route('/threat-distribution')
def threat_distribution():
    return jsonify({"message": "Threat Distribution Data"})


@common_bp.route('/threat-statistics')
def threat_statistics():
    return jsonify({"message": "Threat Statistics Data"})


@common_bp.route("/api/tab-activity", methods=["POST"])
def tab_activity():
    """Tab activity ingestion from browser extension"""
    try:
        data = request.get_json() or {}
        url = (data.get("url") or "").strip()
        title = data.get("title") or ""
        action = data.get("action") or "switch"
        
        if not url:
            return jsonify({"error": "url required"}), 400

        entry = ThreatLog(
            category="tabs",
            url=url,
            status="INFO",
            severity="Low",
            flagged_reason=f"Tab {action}: {title}".strip()
        )
        db.session.add(entry)
        db.session.commit()
        return jsonify({"ok": True})
    except Exception as e:
        logging.error(f"tab_activity error: {e}")
        db.session.rollback()
        return jsonify({"error": "failed"}), 500


@common_bp.route("/download-threat-log")
def download_threat_log():
    """
    CRITICAL FIX: Use BytesIO instead of writing to disk
    Avoids filesystem race conditions and permission issues
    """
    try:
        logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).all()
        
        # Use BytesIO for in-memory CSV generation
        output = BytesIO()
        # Wrap BytesIO with TextIOWrapper for csv.writer
        import io
        text_stream = io.TextIOWrapper(output, encoding='utf-8', newline='')
        
        writer = csv.writer(text_stream)
        writer.writerow(["ID", "Timestamp", "URL", "Status", "Flagged Reason", "Severity"])
        
        for log in logs:
            writer.writerow([
                log.id,
                log.timestamp,
                log.url,
                log.status,
                log.flagged_reason,
                log.severity
            ])
        
        # Flush and seek to start
        text_stream.flush()
        output.seek(0)
        
        return send_file(
            output,
            as_attachment=True,
            download_name='threat_logs.csv',
            mimetype='text/csv'
        )
    except Exception as e:
        logging.error(f"Error generating threat log CSV: {e}")
        return jsonify({"error": "Failed to generate threat log CSV"}), 500
