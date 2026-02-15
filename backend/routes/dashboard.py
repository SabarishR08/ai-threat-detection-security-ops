
"""
Dashboard Routes - Main dashboard view with threat statistics
"""
from flask import Blueprint, render_template
from sqlalchemy import func
from backend.models import ThreatLog

dashboard_bp = Blueprint("dashboard", __name__)

# ...existing code...

@dashboard_bp.route("/settings_audit")
def settings_audit():
    return render_template("settings_audit.html", active_page="settings_audit")

@dashboard_bp.route("/dashboard")
def dashboard():
    try:
        # 1. Threats per day
        threats_per_day = (
            ThreatLog.query
            .with_entities(
                func.date(ThreatLog.timestamp),
                func.count(ThreatLog.id)
            )
            .group_by(func.date(ThreatLog.timestamp))
            .order_by(func.date(ThreatLog.timestamp))
            .all()
        )

        daily_labels = [str(row[0]) for row in threats_per_day]
        daily_values = [row[1] for row in threats_per_day]

        # 2. Severity distribution
        severity_data = (
            ThreatLog.query
            .with_entities(ThreatLog.severity, func.count(ThreatLog.id))
            .group_by(ThreatLog.severity)
            .all()
        )

        severity_labels = [row[0] for row in severity_data]
        severity_values = [row[1] for row in severity_data]

        # 3. Category distribution
        category_data = (
            ThreatLog.query
            .with_entities(ThreatLog.category, func.count(ThreatLog.id))
            .group_by(ThreatLog.category)
            .all()
        )

        category_labels = [row[0] for row in category_data]
        category_values = [row[1] for row in category_data]

        # 4. STAT CARDS (REAL LIVE DATA)
        stats = {
            "emails_scanned": ThreatLog.query.filter_by(category="email").count(),
            "malicious_urls": ThreatLog.query.filter(
                (ThreatLog.category == "url_scan") &
                (func.lower(ThreatLog.status) == "malicious")
            ).count(),
            "qr_threats": ThreatLog.query.filter_by(category="qr").count(),
            "soc_events": ThreatLog.query.filter_by(category="soc").count(),
            "ti_queries": ThreatLog.query.filter_by(category="threat_lookup").count(),
            "active_alerts": ThreatLog.query.filter(
                ThreatLog.severity.in_(["High", "Critical"])
            ).count()
        }

        # 5. Recent logs
        logs_url = ThreatLog.query.filter_by(category="url_scan").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_email = ThreatLog.query.filter_by(category="email").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_soc = ThreatLog.query.filter_by(category="soc").order_by(ThreatLog.timestamp.desc()).limit(10).all()
        logs_qr = ThreatLog.query.filter_by(category="qr").order_by(ThreatLog.timestamp.desc()).limit(10).all()

        alerts = []

        return render_template(
            "dashboard.html",
            logs_url=logs_url,
            logs_email=logs_email,
            logs_soc=logs_soc,
            logs_qr=logs_qr,
            daily_labels=daily_labels,
            daily_values=daily_values,
            severity_labels=severity_labels,
            severity_values=severity_values,
            category_labels=category_labels,
            category_values=category_values,
            stats=stats,
            alerts=alerts,
            active_page="dashboard"
        )

    except Exception as e:
        print("ERROR:", e)
        # Safe defaults to avoid template undefined errors
        fallback_stats = {
            "emails_scanned": 0,
            "malicious_urls": 0,
            "qr_threats": 0,
            "soc_events": 0,
            "ti_queries": 0,
            "active_alerts": 0,
        }
        return render_template(
            "dashboard.html",
            logs_url=[],
            logs_email=[],
            logs_soc=[],
            logs_qr=[],
            daily_labels=[],
            daily_values=[],
            severity_labels=[],
            severity_values=[],
            category_labels=[],
            category_values=[],
            stats=fallback_stats,
            alerts=[],
            active_page="dashboard"
        )
