# backend/models.py
from datetime import datetime
from backend.extensions import db


class SystemSettings(db.Model):
    __tablename__ = "system_settings"
    id = db.Column(db.Integer, primary_key=True)
    email_alerts = db.Column(db.String(20), default="enabled")
    notification_frequency = db.Column(db.String(20), default="immediate")
    auto_scan = db.Column(db.Boolean, default=True)
    log_retention_days = db.Column(db.Integer, default=30)
    vt_available = db.Column(db.Boolean, default=False)

class ThreatLog(db.Model):
    __tablename__ = "threat_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # Index for sorting/filtering by date
    category = db.Column(db.String(50), index=True)  # Index for category filtering (email, url_scan, etc)
    url = db.Column(db.String(500))
    status = db.Column(db.String(50), index=True)  # Index for status filtering (Malicious, Safe, etc)
    flagged_reason = db.Column(db.String(200))
    severity = db.Column(db.String(20), index=True)  # Index for severity filtering (High, Medium, Low)
    details = db.Column(db.Text)

    def __repr__(self):
        return f"<ThreatLog {self.id}>"

class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)  # Index for recent alerts
    severity = db.Column(db.String(20), index=True)  # Index for severity filtering
    message = db.Column(db.String(255))
    status = db.Column(db.String(20), default="active", index=True)  # Index for active/resolved filtering
    source = db.Column(db.String(50))

    def __repr__(self):
        return f"<Alert {self.id}>"

class BlacklistedIP(db.Model):
    __tablename__ = "blacklisted_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    added_on = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<BlacklistedIP {self.ip_address}>"


# Audit log for admin actions (general)
class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    admin_user = db.Column(db.String(100), nullable=False)
    session_id = db.Column(db.String(200))
    source_ip = db.Column(db.String(45))
    setting_name = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)

# Settings change audit log (SOC-style)
class SettingsAudit(db.Model):
    __tablename__ = "settings_audit"
    id = db.Column(db.Integer, primary_key=True)
    changed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    changed_by = db.Column(db.String(100), nullable=True)  # Username or system
    field = db.Column(db.String(100), nullable=False)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)

    def __repr__(self):
        return f"<SettingsAudit {self.field} {self.id}>"
