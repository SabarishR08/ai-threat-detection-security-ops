from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Optional
from backend.extensions import db
from backend.models import SystemSettings, SettingsAudit

DEFAULT_EMAIL_ALERTS = "enabled"
DEFAULT_NOTIFICATION_FREQUENCY = "immediate"
DEFAULT_AUTO_SCAN = True
DEFAULT_LOG_RETENTION_DAYS = 30

@dataclass
class SettingsDTO:
    email_alerts: str = DEFAULT_EMAIL_ALERTS
    notification_frequency: str = DEFAULT_NOTIFICATION_FREQUENCY
    auto_scan: bool = DEFAULT_AUTO_SCAN
    log_retention_days: int = DEFAULT_LOG_RETENTION_DAYS
    vt_source: str = "env"
    vt_configured: bool = False


def _ensure_row() -> SystemSettings:
    row = SystemSettings.query.first()
    if row:
        return row
    row = SystemSettings(
        email_alerts=DEFAULT_EMAIL_ALERTS,
        notification_frequency=DEFAULT_NOTIFICATION_FREQUENCY,
        auto_scan=DEFAULT_AUTO_SCAN,
        log_retention_days=DEFAULT_LOG_RETENTION_DAYS,
    )
    db.session.add(row)
    db.session.commit()
    return row


def get_settings() -> SettingsDTO:
    row = _ensure_row()
    return SettingsDTO(
        email_alerts=row.email_alerts or DEFAULT_EMAIL_ALERTS,
        notification_frequency=row.notification_frequency or DEFAULT_NOTIFICATION_FREQUENCY,
        auto_scan=bool(row.auto_scan) if row.auto_scan is not None else DEFAULT_AUTO_SCAN,
        log_retention_days=int(row.log_retention_days or DEFAULT_LOG_RETENTION_DAYS),
        vt_source="env",
        vt_configured=bool(row.vt_available),
    )


def update_settings(payload: dict, changed_by: str = None) -> SettingsDTO:
    row = _ensure_row()
    changes = []
    # Track changes for audit
    def audit(field, old, new):
        if str(old) != str(new):
            changes.append(SettingsAudit(
                changed_by=changed_by or "system",
                field=field,
                old_value=str(old),
                new_value=str(new)
            ))
    # Email alerts
    new_email_alerts = (payload.get("email_alerts") or row.email_alerts or DEFAULT_EMAIL_ALERTS).lower()
    audit("email_alerts", row.email_alerts, new_email_alerts)
    row.email_alerts = new_email_alerts
    # Notification frequency
    new_nf = (payload.get("notification_frequency") or row.notification_frequency or DEFAULT_NOTIFICATION_FREQUENCY).lower()
    audit("notification_frequency", row.notification_frequency, new_nf)
    row.notification_frequency = new_nf
    # Auto scan
    new_auto_scan = bool(payload.get("auto_scan", row.auto_scan if row.auto_scan is not None else DEFAULT_AUTO_SCAN))
    audit("auto_scan", row.auto_scan, new_auto_scan)
    row.auto_scan = new_auto_scan
    # Log retention
    new_lr = int(payload.get("log_retention", payload.get("log_retention_days", row.log_retention_days or DEFAULT_LOG_RETENTION_DAYS)))
    audit("log_retention_days", row.log_retention_days, new_lr)
    row.log_retention_days = new_lr
    # vt_available is derived from deployment/env; do not set from UI
    try:
        if changes:
            db.session.add_all(changes)
        db.session.commit()
    except Exception as exc:
        logging.error(f"update_settings commit failed: {exc}")
        db.session.rollback()
        raise
    return get_settings()


def mark_vt_available(flag: bool):
    row = _ensure_row()
    row.vt_available = bool(flag)
    try:
        db.session.commit()
    except Exception as e:
        logging.error(f"Failed to mark VT availability: {e}")
        db.session.rollback()
