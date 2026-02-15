"""
Maintenance services: cleanup tasks and scheduled maintenance routines.
"""
import logging
from datetime import datetime, timedelta
from backend.extensions import db
from backend.models import ThreatLog


def cleanup_old_logs(retention_days: int = 30) -> int:
    """Delete ThreatLog entries older than retention_days.
    Returns number of rows deleted.
    """
    try:
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        deleted = ThreatLog.query.filter(ThreatLog.timestamp < cutoff_date).delete()
        db.session.commit()
        logging.info(f"Cleaned up {deleted} old threat logs (> {retention_days} days)")
        return deleted
    except Exception as e:
        logging.error(f"cleanup_old_logs error: {e}")
        db.session.rollback()
        return 0
