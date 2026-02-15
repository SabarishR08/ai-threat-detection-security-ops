"""
Background services initializer
- Starts scheduler
- Schedules auto-scan job
- Starts websocket emitter

Feature-flagged via app.config["ENABLE_BACKGROUND_JOBS"]
"""
import logging
from backend.background.scheduler import schedule_auto_scan, start_scheduler
from backend.background.websocket_emitter import start_websocket_emitter
from backend.email_scanner import scan_emails
from backend.utils.settings_service import get_settings


def initialize_background_services(app, socketio):
    """Initialize background services if enabled."""
    if not app.config.get("ENABLE_BACKGROUND_JOBS", True):
        logging.info("Background jobs disabled via config; skipping initialization")
        return

    settings = get_settings()

    def analyze_email_for_scan(subject, body, from_addr, auto_scan=False):
        try:
            result = scan_emails(subject, body)
            return {
                "is_phishing": result.get("is_phishing", False),
                "severity": "High" if result.get("is_phishing") else "Low",
                "from": from_addr,
                "auto_scan": auto_scan
            }
        except Exception as e:
            logging.error(f"Error analyzing email: {e}")
            return {"is_phishing": False, "severity": "Low", "error": str(e)}

    start_scheduler()
    if settings.auto_scan:
        schedule_auto_scan(app, socketio, analyze_email_for_scan)
    else:
        logging.info("Auto-scan disabled via settings; scheduler started without email job")
    start_websocket_emitter(app, socketio)
    logging.info("Background services initialized")
