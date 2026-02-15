"""
Scheduler - Background job scheduling for auto-scan
CRITICAL FIX: Proper Flask context usage
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from backend.core.email_auto_scan import run_auto_scan

scheduler = BackgroundScheduler()

def schedule_auto_scan(app, socketio, analyze_email_callback):
    """
    Schedule the Gmail auto-scan job (every 5 minutes)
    CRITICAL FIX: Proper Flask context manager usage
    """
    def auto_scan_job():
        # CRITICAL FIX: Use app.app_context() as context manager
        with app.app_context():
            run_auto_scan(app, socketio, analyze_email_callback)
    
    scheduler.add_job(
        func=auto_scan_job,
        trigger="interval",
        minutes=5,
        id="email_auto_scan",
        name="Gmail Auto-Scan",
        replace_existing=True
    )
    logging.info("Email auto-scan job scheduled (every 5 minutes)")


def start_scheduler():
    """Start the background scheduler"""
    if not scheduler.running:
        scheduler.start()
        logging.info("Background scheduler started")


def shutdown_scheduler():
    """Gracefully shutdown the scheduler"""
    if scheduler.running:
        scheduler.shutdown()
        logging.info("Background scheduler stopped")
