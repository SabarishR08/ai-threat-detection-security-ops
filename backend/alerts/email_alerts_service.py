"""
Email Alert Service - Sends threat notifications via Brevo
Runs in background thread to avoid blocking requests
"""
import os
import logging
import requests
import threading
from dotenv import load_dotenv
from backend.utils.settings_service import get_settings

load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

def send_brevo_email_async(client_ip, url, status, severity):
    """
    Send email alert in background thread (non-blocking)
    This prevents blocking the Flask request cycle
    """
    def _send():
        send_brevo_email(client_ip, url, status, severity)
    
    threading.Thread(target=_send, daemon=True).start()


def send_brevo_email(client_ip, url, status, severity):
    """
    Synchronous email sending (called by background thread)
    """
    settings = get_settings()
    if settings.email_alerts == "disabled":
        logging.info("Skipping Brevo email — alerts disabled in settings")
        return False
    if settings.email_alerts == "critical" and severity.lower() not in {"high", "critical", "malicious", "phishing"}:
        logging.info("Skipping Brevo email — non-critical alert")
        return False
    if not BREVO_API_KEY or not ALERT_EMAIL or not SENDER_EMAIL:
        logging.info("Skipping Brevo email — API key / addresses not configured")
        return False
    try:
        brevo_url = "https://api.brevo.com/v3/smtp/email"
        payload = {
            "sender": {"name": "Threat Detection System", "email": SENDER_EMAIL},
            "to": [{"email": ALERT_EMAIL}],
            "subject": f"🚨 Malicious URL Detected - Severity: {severity}",
            "htmlContent": (
                f"<h1>🚨 Malicious URL Detected</h1>"
                f"<p><strong>Client IP:</strong> {client_ip}</p>"
                f"<p><strong>URL:</strong> {url}</p>"
                f"<p><strong>Status:</strong> {status}</p>"
                f"<p><strong>Severity:</strong> {severity}</p>"
            )
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY
        }
        resp = requests.post(brevo_url, headers=headers, json=payload, timeout=15)
        if resp.status_code in (200, 201):
            logging.info(f"Brevo alert sent to {ALERT_EMAIL}")
            return True
        else:
            logging.error(f"Brevo send failed: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        logging.error(f"Error sending Brevo email alert: {e}")
        return False
