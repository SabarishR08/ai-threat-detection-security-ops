#backend\services\alert_service.py
#used in \backend\email_scanner.py
#as from services.alert_service import send_brevo_alert

import requests
import os

# Load from environment
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER = os.getenv("BREVO_SENDER")
BREVO_RECEIVER = os.getenv("BREVO_RECEIVER")

def send_brevo_alert(subject: str, body: str):
    """
    Sends an email alert through Brevo.
    Returns True/False depending on success.
    """

    if not (BREVO_API_KEY and BREVO_SENDER and BREVO_RECEIVER):
        print("[Brevo] Missing API key/sender/receiver → Alert skipped.")
        return False

    try:
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "accept": "application/json",
                "api-key": BREVO_API_KEY,
                "content-type": "application/json"
            },
            json={
                "sender": {"name": "Phishing Alert", "email": BREVO_SENDER},
                "to": [{"email": BREVO_RECEIVER}],
                "subject": subject,
                "htmlContent": body
            }
        )

        if response.status_code in (200, 201):
            print("[Brevo] Alert sent successfully.")
            return True

        print(f"[Brevo] Failed ({response.status_code}): {response.text}")
        return False

    except Exception as e:
        print(f"[Brevo] Error sending alert: {e}")
        return False


# ---------------------------
# Brevo Email Alert Function (URL alerts handled via send_brevo_alert above)
