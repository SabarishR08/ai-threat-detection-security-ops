import os
import requests
from dotenv import load_dotenv

load_dotenv()

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
ALERT_EMAIL = os.getenv("ALERT_EMAIL")

def send_email_alert(src_ip, dst_ip, packet_size):
    """Send an email alert for a detected threat via Brevo API."""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    
    subject = "🚨Threat Detected!"
    message = f"""
    <h2>⚠️ Threat Alert ⚠️</h2>
    <p><strong>Suspicious Packet Detected:</strong></p>
    <ul>
        <li><b>Source IP:</b> {src_ip}</li>
        <li><b>Destination IP:</b> {dst_ip}</li>
        <li><b>Packet Size:</b> {packet_size} bytes</li>
    </ul>
    <p>Stay alert and investigate immediately!</p>
    """
    
    payload = {
        "sender": {"name": "AI-Kavach", "email": SENDER_EMAIL},
        "to": [{"email": ALERT_EMAIL}],
        "subject": subject,
        "htmlContent": message
    }
    
    response = requests.post(url, json=payload, headers=headers)
    
    if response.status_code == 201:
        print("✅ Email sent successfully!")
    else:
        print(f"❌ Failed to send email: {response.text}")

# Test email sending
if __name__ == "__main__":
    send_email_alert("192.168.1.1", "192.168.1.100", 150)
