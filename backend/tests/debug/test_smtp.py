import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP Server details
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_USERNAME = os.getenv("BREVO_SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("BREVO_SMTP_PASSWORD", "")

SMTP_KEY = ""
SMTP_API = os.getenv("BREVO_API_KEY", "")

def main() -> None:
    sender_email = os.getenv("BREVO_SENDER_EMAIL", SMTP_USERNAME or "example@example.com")
    receiver_email = os.getenv("BREVO_RECEIVER_EMAIL", "example@example.com")
    subject = "Test Email from AI-Kavach"
    body = "Hello, this is a test email from AI-Kavach using Brevo SMTP."

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        if not SMTP_USERNAME or not SMTP_PASSWORD:
            raise ValueError("BREVO_SMTP_USERNAME/BREVO_SMTP_PASSWORD are not set")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("✅ Test email sent successfully!")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")


if __name__ == "__main__":
    main()
