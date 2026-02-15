import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()

# SMTP Server details (use environment variables in production)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp-relay.brevo.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "your-brevo-email@smtp-brevo.com")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "your-brevo-api-key-here")
SMTP_KEY = os.getenv("SMTP_KEY", "")
SMTP_API = os.getenv("SENDBLUE_API_KEY", "your-sendblue-api-key-here")

# Email details
sender_email = os.getenv("SENDER_EMAIL", "notification@example.com")
receiver_email = os.getenv("RECEIVER_EMAIL", "test@example.com")
subject = "Test Email from AI-Kavach"
body = "Hello, this is a test email from AI-Kavach using Brevo SMTP."

# Create email message
msg = MIMEMultipart()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject
msg.attach(MIMEText(body, "plain"))

# Connect to SMTP Server and send email
try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()  # Secure connection
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()
    print("✅ Test email sent successfully!")
except Exception as e:
    print(f"❌ Failed to send email: {e}")
