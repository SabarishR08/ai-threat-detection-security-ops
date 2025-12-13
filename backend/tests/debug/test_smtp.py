import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# SMTP Server details
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587
SMTP_USERNAME = "9cfb55001@smtp-brevo.com"
SMTP_PASSWORD = "xsmtpsib-a497853b473b0f62b01bccdb4a78f7c0da7ca3d4d82d909c701a2f01d97da295-0pfALIQNd9iswYkY"
#jNDZnJPQfGzUt61B  
# Change if regenerated

SMTP_KEY = ""
SMTP_API= "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"

# Email details
sender_email = "9cfb55001@smtp-brevo.com"
receiver_email = "sabarishtmp24@gmail.com"
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
