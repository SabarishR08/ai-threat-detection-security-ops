import os
from dotenv import load_dotenv
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException

# ----------------------------
# Load .env
# ----------------------------
load_dotenv()
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SENDER = os.getenv("BREVO_SENDER")
BREVO_RECEIVER = os.getenv("BREVO_RECEIVER")

# ----------------------------
# Brevo API Setup
# ----------------------------
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = BREVO_API_KEY
api_instance = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

# ----------------------------
# Sample Phishing Email Content
# ----------------------------
subject = "⚠️ Action Required: Account Verification Needed"

html_content = """
<html>
  <head></head>
  <body style="font-family:Arial,sans-serif; font-size:14px; color:#333;">
    <p>Hi,</p>
    <p>We've noticed unusual activity on your account. Please verify your account immediately to avoid suspension:</p>
    <p><a href="http://phishing-reset-login.com" style="color:#1a73e8;">Verify Your Account</a></p>
    <p>Thank you,<br/>Security Team</p>
    <hr/>
    <small>This is an automated message. Do not reply.</small>
  </body>
</html>
"""

text_content = """
Hi,

We've noticed unusual activity on your account. Please verify your account immediately to avoid suspension:

Verify your account: http://phishing-reset-login.com

- Security Team
"""

# ----------------------------
# Compose and Send Email
# ----------------------------
email_data = {
    "sender": {"email": BREVO_SENDER},
    "to": [{"email": BREVO_RECEIVER}],
    "subject": subject,
    "htmlContent": html_content,
    "textContent": text_content
}

try:
    response = api_instance.send_transac_email(email_data)
    print("✅ Sample phishing email sent! Response:", response)
except ApiException as e:
    print("❌ Failed to send email:", e)
