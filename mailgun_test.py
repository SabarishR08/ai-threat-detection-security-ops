import os
import requests

def send_simple_message():
    mailgun_api_key = os.getenv("MAILGUN_API_KEY", "")
    mailgun_domain = os.getenv("MAILGUN_DOMAIN", "sandbox.example.mailgun.org")
    sender_email = os.getenv("MAILGUN_SENDER", f"postmaster@{mailgun_domain}")
    receiver_email = os.getenv("MAILGUN_RECEIVER", "example@example.com")

    if not mailgun_api_key:
        raise ValueError("MAILGUN_API_KEY is not set")

    return requests.post(
        f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
        auth=("api", mailgun_api_key),
        data={
            "from": f"Mailgun Sandbox <{sender_email}>",
            "to": receiver_email,
            "subject": "Test Email 🚀",
            "text": "If you see this, your Mailgun setup WORKS!"
        }
    )

response = send_simple_message()
print(response.status_code)
print(response.text)