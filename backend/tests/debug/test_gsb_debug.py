#!/usr/bin/env python3
"""
Debug GSB API response directly.
"""
import os
import requests
import json
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
GSB_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

print(f"GSB API Key present: {bool(GSB_API_KEY)}")
print(f"GSB API Key (first 20 chars): {GSB_API_KEY[:20] if GSB_API_KEY else 'MISSING'}")

test_url = "https://microsoft365termsorg.weebly.com"

payload = {
    "client": {"clientId": "threat-checker", "clientVersion": "1.0"},
    "threatInfo": {
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": test_url}],
    },
}

url = f"https://safebrowsing.googleapis.com/v5/threatMatches:find?key={GSB_API_KEY}"

try:
    response = requests.post(url, json=payload, timeout=10)
    print(f"\nGSB Response Status: {response.status_code}")
    print(f"GSB Response Headers: {dict(response.headers)}")
    print(f"\nGSB Response Body:")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Error: {e}")
