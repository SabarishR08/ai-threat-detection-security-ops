#!/usr/bin/env python3
"""
Test PhishTank API directly to see if it can detect phishing.
"""
import os
import requests
import json
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")

print(f"PhishTank API Key present: {bool(PHISHTANK_API_KEY)}")

test_urls = [
    "https://microsoft365termsorg.weebly.com",
    "https://smartserviceprovider.duckdns.org",
]

for url in test_urls:
    print(f"\nTesting: {url}")
    
    form_data = {
        "url": url,
        "format": "json",
    }
    if PHISHTANK_API_KEY:
        form_data["app_key"] = PHISHTANK_API_KEY
    
    try:
        response = requests.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=form_data,
            timeout=10
        )
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"Response: {json.dumps(data, indent=2)}")
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Exception: {e}")
