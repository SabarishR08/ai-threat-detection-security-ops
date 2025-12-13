#!/usr/bin/env python3
"""Test script for QR generator API with multiple payload types"""

import sys
import os
import json
import base64
from io import BytesIO

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app_init import create_app

# Create app context
app = create_app()
client = app.test_client()

# Test payloads for each type
test_cases = [
    {
        "name": "URL Payload",
        "payload": {"type": "url", "url": "https://example.com/phishing"},
    },
    {
        "name": "WiFi Payload",
        "payload": {
            "type": "wifi",
            "ssid": "FreeWiFi",
            "security": "WPA",
            "password": "secret123"
        },
    },
    {
        "name": "SMS Payload",
        "payload": {
            "type": "sms",
            "phone": "+1234567890",
            "message": "Click here for prize"
        },
    },
    {
        "name": "Tel Payload",
        "payload": {
            "type": "tel",
            "phone": "+1-800-SCAMMER"
        },
    },
    {
        "name": "Email Payload",
        "payload": {
            "type": "email",
            "email": "attacker@evil.com",
            "subject": "Verify Account",
            "body": "Click link to confirm"
        },
    },
    {
        "name": "UPI Payload",
        "payload": {
            "type": "upi",
            "upi_id": "attacker@upi",
            "amount": "100",
            "description": "Payment Request"
        },
    },
    {
        "name": "Text Payload",
        "payload": {
            "type": "text",
            "text": "This is plain text in QR"
        },
    },
]

print("=" * 70)
print("Testing QR Generator API - Multi-Payload Support")
print("=" * 70)

passed = 0
failed = 0

for test_case in test_cases:
    name = test_case["name"]
    payload = test_case["payload"]
    
    print(f"\n{name}:")
    print(f"  Payload: {json.dumps(payload, indent=4)}")
    
    # Send request
    response = client.post(
        "/api/generate-qr",
        json=payload,
        content_type="application/json"
    )
    
    # Check response
    if response.status_code == 200:
        data = response.get_json()
        
        if "qr_code" in data and data["qr_code"]:
            # Verify it's valid base64
            try:
                qr_bytes = base64.b64decode(data["qr_code"])
                
                # Verify it's a PNG (starts with PNG signature)
                if qr_bytes[:8] == b'\x89PNG\r\n\x1a\n':
                    print(f"  ✓ PASSED - QR code generated successfully")
                    print(f"    - Size: {len(qr_bytes)} bytes")
                    print(f"    - Payload Type: {data.get('type')}")
                    print(f"    - Encoded Payload: {data.get('payload')[:50]}...")
                    passed += 1
                else:
                    print(f"  ✗ FAILED - Invalid PNG signature")
                    failed += 1
            except Exception as e:
                print(f"  ✗ FAILED - Invalid base64: {e}")
                failed += 1
        else:
            print(f"  ✗ FAILED - No qr_code in response: {data}")
            failed += 1
    else:
        data = response.get_json()
        print(f"  ✗ FAILED - Status {response.status_code}: {data}")
        failed += 1

# Test error cases
print("\n" + "=" * 70)
print("Testing Error Cases")
print("=" * 70)

error_cases = [
    {
        "name": "Missing URL",
        "payload": {"type": "url", "url": ""}
    },
    {
        "name": "Missing WiFi SSID",
        "payload": {"type": "wifi", "ssid": "", "security": "WPA"}
    },
    {
        "name": "Invalid Payload Type",
        "payload": {"type": "invalid", "text": "test"}
    },
]

for test_case in error_cases:
    name = test_case["name"]
    payload = test_case["payload"]
    
    print(f"\n{name}:")
    response = client.post(
        "/api/generate-qr",
        json=payload,
        content_type="application/json"
    )
    
    if response.status_code >= 400:
        data = response.get_json()
        print(f"  ✓ PASSED - Correctly returned error: {data.get('error')}")
        passed += 1
    else:
        print(f"  ✗ FAILED - Should have returned error but got status {response.status_code}")
        failed += 1

# Summary
print("\n" + "=" * 70)
print(f"Results: {passed} passed, {failed} failed")
print("=" * 70)

sys.exit(0 if failed == 0 else 1)
