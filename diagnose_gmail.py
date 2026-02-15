#!/usr/bin/env python
"""Gmail Fetcher Diagnostic Tool"""

import sys
import logging
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

print("=" * 70)
print("[Gmail Fetcher Diagnostic]")
print("=" * 70)

# Test 1: Check credentials file
print("\n1. Checking Gmail Credentials...")
from backend.services.gmail_service import CREDENTIALS_PATH, TOKEN_PATH

if CREDENTIALS_PATH.exists():
    print(f"   ✅ Credentials file found: {CREDENTIALS_PATH}")
    try:
        import json
        with open(CREDENTIALS_PATH) as f:
            creds = json.load(f)
            if "installed" in creds:
                print(f"   ✅ Valid OAuth2 credentials structure")
                print(f"      Client ID: {creds['installed'].get('client_id', 'N/A')[:30]}...")
            else:
                print(f"   ❌ Invalid credentials structure")
    except Exception as e:
        print(f"   ❌ Failed to read credentials: {e}")
else:
    print(f"   ❌ Credentials file NOT found: {CREDENTIALS_PATH}")
    print(f"      Please add Gmail OAuth credentials to: {CREDENTIALS_PATH}")

# Test 2: Check token file
print("\n2. Checking Token Cache...")
if TOKEN_PATH.exists():
    print(f"   ✅ Token cache found: {TOKEN_PATH}")
else:
    print(f"   ℹ️  No token cache (will be created on first auth): {TOKEN_PATH}")

# Test 3: Check required libraries
print("\n3. Checking Required Libraries...")
required_libs = [
    "google.auth.transport.requests",
    "google_auth_oauthlib.flow",
    "googleapiclient.discovery",
    "bs4"
]

for lib in required_libs:
    try:
        __import__(lib)
        print(f"   ✅ {lib}")
    except ImportError as e:
        print(f"   ❌ {lib} - {e}")

# Test 4: Try to authenticate (if credentials exist)
print("\n4. Testing Gmail Authentication...")
if CREDENTIALS_PATH.exists():
    try:
        from backend.services.gmail_service import authenticate_gmail
        print("   ℹ️  Attempting authentication...")
        service = authenticate_gmail()
        print("   ✅ Successfully authenticated with Gmail API")
        
        # Try to list emails
        try:
            results = service.users().messages().list(
                userId='me',
                maxResults=1,
                fields='messages(id)'
            ).execute()
            messages = results.get('messages', [])
            print(f"   ✅ Found {len(messages)} email(s)")
        except Exception as e:
            print(f"   ❌ Failed to list emails: {e}")
            print(f"      This might be an OAuth scope issue")
            
    except FileNotFoundError as e:
        print(f"   ❌ {e}")
    except ValueError as e:
        print(f"   ❌ {e}")
    except Exception as e:
        print(f"   ❌ Authentication error: {e}")
        print(f"      Error type: {type(e).__name__}")
        if "redirect" in str(e).lower():
            print(f"      ℹ️  This is a browser/localhost redirect issue")
            print(f"      ℹ️  You may need to:")
            print(f"          1. Visit the browser URL shown above")
            print(f"          2. Grant permissions")
            print(f"          3. Copy authorization code")
else:
    print("   ⏭️  Skipping auth test (no credentials file)")

# Test 5: Test fetch_recent_emails function
print("\n5. Testing Email Fetching...")
try:
    from backend.services.gmail_service import fetch_recent_emails
    print("   ℹ️  Attempting to fetch emails...")
    emails = fetch_recent_emails(limit=1)
    if emails:
        print(f"   ✅ Successfully fetched {len(emails)} email(s)")
        if isinstance(emails, list) and len(emails) > 0:
            email_preview = emails[0][:100] + "..." if len(emails[0]) > 100 else emails[0]
            print(f"      Preview: {email_preview}")
    else:
        print(f"   ⚠️  No emails returned (might be empty inbox or permission issue)")
except Exception as e:
    print(f"   ❌ Error fetching emails: {e}")
    print(f"      Error type: {type(e).__name__}")

print("\n" + "=" * 70)
print("[Diagnostic Complete]")
print("=" * 70)
print("\nCommon Issues:")
print("1. No credentials file:")
print("   - Add Gmail OAuth credentials to backend/credentials/credentials.json")
print("2. Authentication fails:")
print("   - Token may be expired or invalid")
print("   - Delete token.pickle and re-authenticate")
print("3. No emails found:")
print("   - Check Gmail inbox has emails")
print("   - Verify OAuth scope includes gmail.readonly")
print("4. Permission denied:")
print("   - Re-authenticate to grant required permissions")
