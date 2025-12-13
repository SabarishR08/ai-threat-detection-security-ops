#!/usr/bin/env python3
"""
Test the /check-url endpoint with real API calls.
"""
import requests
import json
import time

BASE_URL = "http://localhost:5000"

TEST_URLS = [
    "https://microsoft365termsorg.weebly.com",
    "https://smartserviceprovider.duckdns.org",
    "https://google.com",
    "https://web.whatsapp.com",
]

def test_check_url_endpoint():
    """Test /check-url endpoint."""
    print("\n" + "=" * 70)
    print("TESTING /CHECK-URL ENDPOINT")
    print("=" * 70)
    
    for url in TEST_URLS:
        print(f"\n{'─' * 70}")
        print(f"URL: {url}")
        print(f"{'─' * 70}")
        
        try:
            payload = {"url": url}
            start = time.time()
            response = requests.post(
                f"{BASE_URL}/check-url",
                json=payload,
                timeout=30
            )
            elapsed = time.time() - start
            
            if response.status_code == 200:
                data = response.json()
                print(f"Status: {data.get('status', 'Unknown')}")
                print(f"Severity: {data.get('severity', 'Unknown')}")
                print(f"Detected By: {data.get('detected_by', 'None')}")
                print(f"Reason: {data.get('reason', 'N/A')}")
                print(f"Response Time: {elapsed:.2f}s")
                
                sources = data.get("sources", {})
                print(f"\nSources:")
                print(f"  VT: {json.dumps(sources.get('virustotal', {}), indent=4)}")
                print(f"  GSB: {json.dumps(sources.get('gsb', {}), indent=4)}")
                print(f"  PT: {json.dumps(sources.get('phishtank', {}), indent=4)}")
                
            else:
                print(f"❌ Error: {response.status_code}")
                print(f"Response: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("❌ ERROR: Cannot connect to backend. Is it running on port 5000?")
            return False
        except Exception as e:
            print(f"❌ ERROR: {e}")
            return False
    
    print("\n" + "=" * 70)
    print("ENDPOINT TEST COMPLETE")
    print("=" * 70)
    return True

if __name__ == "__main__":
    print("\n" + "╔" + "=" * 68 + "╗")
    print("║" + " /CHECK-URL ENDPOINT TEST ".center(68) + "║")
    print("╚" + "=" * 68 + "╝")
    
    if test_check_url_endpoint():
        print("\n✅ All tests completed successfully")
    else:
        print("\n⚠️  Some tests failed or backend is not running")
