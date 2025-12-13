#!/usr/bin/env python3
"""
Fetch known phishing URLs from online resources and test against /check-url endpoint.
Tests the threat detection system with real phishing samples.
"""
import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:5000"

# Known public phishing/threat sources
PHISHING_SOURCES = {
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus_phishing": "https://urlhaus-api.abuse.ch/v1/urls/recent/?threat_type=phishing&limit=20",
}

def fetch_openphish_urls(limit=10):
    """Fetch recent phishing URLs from OpenPhish."""
    print("\n[+] Fetching from OpenPhish...")
    try:
        response = requests.get(PHISHING_SOURCES["openphish"], timeout=10)
        if response.status_code == 200:
            urls = response.text.strip().split('\n')[:limit]
            return [url for url in urls if url.startswith(('http://', 'https://'))]
    except Exception as e:
        print(f"    Error: {e}")
    return []

def fetch_urlhaus_phishing_urls(limit=10):
    """Fetch phishing URLs from URLhaus API."""
    print("\n[+] Fetching from URLhaus...")
    try:
        response = requests.post(PHISHING_SOURCES["urlhaus_phishing"], timeout=10)
        if response.status_code == 200:
            data = response.json()
            urls = [item.get("url") for item in data.get("results", [])][:limit]
            return [url for url in urls if url]
    except Exception as e:
        print(f"    Error: {e}")
    return []

def test_url_against_backend(url):
    """Test a single URL against /check-url endpoint."""
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
            return {
                "url": url,
                "status": data.get("status", "Unknown"),
                "severity": data.get("severity", "Unknown"),
                "detected_by": data.get("detected_by", "None"),
                "reason": data.get("reason", "N/A"),
                "response_time": f"{elapsed:.2f}s",
                "sources": data.get("sources", {}),
                "success": True
            }
        else:
            return {
                "url": url,
                "error": f"HTTP {response.status_code}",
                "success": False
            }
    except requests.exceptions.ConnectionError:
        return {
            "url": url,
            "error": "Cannot connect to backend",
            "success": False
        }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "success": False
        }

def main():
    print("\n" + "=" * 80)
    print(" PHISHING URL TEST SUITE (REAL-WORLD SAMPLES) ".center(80))
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ".center(80))
    print("=" * 80)
    
    all_urls = []
    
    # Fetch from sources
    all_urls.extend(fetch_openphish_urls(limit=15))
    all_urls.extend(fetch_urlhaus_phishing_urls(limit=15))
    
    # Remove duplicates
    all_urls = list(set(all_urls))
    
    if not all_urls:
        print("\n[!] Could not fetch phishing URLs from online sources")
        print("    This may indicate network issues or API changes")
        return
    
    print(f"\n[OK] Fetched {len(all_urls)} unique phishing URLs")
    
    # Test each URL
    results = []
    malicious_count = 0
    safe_count = 0
    unknown_count = 0
    error_count = 0
    
    print(f"\n" + "-" * 80)
    print(f"TESTING {len(all_urls)} URLS AGAINST /CHECK-URL ENDPOINT")
    print("-" * 80)
    
    for i, url in enumerate(all_urls, 1):
        result = test_url_against_backend(url)
        results.append(result)
        
        if result.get("success"):
            status = result.get("status", "Unknown")
            if status == "Malicious":
                malicious_count += 1
                symbol = "[MALICIOUS]"
            elif status == "Suspicious":
                unknown_count += 1
                symbol = "[SUSPICIOUS]"
            else:
                safe_count += 1
                symbol = "[SAFE]"
        else:
            error_count += 1
            symbol = "[ERROR]"
        
        print(f"\n[{i:2d}/{len(all_urls)}] {symbol} {url[:60]}")
        if result.get("success"):
            print(f"     Status: {result.get('status', 'Unknown')}")
            print(f"     Detected By: {result.get('detected_by', 'None')}")
            print(f"     Response Time: {result.get('response_time', 'N/A')}")
        else:
            print(f"     Error: {result.get('error', 'Unknown error')}")
    
    # Print summary
    print(f"\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"[OK] Malicious Detected: {malicious_count}/{len(all_urls)} ({100*malicious_count//len(all_urls) if all_urls else 0}%)")
    print(f"[!] Suspicious: {unknown_count}/{len(all_urls)}")
    print(f"[SAFE] False Negatives: {safe_count}/{len(all_urls)} ({100*safe_count//len(all_urls) if all_urls else 0}%)")
    print(f"[ERROR] Test Errors: {error_count}/{len(all_urls)}")
    
    # Detailed results
    print(f"\n" + "=" * 80)
    print("DETAILED RESULTS (JSON)")
    print("=" * 80)
    print(json.dumps(results, indent=2))
    
    # Export results
    export_file = "phishing_test_results.json"
    with open(export_file, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_urls_tested": len(all_urls),
            "malicious_detected": malicious_count,
            "suspicious": unknown_count,
            "safe_results": safe_count,
            "errors": error_count,
            "results": results
        }, f, indent=2)
    
    print(f"\n[OK] Results exported to {export_file}")

if __name__ == "__main__":
    main()
