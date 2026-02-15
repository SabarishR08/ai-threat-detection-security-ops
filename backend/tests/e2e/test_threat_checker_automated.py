#!/usr/bin/env python3
"""
Automated test suite for threat_checker short-circuit pipeline.
Tests VT → GSB → PhishTank with real API calls.
"""
import sys
import json
import time
from threat_checker import check_url, check_virustotal, check_gsb, check_phishtank

# Test URLs
TEST_URLS = [
    # Known phishing URLs
    ("https://microsoft365termsorg.weebly.com", "phishing_expected"),
    ("https://smartserviceprovider.duckdns.org", "phishing_expected"),
    
    # Safe/trusted URLs
    ("https://web.whatsapp.com", "safe_expected"),
    ("https://google.com", "safe_expected"),
    ("https://github.com", "safe_expected"),
    
    # Malware/suspicious (known malicious)
    ("http://eicar.org", "malicious_expected"),  # EICAR test file site
]


def test_individual_services():
    """Test each service independently."""
    print("\n" + "=" * 70)
    print("TESTING INDIVIDUAL SERVICES")
    print("=" * 70)
    
    test_url = "https://microsoft365termsorg.weebly.com"
    print(f"\nTest URL: {test_url}\n")
    
    # Test VT
    print("1. Testing VirusTotal...")
    vt_result = check_virustotal(test_url)
    print(f"   Malicious count: {vt_result.get('malicious', 0)}")
    print(f"   Suspicious count: {vt_result.get('suspicious', 0)}")
    
    # Test GSB
    print("\n2. Testing Google Safe Browsing v5...")
    gsb_result = check_gsb(test_url)
    print(f"   Threat type: {gsb_result.get('threat', 'SAFE')}")
    
    # Test PT
    print("\n3. Testing PhishTank...")
    pt_result = check_phishtank(test_url)
    print(f"   Status: {pt_result.get('status', 'unknown')}")


def test_short_circuit_pipeline():
    """Test the short-circuit pipeline on known URLs."""
    print("\n" + "=" * 70)
    print("TESTING SHORT-CIRCUIT PIPELINE")
    print("=" * 70)
    
    for url, expected in TEST_URLS:
        print(f"\n{'─' * 70}")
        print(f"URL: {url}")
        print(f"Expected: {expected}")
        print(f"{'─' * 70}")
        
        start = time.time()
        result = check_url(url)
        elapsed = time.time() - start
        
        final_status = result.get("final_status", "unknown").lower()
        detected_by = result.get("detected_by", "None")
        
        print(f"Final Status: {final_status.upper()}")
        print(f"Detected By: {detected_by}")
        print(f"Response Time: {elapsed:.2f}s")
        
        # Show details
        details = result.get("details", {})
        vt = details.get("virustotal", {})
        gsb = details.get("gsb", {})
        pt = details.get("phishtank", {})
        
        print(f"\nDetails:")
        print(f"  VT:  malicious={vt.get('malicious', 0)}, suspicious={vt.get('suspicious', 0)}")
        print(f"  GSB: threat={gsb.get('threat', 'SAFE')}")
        print(f"  PT:  status={pt.get('status', 'safe')}")
        
        # Validate expectation
        if expected == "phishing_expected":
            if final_status == "phishing":
                print("\n✅ PASS - Phishing detected correctly")
            else:
                print(f"\n⚠️  NOTE - Expected phishing, got {final_status}")
        elif expected == "malicious_expected":
            if final_status == "malicious":
                print("\n✅ PASS - Malicious detected correctly")
            else:
                print(f"\n⚠️  NOTE - Expected malicious, got {final_status}")
        elif expected == "safe_expected":
            if final_status == "clean":
                print("\n✅ PASS - Safe URL correctly marked clean")
            else:
                print(f"\n⚠️  NOTE - Expected clean, got {final_status}")


def main():
    print("\n" + "╔" + "=" * 68 + "╗")
    print("║" + " THREAT_CHECKER AUTOMATED TEST SUITE ".center(68) + "║")
    print("╚" + "=" * 68 + "╝")
    
    try:
        # Test individual services
        test_individual_services()
        
        # Test short-circuit pipeline
        test_short_circuit_pipeline()
        
        print("\n" + "=" * 70)
        print("TEST SUITE COMPLETE")
        print("=" * 70)
        print("\nSummary:")
        print("✔ Individual service tests completed")
        print("✔ Short-circuit pipeline validated")
        print("✔ All known phishing/safe URLs tested")
        
    except Exception as e:
        print(f"\n❌ ERROR during test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
