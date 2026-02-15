#!/usr/bin/env python3
"""
Direct test of threat_checker module with real phishing URLs.
"""
import json
from datetime import datetime
from threat_checker import check_url

# Real phishing URLs from URLhaus/OpenPhish
REAL_PHISHING_URLS = [
    "https://themusicbelow.com/wp-content/maintenance/assets/font",
    "https://santosga.dreamhosters.com/bokl/auth/login.php",
    "https://bananbrain.com/avs7iisv",
    "https://vision-rmspending41.com/4904477605/",
    "https://google.com",  # Safe control
    "https://github.com",  # Safe control
    "https://amazon.com",  # Safe control
]

def main():
    print("\n" + "=" * 80)
    print(" DIRECT THREAT_CHECKER TEST WITH REAL PHISHING URLs ".center(80))
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ".center(80))
    print("=" * 80)
    
    results = []
    malicious_count = 0
    safe_count = 0
    error_count = 0
    
    print(f"\n" + "-" * 80)
    print(f"TESTING {len(REAL_PHISHING_URLS)} URLS WITH THREAT_CHECKER")
    print("-" * 80)
    
    for i, url in enumerate(REAL_PHISHING_URLS, 1):
        print(f"\n[{i:2d}/{len(REAL_PHISHING_URLS)}] Testing: {url[:60]}")
        
        try:
            result = check_url(url)
            results.append(result)
            
            final_status = result.get("final_status", "unknown").upper()
            detected_by = result.get("detected_by", "None")
            
            if final_status == "MALICIOUS":
                malicious_count += 1
                status_str = "[MALICIOUS]"
            elif final_status == "PHISHING":
                malicious_count += 1
                status_str = "[PHISHING]"
            elif final_status == "CLEAN":
                safe_count += 1
                status_str = "[CLEAN]"
            else:
                error_count += 1
                status_str = "[UNKNOWN]"
            
            print(f"   Result: {status_str}")
            print(f"   Final Status: {final_status}")
            print(f"   Detected By: {detected_by}")
            
            # Show details
            details = result.get("details", {})
            vt = details.get("virustotal", {})
            gsb = details.get("gsb", {})
            pt = details.get("phishtank", {})
            
            print(f"   Details:")
            print(f"     - VT: malicious={vt.get('malicious', 0)}, suspicious={vt.get('suspicious', 0)}")
            print(f"     - GSB: threat={gsb.get('threat', 'SAFE')}")
            print(f"     - PT: status={pt.get('status', 'safe')}")
            
        except Exception as e:
            error_count += 1
            print(f"   ERROR: {e}")
            results.append({
                "url": url,
                "error": str(e)
            })
    
    # Summary
    print(f"\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"[OK] Malicious/Phishing Detected: {malicious_count}/{len(REAL_PHISHING_URLS)} ({100*malicious_count//len(REAL_PHISHING_URLS) if REAL_PHISHING_URLS else 0}%)")
    print(f"[CLEAN] Safe Results: {safe_count}/{len(REAL_PHISHING_URLS)} ({100*safe_count//len(REAL_PHISHING_URLS) if REAL_PHISHING_URLS else 0}%)")
    print(f"[ERROR] Test Errors: {error_count}/{len(REAL_PHISHING_URLS)}")
    
    # Export results
    export_file = "threat_checker_test_results.json"
    with open(export_file, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_urls_tested": len(REAL_PHISHING_URLS),
            "malicious_detected": malicious_count,
            "safe_results": safe_count,
            "errors": error_count,
            "results": results
        }, f, indent=2)
    
    print(f"\n[OK] Results exported to {export_file}")
    
    # Show detailed JSON
    print(f"\n" + "=" * 80)
    print("DETAILED RESULTS (JSON)")
    print("=" * 80)
    print(json.dumps(results, indent=2)[:2000] + "...")  # Truncate for display

if __name__ == "__main__":
    main()
