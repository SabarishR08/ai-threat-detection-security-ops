"""
Performance and efficiency testing script for the threat detection system.
Tests all routes, measures response times, and validates optimizations.
"""

import sys
from pathlib import Path
import time
import json

# Add backend to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app_init import create_app
from models import ThreatLog, Alert, BlacklistedIP
from extensions import db

def test_routes_performance():
    """Test all routes and measure response times."""
    print("\n" + "="*60)
    print("🚀 TESTING ROUTES PERFORMANCE")
    print("="*60)
    
    app = create_app()
    results = []
    
    with app.test_client() as client:
        routes = [
            ("/", "Home redirect"),
            ("/dashboard", "Dashboard"),
            ("/logs", "Logs page"),
            ("/threat_lookup", "Threat lookup"),
            ("/qr_detector", "QR detector"),
            ("/soc-analyzer", "SOC analyzer"),
            ("/email_scanner/", "Email scanner"),
            ("/api/logs", "API: Logs"),
            ("/api/threat_logs", "API: Threat logs"),
            ("/api/threat_stats", "API: Threat stats"),
            ("/api/threat_trends", "API: Threat trends"),
            ("/api/threat_distribution", "API: Distribution"),
            ("/api/threat_statistics", "API: Statistics"),
            ("/api/threat_timeline", "API: Timeline"),
        ]
        
        for route, name in routes:
            start = time.time()
            try:
                resp = client.get(route)
                elapsed = (time.time() - start) * 1000
                
                status_icon = "✅" if resp.status_code in [200, 302] else "❌"
                speed_icon = "⚡" if elapsed < 100 else "🐢" if elapsed < 500 else "🔴"
                
                results.append({
                    "route": route,
                    "name": name,
                    "status": resp.status_code,
                    "time_ms": round(elapsed, 2),
                    "success": resp.status_code in [200, 302]
                })
                
                print(f"{status_icon} {speed_icon} {name:25} | {resp.status_code:3} | {elapsed:7.2f}ms")
                
            except Exception as e:
                print(f"❌ ❌ {name:25} | ERROR | {str(e)[:40]}")
                results.append({
                    "route": route,
                    "name": name,
                    "status": "ERROR",
                    "time_ms": 0,
                    "success": False,
                    "error": str(e)
                })
    
    return results

def test_database_performance():
    """Test database query performance."""
    print("\n" + "="*60)
    print("💾 TESTING DATABASE PERFORMANCE")
    print("="*60)
    
    app = create_app()
    
    with app.app_context():
        # Test 1: Count all logs
        start = time.time()
        count = ThreatLog.query.count()
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 50 else "🐢" if elapsed < 200 else "🔴"
        print(f"{speed_icon} Count all logs ({count:,} rows) | {elapsed:.2f}ms")
        
        # Test 2: Fetch recent logs (with limit)
        start = time.time()
        logs = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(100).all()
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 100 else "🐢" if elapsed < 500 else "🔴"
        print(f"{speed_icon} Fetch 100 recent logs | {elapsed:.2f}ms")
        
        # Test 3: Group by category (aggregated query)
        start = time.time()
        from sqlalchemy import func
        categories = db.session.query(
            ThreatLog.category,
            func.count(ThreatLog.id)
        ).group_by(ThreatLog.category).all()
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 50 else "🐢" if elapsed < 200 else "🔴"
        print(f"{speed_icon} Group by category ({len(categories)} groups) | {elapsed:.2f}ms")
        
        # Test 4: Dashboard stats (cached)
        start = time.time()
        from utils.helpers import get_dashboard_stats
        stats = get_dashboard_stats()
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 100 else "🐢" if elapsed < 500 else "🔴"
        print(f"{speed_icon} Dashboard stats (cached) | {elapsed:.2f}ms")
        
        # Test 5: Dashboard stats (second call - should be instant cache)
        start = time.time()
        stats = get_dashboard_stats()
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 10 else "🐢" if elapsed < 50 else "🔴"
        cache_working = elapsed < 10
        print(f"{speed_icon} Dashboard stats (cache hit) | {elapsed:.2f}ms {'✅ Cache working!' if cache_working else '❌ Cache not working'}")
        
        # Test 6: Logs by category (batch query)
        start = time.time()
        from utils.helpers import get_logs_by_category
        logs_dict = get_logs_by_category(limit_per_category=50)
        elapsed = (time.time() - start) * 1000
        speed_icon = "⚡" if elapsed < 200 else "🐢" if elapsed < 1000 else "🔴"
        print(f"{speed_icon} Logs by category (5 queries) | {elapsed:.2f}ms")

def test_api_endpoints():
    """Test API endpoints with POST requests."""
    print("\n" + "="*60)
    print("🔌 TESTING API ENDPOINTS")
    print("="*60)
    
    app = create_app()
    
    with app.test_client() as client:
        # Test URL check (safe URL)
        print("\n📡 Testing URL check endpoint...")
        start = time.time()
        resp = client.post('/check-url', 
                          json={"url": "https://google.com"},
                          content_type='application/json')
        elapsed = (time.time() - start) * 1000
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"✅ URL check: {data.get('status', 'N/A')} | {elapsed:.2f}ms")
        else:
            print(f"⚠️  URL check: Status {resp.status_code} | {elapsed:.2f}ms")
        
        # Test threat lookup
        print("\n🔍 Testing threat lookup endpoint...")
        start = time.time()
        resp = client.post('/api/threat_lookup',
                          json={"query": "https://example.com"},
                          content_type='application/json')
        elapsed = (time.time() - start) * 1000
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"✅ Threat lookup: {data.get('status', 'N/A')} | {elapsed:.2f}ms")
        else:
            print(f"⚠️  Threat lookup: Status {resp.status_code} | {elapsed:.2f}ms")

def generate_summary(results):
    """Generate performance summary."""
    print("\n" + "="*60)
    print("📊 PERFORMANCE SUMMARY")
    print("="*60)
    
    successful = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    
    if successful:
        times = [r["time_ms"] for r in successful]
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        print(f"\n✅ Successful routes: {len(successful)}/{len(results)}")
        print(f"⚡ Average response time: {avg_time:.2f}ms")
        print(f"🏆 Fastest response: {min_time:.2f}ms")
        print(f"🐌 Slowest response: {max_time:.2f}ms")
        
        # Performance rating
        if avg_time < 100:
            print(f"\n🏅 EXCELLENT - Average < 100ms")
        elif avg_time < 300:
            print(f"\n👍 GOOD - Average < 300ms")
        elif avg_time < 500:
            print(f"\n⚠️  MODERATE - Average < 500ms")
        else:
            print(f"\n🔴 SLOW - Average > 500ms")
    
    if failed:
        print(f"\n❌ Failed routes: {len(failed)}")
        for r in failed:
            print(f"  - {r['name']}: {r.get('error', 'Unknown error')[:50]}")
    
    # Optimization checks
    print("\n" + "="*60)
    print("🔧 OPTIMIZATION CHECKS")
    print("="*60)
    
    app = create_app()
    with app.app_context():
        # Check if indexes exist
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        indexes = inspector.get_indexes('threat_logs')
        print(f"✅ Database indexes: {len(indexes)} found")
        
        # Check cache
        from utils.helpers import _dashboard_cache
        cache_active = _dashboard_cache.get("data") is not None
        print(f"{'✅' if cache_active else '⚠️ '} Dashboard cache: {'Active' if cache_active else 'Empty'}")
        
    print("\n" + "="*60)
    print("✅ TESTING COMPLETE")
    print("="*60 + "\n")

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("🧪 THREAT DETECTION SYSTEM - PERFORMANCE TEST")
    print("="*60)
    
    try:
        # Run tests
        results = test_routes_performance()
        test_database_performance()
        test_api_endpoints()
        generate_summary(results)
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
