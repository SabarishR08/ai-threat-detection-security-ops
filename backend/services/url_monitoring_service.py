"""
URL Monitoring Service - Continuous monitoring of known threats and suspicious URLs

Features:
- Periodic re-scanning of flagged URLs
- Status change detection and alerting
- Automatic threat closure when URLs become safe
- Monitoring queue management
- Historical tracking of URL status changes
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict

from backend.extensions import db
from backend.models import ThreatLog
from backend.services.threat_lookup_service import unified_check_url_async

# Monitoring queue (in production, use Redis or database)
monitoring_queue = {
    "active": {},  # URLs currently being monitored
    "history": defaultdict(list),  # Status change history
    "auto_close_enabled": True,
    "scan_interval_minutes": 60,  # Default re-scan interval
}

# Configuration
MONITOR_CONFIG = {
    "max_monitored_urls": 1000,  # Limit monitoring queue size
    "auto_close_after_safe_scans": 3,  # Close after 3 consecutive safe scans
    "escalation_threshold": 5,  # Alert if status changes 5+ times
    "retention_days": 30,  # Keep history for 30 days
}


class URLMonitor:
    """Manages continuous monitoring of URLs for threat status changes."""
    
    def __init__(self):
        self.monitored_urls = monitoring_queue["active"]
        self.history = monitoring_queue["history"]
    
    def add_to_monitoring(self, url: str, initial_status: str, severity: str, 
                          threat_log_id: Optional[int] = None) -> Dict:
        """
        Add URL to monitoring queue.
        
        Args:
            url: URL to monitor
            initial_status: Initial threat status (Malicious/Phishing/Suspicious)
            severity: Severity level (High/Medium/Low)
            threat_log_id: Associated ThreatLog entry ID
        
        Returns:
            Dict with monitoring status
        """
        if len(self.monitored_urls) >= MONITOR_CONFIG["max_monitored_urls"]:
            logging.warning(f"Monitoring queue full ({MONITOR_CONFIG['max_monitored_urls']}), cannot add {url}")
            return {"success": False, "error": "Monitoring queue full"}
        
        if url in self.monitored_urls:
            logging.info(f"URL already being monitored: {url}")
            return {"success": False, "error": "Already monitored"}
        
        monitor_entry = {
            "url": url,
            "initial_status": initial_status,
            "current_status": initial_status,
            "severity": severity,
            "threat_log_id": threat_log_id,
            "added_at": datetime.utcnow().isoformat(),
            "last_scan": datetime.utcnow().isoformat(),
            "scan_count": 1,
            "consecutive_safe_scans": 0,
            "status_changes": 0,
            "auto_close": monitoring_queue["auto_close_enabled"],
        }
        
        self.monitored_urls[url] = monitor_entry
        self.history[url].append({
            "timestamp": datetime.utcnow().isoformat(),
            "status": initial_status,
            "severity": severity,
            "event": "monitoring_started"
        })
        
        logging.info(f"Added {url} to monitoring queue (status: {initial_status})")
        return {"success": True, "monitor_entry": monitor_entry}
    
    def remove_from_monitoring(self, url: str, reason: str = "manual_removal") -> bool:
        """Remove URL from monitoring queue."""
        if url not in self.monitored_urls:
            return False
        
        entry = self.monitored_urls[url]
        self.history[url].append({
            "timestamp": datetime.utcnow().isoformat(),
            "status": entry["current_status"],
            "event": "monitoring_stopped",
            "reason": reason
        })
        
        del self.monitored_urls[url]
        logging.info(f"Removed {url} from monitoring (reason: {reason})")
        return True
    
    async def rescan_url(self, url: str) -> Dict:
        """
        Re-scan a monitored URL and check for status changes.
        
        Returns:
            Dict with scan results and any status changes
        """
        if url not in self.monitored_urls:
            return {"error": "URL not in monitoring queue"}
        
        entry = self.monitored_urls[url]
        previous_status = entry["current_status"]
        
        try:
            # Perform fresh scan (force_refresh=True)
            result = await unified_check_url_async(url, force_refresh=True, include_ip_enrichment=False)
            new_status = result.get("final_status", "Unknown")
            new_severity = result.get("severity", "Unknown")
            
            # Update monitoring entry
            entry["last_scan"] = datetime.utcnow().isoformat()
            entry["scan_count"] += 1
            entry["current_status"] = new_status
            entry["severity"] = new_severity
            
            # Track status change
            status_changed = (previous_status != new_status)
            if status_changed:
                entry["status_changes"] += 1
                logging.warning(f"Status change detected for {url}: {previous_status} -> {new_status}")
                
                self.history[url].append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "old_status": previous_status,
                    "new_status": new_status,
                    "severity": new_severity,
                    "event": "status_changed"
                })
            
            # Track consecutive safe scans for auto-closure
            if new_status == "Safe":
                entry["consecutive_safe_scans"] += 1
            else:
                entry["consecutive_safe_scans"] = 0
            
            # Auto-close if configured and conditions met
            should_close = (
                entry["auto_close"] and
                entry["consecutive_safe_scans"] >= MONITOR_CONFIG["auto_close_after_safe_scans"]
            )
            
            if should_close:
                await self.auto_close_threat(url, entry)
                return {
                    "url": url,
                    "status_changed": status_changed,
                    "previous_status": previous_status,
                    "current_status": new_status,
                    "auto_closed": True,
                    "scan_result": result
                }
            
            # Escalation check
            if entry["status_changes"] >= MONITOR_CONFIG["escalation_threshold"]:
                logging.critical(f"ESCALATION: {url} has changed status {entry['status_changes']} times")
                self.history[url].append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "status": new_status,
                    "event": "escalation",
                    "status_changes": entry["status_changes"]
                })
            
            return {
                "url": url,
                "status_changed": status_changed,
                "previous_status": previous_status,
                "current_status": new_status,
                "consecutive_safe_scans": entry["consecutive_safe_scans"],
                "auto_closed": False,
                "scan_result": result
            }
            
        except Exception as e:
            logging.error(f"Error rescanning {url}: {e}")
            return {"error": str(e), "url": url}
    
    async def auto_close_threat(self, url: str, entry: Dict):
        """
        Automatically close a threat when it becomes safe.
        Updates ThreatLog and removes from monitoring.
        """
        try:
            threat_log_id = entry.get("threat_log_id")
            if threat_log_id:
                # Update ThreatLog status to "Resolved"
                threat_log = ThreatLog.query.get(threat_log_id)
                if threat_log:
                    threat_log.status = "Resolved"
                    threat_log.details = f"{threat_log.details}\n\nAuto-closed: {entry['consecutive_safe_scans']} consecutive safe scans"
                    db.session.commit()
                    logging.info(f"Auto-closed ThreatLog #{threat_log_id} for {url}")
            
            # Record closure in history
            self.history[url].append({
                "timestamp": datetime.utcnow().isoformat(),
                "status": "Safe",
                "event": "auto_closed",
                "consecutive_safe_scans": entry["consecutive_safe_scans"]
            })
            
            # Remove from monitoring
            self.remove_from_monitoring(url, reason="auto_closed")
            
        except Exception as e:
            logging.error(f"Error auto-closing threat for {url}: {e}")
            db.session.rollback()
    
    async def scan_all_monitored(self) -> List[Dict]:
        """
        Scan all URLs in monitoring queue.
        Called periodically by background scheduler.
        
        Returns:
            List of scan results with status changes
        """
        if not self.monitored_urls:
            logging.debug("No URLs in monitoring queue")
            return []
        
        results = []
        logging.info(f"Scanning {len(self.monitored_urls)} monitored URLs")
        
        # Process in batches of 10 to avoid overwhelming APIs
        urls = list(self.monitored_urls.keys())
        batch_size = 10
        
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            tasks = [self.rescan_url(url) for url in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, Exception):
                    logging.error(f"Batch scan error: {result}")
                    continue
                results.append(result)
            
            # Brief pause between batches
            if i + batch_size < len(urls):
                await asyncio.sleep(2)
        
        # Clean up old history
        self.cleanup_old_history()
        
        return results
    
    def cleanup_old_history(self):
        """Remove history entries older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=MONITOR_CONFIG["retention_days"])
        
        for url in list(self.history.keys()):
            self.history[url] = [
                entry for entry in self.history[url]
                if datetime.fromisoformat(entry["timestamp"]) > cutoff
            ]
            
            if not self.history[url]:
                del self.history[url]
    
    def get_monitoring_stats(self) -> Dict:
        """Get statistics about current monitoring queue."""
        stats = {
            "monitored_urls_count": len(self.monitored_urls),
            "max_capacity": MONITOR_CONFIG["max_monitored_urls"],
            "capacity_used_percent": (len(self.monitored_urls) / MONITOR_CONFIG["max_monitored_urls"]) * 100,
            "status_breakdown": defaultdict(int),
            "severity_breakdown": defaultdict(int),
            "avg_scan_count": 0,
            "urls_with_status_changes": 0,
            "urls_near_auto_close": 0,
            "escalated_urls": 0,
        }
        
        total_scans = 0
        for entry in self.monitored_urls.values():
            stats["status_breakdown"][entry["current_status"]] += 1
            stats["severity_breakdown"][entry["severity"]] += 1
            total_scans += entry["scan_count"]
            
            if entry["status_changes"] > 0:
                stats["urls_with_status_changes"] += 1
            
            if entry["consecutive_safe_scans"] >= MONITOR_CONFIG["auto_close_after_safe_scans"] - 1:
                stats["urls_near_auto_close"] += 1
            
            if entry["status_changes"] >= MONITOR_CONFIG["escalation_threshold"]:
                stats["escalated_urls"] += 1
        
        if self.monitored_urls:
            stats["avg_scan_count"] = total_scans / len(self.monitored_urls)
        
        return stats
    
    def get_url_history(self, url: str) -> List[Dict]:
        """Get complete history for a specific URL."""
        return self.history.get(url, [])
    
    def get_all_monitored(self) -> List[Dict]:
        """Get list of all monitored URLs with their status."""
        return list(self.monitored_urls.values())


# Global monitor instance
url_monitor = URLMonitor()


def get_url_monitor() -> URLMonitor:
    """Get the global URL monitor instance."""
    return url_monitor


# Convenience functions
def add_url_to_monitor(url: str, status: str, severity: str, threat_log_id: Optional[int] = None) -> Dict:
    """Add URL to monitoring queue."""
    return url_monitor.add_to_monitoring(url, status, severity, threat_log_id)


async def rescan_monitored_url(url: str) -> Dict:
    """Rescan a specific monitored URL."""
    return await url_monitor.rescan_url(url)


async def scan_all_monitored_urls() -> List[Dict]:
    """Scan all monitored URLs."""
    return await url_monitor.scan_all_monitored()


def get_monitoring_statistics() -> Dict:
    """Get monitoring queue statistics."""
    return url_monitor.get_monitoring_stats()
