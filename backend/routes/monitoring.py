"""
URL Monitoring Routes - Manage URL monitoring queue and auto-closure
"""
import logging
from flask import Blueprint, request, jsonify
from backend.extensions import limiter
from backend.services.url_monitoring_service import (
    add_url_to_monitor, rescan_monitored_url, scan_all_monitored_urls,
    get_monitoring_statistics, get_url_monitor
)
from datetime import datetime

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/api/monitoring")


@monitoring_bp.route("/stats", methods=["GET"])
def monitoring_stats():
    """
    Get URL monitoring queue statistics.
    Returns capacity, status breakdown, and performance metrics.
    """
    try:
        stats = get_monitoring_statistics()
        return jsonify({
            "status": "success",
            "stats": stats,
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logging.error(f"Error fetching monitoring stats: {e}")
        return jsonify({"error": "Failed to fetch monitoring stats"}), 500


@monitoring_bp.route("/list", methods=["GET"])
def monitoring_list():
    """
    Get list of all monitored URLs.
    Optional query params:
      - status: filter by status (Malicious/Phishing/Suspicious)
      - severity: filter by severity (High/Medium/Low)
    """
    try:
        monitor = get_url_monitor()
        monitored_urls = monitor.get_all_monitored()
        
        # Apply filters
        status_filter = request.args.get("status")
        severity_filter = request.args.get("severity")
        
        if status_filter:
            monitored_urls = [u for u in monitored_urls if u["current_status"] == status_filter]
        
        if severity_filter:
            monitored_urls = [u for u in monitored_urls if u["severity"] == severity_filter]
        
        return jsonify({
            "status": "success",
            "monitored_urls": monitored_urls,
            "count": len(monitored_urls),
            "timestamp": datetime.utcnow().isoformat()
        })
    except Exception as e:
        logging.error(f"Error fetching monitoring list: {e}")
        return jsonify({"error": "Failed to fetch monitoring list"}), 500


@monitoring_bp.route("/add", methods=["POST"])
@limiter.limit("10 per minute")
def add_to_monitoring():
    """
    Manually add URL to monitoring queue.
    Request body: {"url": "...", "status": "...", "severity": "..."}
    """
    try:
        data = request.get_json() or {}
        url = data.get("url")
        status = data.get("status", "Suspicious")
        severity = data.get("severity", "Medium")
        
        if not url:
            return jsonify({"error": "URL is required"}), 400
        
        result = add_url_to_monitor(url, status, severity)
        
        if result.get("success"):
            return jsonify({
                "status": "success",
                "message": f"Added {url} to monitoring queue",
                "monitor_entry": result["monitor_entry"]
            })
        else:
            return jsonify({
                "status": "error",
                "error": result.get("error", "Failed to add to monitoring")
            }), 400
            
    except Exception as e:
        logging.error(f"Error adding to monitoring: {e}")
        return jsonify({"error": "Failed to add to monitoring"}), 500


@monitoring_bp.route("/remove/<path:url>", methods=["DELETE"])
@limiter.limit("20 per minute")
def remove_from_monitoring(url):
    """
    Remove URL from monitoring queue.
    """
    try:
        monitor = get_url_monitor()
        success = monitor.remove_from_monitoring(url, reason="manual_removal")
        
        if success:
            return jsonify({
                "status": "success",
                "message": f"Removed {url} from monitoring queue"
            })
        else:
            return jsonify({
                "status": "error",
                "error": "URL not found in monitoring queue"
            }), 404
            
    except Exception as e:
        logging.error(f"Error removing from monitoring: {e}")
        return jsonify({"error": "Failed to remove from monitoring"}), 500


@monitoring_bp.route("/rescan/<path:url>", methods=["POST"])
@limiter.limit("5 per minute")
async def rescan_monitored(url):
    """
    Trigger immediate rescan of monitored URL.
    """
    try:
        result = await rescan_monitored_url(url)
        
        if "error" in result:
            return jsonify({
                "status": "error",
                "error": result["error"]
            }), 400
        
        return jsonify({
            "status": "success",
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error rescanning URL: {e}")
        return jsonify({"error": "Failed to rescan URL"}), 500


@monitoring_bp.route("/rescan_all", methods=["POST"])
@limiter.limit("1 per minute")
async def rescan_all():
    """
    Trigger rescan of all monitored URLs.
    WARNING: This can be resource-intensive.
    """
    try:
        results = await scan_all_monitored_urls()
        
        status_changes = [r for r in results if r.get("status_changed")]
        auto_closed = [r for r in results if r.get("auto_closed")]
        
        return jsonify({
            "status": "success",
            "scanned_count": len(results),
            "status_changes_count": len(status_changes),
            "auto_closed_count": len(auto_closed),
            "status_changes": status_changes,
            "auto_closed": auto_closed,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error rescanning all URLs: {e}")
        return jsonify({"error": "Failed to rescan all URLs"}), 500


@monitoring_bp.route("/history/<path:url>", methods=["GET"])
def monitoring_history(url):
    """
    Get complete monitoring history for a specific URL.
    """
    try:
        monitor = get_url_monitor()
        history = monitor.get_url_history(url)
        
        if not history:
            return jsonify({
                "status": "success",
                "message": "No history found for this URL",
                "history": []
            })
        
        return jsonify({
            "status": "success",
            "url": url,
            "history": history,
            "event_count": len(history)
        })
        
    except Exception as e:
        logging.error(f"Error fetching monitoring history: {e}")
        return jsonify({"error": "Failed to fetch history"}), 500


@monitoring_bp.route("/batch_close", methods=["POST"])
@limiter.limit("5 per minute")
def batch_close():
    """
    Manually close multiple threats.
    Request body: {"urls": ["url1", "url2", ...], "reason": "false_positive"}
    """
    try:
        data = request.get_json() or {}
        urls = data.get("urls", [])
        reason = data.get("reason", "manual_closure")
        
        if not urls:
            return jsonify({"error": "URLs list is required"}), 400
        
        monitor = get_url_monitor()
        results = {
            "closed": [],
            "not_found": [],
            "errors": []
        }
        
        for url in urls:
            try:
                if monitor.remove_from_monitoring(url, reason=reason):
                    results["closed"].append(url)
                else:
                    results["not_found"].append(url)
            except Exception as e:
                results["errors"].append({"url": url, "error": str(e)})
        
        return jsonify({
            "status": "success",
            "results": results,
            "closed_count": len(results["closed"]),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Error in batch close: {e}")
        return jsonify({"error": "Failed to process batch close"}), 500
