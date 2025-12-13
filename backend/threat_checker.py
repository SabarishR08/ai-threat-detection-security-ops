"""
Short-circuit threat checker: PhishTank -> VirusTotal -> Google Safe Browsing.
Stops on first malicious/phishing detection and returns structured result.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict

import requests

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GSB_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY", "")

VT_URL_SUBMIT = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSES = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"
GSB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


# ----------------------------
# Helpers
# ----------------------------

def _safe_request(method: str, url: str, **kwargs) -> requests.Response | None:
    try:
        resp = requests.request(method, url, timeout=10, **kwargs)
        resp.raise_for_status()
        return resp
    except Exception as exc:
        logging.warning(f"Request failed for {url}: {exc}")
        return None


# ----------------------------
# VirusTotal
# ----------------------------

def check_virustotal(url: str) -> Dict[str, Any]:
    """Check URL on VirusTotal v3; return counts for malicious/suspicious."""
    headers = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}
    result: Dict[str, Any] = {"malicious": 0, "suspicious": 0, "raw": {}}

    if not headers:
        return result

    # Submit URL for analysis
    submit_resp = _safe_request("POST", VT_URL_SUBMIT, headers=headers, data={"url": url})
    if not submit_resp:
        return result

    try:
        submit_data = submit_resp.json()
        analysis_id = submit_data.get("data", {}).get("id")
    except Exception:
        return result

    if not analysis_id:
        return result

    # Fetch analysis result
    analysis_url = VT_ANALYSES.format(analysis_id=analysis_id)
    analysis_resp = _safe_request("GET", analysis_url, headers=headers)
    if not analysis_resp:
        return result

    try:
        analysis_data = analysis_resp.json()
        stats = analysis_data.get("data", {}).get("attributes", {}).get("stats", {})
        result["malicious"] = int(stats.get("malicious", 0))
        result["suspicious"] = int(stats.get("suspicious", 0))
        result["raw"] = analysis_data
    except Exception:
        # Keep defaults on parse errors
        pass

    return result


# ----------------------------
# Google Safe Browsing v5
# ----------------------------

def check_gsb(url: str) -> Dict[str, Any]:
    """Check URL with Google Safe Browsing v5."""
    if not GSB_API_KEY:
        return {"threat": "SAFE", "raw": {}}

    payload = {
        "client": {"clientId": "threat-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "THREAT_TYPE_UNSPECIFIED",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    params = {"key": GSB_API_KEY}
    resp = _safe_request("POST", GSB_URL, params=params, json=payload)
    if not resp:
        return {"threat": "SAFE", "raw": {}}

    try:
        data = resp.json()
        matches = data.get("threatMatches") or data.get("matches") or []
        if not matches:
            return {"threat": "SAFE", "raw": data}
        # Take the first threat type for decision purposes
        threat_type = matches[0].get("threatType", "UNKNOWN")
        return {"threat": threat_type, "raw": data}
    except Exception:
        return {"threat": "SAFE", "raw": {}}


# ----------------------------
# PhishTank
# ----------------------------

def check_phishtank(url: str) -> Dict[str, Any]:
    """Check URL with PhishTank."""
    form_data = {
        "url": url,
        "format": "json",
    }
    if PHISHTANK_API_KEY:
        form_data["app_key"] = PHISHTANK_API_KEY

    resp = _safe_request("POST", PHISHTANK_URL, data=form_data)
    if not resp:
        return {"status": "safe", "raw": {}}

    try:
        data = resp.json()
        results = data.get("results") or data
        verified = bool(results.get("verified"))
        in_db = bool(results.get("in_database"))
        status = "phishing" if (verified and in_db) else "safe"
        return {"status": status, "raw": data}
    except Exception:
        return {"status": "safe", "raw": {}}


# ----------------------------
# Short-circuit pipeline
# ----------------------------

def check_url(url: str) -> Dict[str, Any]:
    """Run PhishTank -> VirusTotal -> GSB with short-circuit stop on detection."""
    details: Dict[str, Any] = {
        "phishtank": {},
        "virustotal": {},
        "gsb": {},
    }

    # 1) PhishTank first for demo-friendly phishing hits
    pt = check_phishtank(url)
    details["phishtank"] = pt
    if pt.get("status") == "phishing":
        return {
            "final_status": "phishing",
            "detected_by": "PhishTank",
            "details": details,
        }

    # 2) VirusTotal
    vt = check_virustotal(url)
    details["virustotal"] = vt
    if vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0:
        return {
            "final_status": "malicious",
            "detected_by": "VirusTotal",
            "details": details,
        }

    # 3) Google Safe Browsing
    gsb = check_gsb(url)
    details["gsb"] = gsb
    threat = str(gsb.get("threat", "SAFE")).upper()
    if "SOCIAL_ENGINEERING" in threat:
        return {
            "final_status": "phishing",
            "detected_by": "GSB",
            "details": details,
        }
    if "MALWARE" in threat and threat != "SAFE":
        return {
            "final_status": "malicious",
            "detected_by": "GSB",
            "details": details,
        }

    # 4) All clean
    return {
        "final_status": "clean",
        "detected_by": "None",
        "details": details,
    }


__all__ = [
    "check_virustotal",
    "check_gsb",
    "check_phishtank",
    "check_url",
]
