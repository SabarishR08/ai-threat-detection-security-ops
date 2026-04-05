# soc_analyzer.py
import re
import json
import os
import asyncio
from datetime import datetime
from dotenv import load_dotenv
import httpx
from google import generativeai as genai  # REST only

load_dotenv()

# ----------------------------
# Gemini Setup
# ----------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or "YOUR_GEMINI_API_KEY_HERE"

genai.configure(api_key=GEMINI_API_KEY)


# ----------------------------
# Utility: Extract IPs
# ----------------------------
def extract_ips(log_text):
    return list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text)))


# ----------------------------
# Rule-based Analysis
# ----------------------------
def rule_based_analysis(log_text):
    threats = []

    failed_logins = len(re.findall(r"failed password|authentication failure", log_text, re.I))
    if failed_logins > 5:
        threats.append({"type": "Bruteforce Attack", "count": failed_logins, "severity": "High"})

    if "nmap" in log_text.lower() or "port scan" in log_text.lower():
        threats.append({"type": "Port Scanning", "severity": "Medium"})

    if "sudo" in log_text.lower() and "failed" in log_text.lower():
        threats.append({"type": "Unauthorized sudo attempt", "severity": "High"})

    if "base64" in log_text.lower():
        threats.append({"type": "Encoded (possibly malicious) payload detected", "severity": "Medium"})

    return threats


# ----------------------------
# Async REST call to Gemini
# ----------------------------
async def ai_gemini_analysis_rest(log_text):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"

    prompt = f"""
You are a Security Operations Center (SOC) AI.

Analyze the following logs and identify:
- Threat summary
- Suspicious IPs
- Attack indicators
- Severity level (Low / Medium / High / Critical)
- Recommended mitigation steps

Respond ONLY in structured JSON format with fields:
summary, severity, threats (list), recommendations (list)

Logs to analyze:
{log_text}
"""

    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    async with httpx.AsyncClient(timeout=60) as client:
        max_retries = 3
        delay = 1
        for attempt in range(max_retries):
            try:
                response = await client.post(url, json=payload, headers={"Content-Type": "application/json"})
                # Handle rate limiting explicitly
                if response.status_code == 429:
                    return {
                        "summary": "AI enrichment unavailable: rate limited",
                        "severity": "Unknown",
                        "threats": [],
                        "recommendations": ["AI service rate limited (429). Using rule-based analysis only."],
                        "error": "rate_limited"
                    }

                if not response.is_success:
                    # Surface server message when possible
                    try:
                        body = response.json()
                        message = body.get('error') or body.get('message') or response.text
                    except Exception as e:
                        logging.debug(f"Failed to parse AI error response: {e}")
                        message = response.text
                    return {
                        "summary": "AI enrichment failed",
                        "severity": "Unknown",
                        "threats": [],
                        "recommendations": [f"AI service error: {message}"],
                        "error": "ai_error"
                    }

                text_output = response.json()["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = text_output.strip().replace("```json", "").replace("```", "").strip()
                return json.loads(cleaned)
            except Exception as e:
                if attempt < max_retries - 1:
                    await asyncio.sleep(delay)
                    delay *= 2
                    continue
                return {
                    "summary": "REST API analysis failed",
                    "severity": "Unknown",
                    "threats": [],
                    "recommendations": [str(e)]
                }


# ----------------------------
# Gemini Wrapper (SDK first, REST fallback)
# ----------------------------
def ai_gemini_analysis(log_text):
    # REST (sync wrapper)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(ai_gemini_analysis_rest(log_text))
    except Exception as e:
        return {
            "summary": f"AI analysis unavailable: {e}",
            "severity": "Unknown",
            "threats": [],
            "recommendations": ["AI analysis unavailable - using rule-based findings only"],
            "error": "ai_unavailable"
        }


# ----------------------------
# Main Analyzer Function
# ----------------------------
def analyze_logs(log_text):
    if not log_text or len(log_text.strip()) == 0:
        return {"error": "No logs provided"}
    ips = extract_ips(log_text)
    rules = rule_based_analysis(log_text)

    # Determine rule-derived severity
    rule_severity = "Unknown"
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    max_score = 0
    for r in rules:
        s = r.get('severity', 'Low')
        score = severity_order.get(s, 1)
        if score > max_score:
            max_score = score
            rule_severity = s

    # AI enrichment (best-effort). It must NOT override rule-based HIGH/Critical findings.
    ai_result = ai_gemini_analysis(log_text)

    # Merge final severity: rules take precedence if >= Medium
    ai_sev = ai_result.get('severity', 'Unknown') if isinstance(ai_result, dict) else 'Unknown'
    final_severity = ai_sev
    if rule_severity != 'Unknown':
        # If rules found High/Critical, honor that
        if rule_severity in ('High', 'Critical'):
            final_severity = rule_severity
        else:
            # prefer the higher severity between rule and ai
            final_severity = rule_severity if severity_order.get(rule_severity,0) >= severity_order.get(ai_sev,0) else ai_sev

    # Combine threat lists (dedupe by type + description)
    combined_threats = []
    seen = set()
    for t in rules:
        key = (t.get('type'), str(t.get('count','')))
        if key not in seen:
            combined_threats.append(t)
            seen.add(key)

    # AI threats may be a list of dicts or strings
    ai_threats = ai_result.get('threats') if isinstance(ai_result, dict) else []
    if isinstance(ai_threats, list):
        for at in ai_threats:
            key = None
            if isinstance(at, dict):
                key = (at.get('type'), at.get('description',''))
            else:
                key = (str(at), '')
            if key not in seen:
                combined_threats.append(at)
                seen.add(key)

    return {
        "ips_found": ips,
        "rule_based_findings": rules,
        "ai_analysis": ai_result,
        "final_severity": final_severity,
        "final_threats": combined_threats,
        "timestamp": datetime.now().isoformat()
    }
