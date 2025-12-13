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
                response.raise_for_status()
                text_output = response.json()["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = text_output.strip().replace("```json","").replace("```","").strip()
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
            "summary": f"Analysis failed: {e}",
            "severity": "Unknown",
            "threats": [],
            "recommendations": []
        }


# ----------------------------
# Main Analyzer Function
# ----------------------------
def analyze_logs(log_text):
    if not log_text or len(log_text.strip()) == 0:
        return {"error": "No logs provided"}

    return {
        "ips_found": extract_ips(log_text),
        "rule_based_findings": rule_based_analysis(log_text),
        "ai_analysis": ai_gemini_analysis(log_text),
        "timestamp": datetime.now().isoformat()
    }
