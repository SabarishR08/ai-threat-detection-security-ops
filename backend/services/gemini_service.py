# backend/services/gemini_service.py

import os
import json
import asyncio
import httpx
import re
from dotenv import load_dotenv
try:
    import google.generativeai as genai  # type: ignore
    _gemini_lib_available = True
except Exception:
    genai = None
    _gemini_lib_available = False

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

gemini_initialized = False
gemini_client = None

# ----------------------------
# Initialize Gemini SDK Once
# ----------------------------
if _gemini_lib_available and GEMINI_API_KEY:
    # Configure API key for REST usage only
    genai.configure(api_key=GEMINI_API_KEY)
else:
    print("WARNING: Gemini not fully configured (missing library or API key). AI fusion will return Unknown.")


# ============================================================
#  Async REST Fallback (FAST + SHORT REASON)
# ============================================================
async def classify_email_rest(content, reason_max_chars=200):

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    )

    # 🔥 Short, fast, efficient prompt
    prompt = f"""
    Classify this email into: Safe, Spam, Scam, Phishing, Social Engineering, Marketing.

    Output ONLY JSON:
    {{
        "category": "...",
        "reason": "1 short sentence"
    }}

    Email:
    {content}
    """

    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }

    async with httpx.AsyncClient(timeout=12) as client:
        for attempt in range(3):
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()

                text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = text.replace("```json", "").replace("```", "").strip()

                result = json.loads(cleaned)

                # Trim reason
                if "reason" in result and len(result["reason"]) > reason_max_chars:
                    result["reason"] = result["reason"][:reason_max_chars] + "..."

                return result

            except httpx.HTTPStatusError as e:
                # Handle rate limiting - use threat detection fallback
                if e.response.status_code == 429:
                    # Rate limited - fall back to threat detection
                    try:
                        fallback_result = await detect_phishing_in_email(content)
                        return fallback_result
                    except Exception:
                        return {
                            "category": "Unknown",
                            "reason": "Service temporarily unavailable. Please try again later."
                        }
                return {
                    "category": "Unknown",
                    "reason": f"API error: {e.response.status_code}. Please try again later."
                }
            except Exception as e:
                error_msg = str(e)
                # Mask API key if accidentally exposed
                error_msg = error_msg.split('?key=')[0] if '?key=' in error_msg else error_msg
                
                if attempt < 2:
                    await asyncio.sleep(1 * (2 ** attempt))
                    continue
                return {
                    "category": "Unknown",
                    "reason": "Unable to analyze email. Service temporarily unavailable."
                }


# ============================================================
#  MAIN ENTRY POINT (sync function, SAFE)
# ============================================================
def classify_email_nlp(content):
    """
    Synchronous wrapper for backward compatibility.

    SAFE:
    - Works inside running event loop (asyncio.get_running_loop)
    - Works in normal sync execution
    - Never throws: 'event loop is already running'
    """

    global gemini_initialized, gemini_client

    # ---------------------------------------------------------
    # REST FALLBACK (safe for async + sync)
    # ---------------------------------------------------------
    try:
        loop = asyncio.get_running_loop()

        # We ARE inside an event loop → must use thread-safe submission
        future = asyncio.run_coroutine_threadsafe(
            classify_email_rest(content),
            loop
        )
        return future.result()

    except RuntimeError:
        # No running loop → safe to run normally
        return asyncio.run(classify_email_rest(content))


# ============================================================
#  Threat Detection Fallback (when Gemini is rate-limited)
# ============================================================
async def detect_phishing_in_email(content: str) -> dict:
    """
    Fallback: Extract URLs and check them against PhishTank & GSB
    when Gemini is rate-limited.
    """
    # Extract URLs from email content
    url_pattern = r'https?://[^\s\)\]\}]+'
    urls = re.findall(url_pattern, content)
    
    if not urls:
        # No URLs = likely safe
        return {
            "category": "Safe",
            "reason": "No suspicious URLs detected"
        }
    
    # Import threat detection services
    from services.phishtank_service import check_url_phishtank
    from services.google_safebrowsing_service import check_url_safebrowsing
    
    phishing_count = 0
    suspicious_count = 0
    
    # Check each URL
    for url in urls[:5]:  # Check max 5 URLs to avoid timeouts
        try:
            # Check PhishTank
            pt_result = await asyncio.wait_for(
                check_url_phishtank(url),
                timeout=3
            )
            pt_status = str(pt_result.get("status", "")).lower()
            
            if pt_status == "phishing":
                phishing_count += 1
            elif pt_status == "suspicious":
                suspicious_count += 1
            
            # Check Google Safe Browsing
            gsb_result = await asyncio.wait_for(
                check_url_safebrowsing(url),
                timeout=3
            )
            gsb_status = str(gsb_result.get("status", "")).upper()
            
            if "MALWARE" in gsb_status or "SOCIAL_ENGINEERING" in gsb_status:
                phishing_count += 1
            
        except Exception:
            pass  # Skip on error
    
    # Determine category based on findings
    if phishing_count > 0:
        return {
            "category": "Phishing",
            "reason": f"Detected {phishing_count} phishing URLs via threat intelligence"
        }
    elif suspicious_count > 0:
        return {
            "category": "Suspicious",
            "reason": f"Found {suspicious_count} suspicious URLs"
        }
    else:
        return {
            "category": "Safe",
            "reason": "URLs checked against threat databases"
        }


# ============================================================
#  Threat Fusion (Unified TI → Gemini)
# ============================================================

FUSION_MODEL = "gemini-2.5-flash"


def _fusion_prompt(threat_payload: dict) -> str:
    return f'''
You are a cybersecurity threat analyst. Given multi-source threat intel for a URL, produce a STRICT JSON verdict.

Return ONLY JSON (no prose). Fields:
{{
  "ai_final_verdict": "Malicious|Phishing|Suspicious|Safe|Unknown",
  "confidence": 0-1 float,
  "reasoning": "one concise sentence",
  "severity_score": 0-10 float
}}

Evidence:
{json.dumps(threat_payload, indent=2)[:6000]}
'''


async def analyze_threat_fusion_async(threat_payload: dict) -> dict:
    if not _gemini_lib_available:
        return {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": "gemini library not installed",
            "severity_score": 0,
            "error": "missing_library",
        }

    if not GEMINI_API_KEY:
        return {
            "ai_final_verdict": "Unknown",
            "confidence": 0.0,
            "reasoning": "GEMINI_API_KEY missing",
            "severity_score": 0,
            "error": "missing_api_key",
        }

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{FUSION_MODEL}:generateContent?key={GEMINI_API_KEY}"
    )

    prompt = _fusion_prompt(threat_payload)
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            cleaned = text.replace("```json", "").replace("```", "").strip()
            data = json.loads(cleaned)
            verdict = str(data.get("ai_final_verdict", "Unknown"))
            confidence = float(data.get("confidence", 0) or 0)
            severity_score = float(data.get("severity_score", 0) or 0)
            reasoning = data.get("reasoning", "")
            return {
                "ai_final_verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
                "severity_score": severity_score,
            }
        except httpx.HTTPStatusError as e:
            # Handle rate limiting and other HTTP errors
            if e.response.status_code == 429:
                # Rate limited - use threat detection fallback
                try:
                    fallback_result = await detect_phishing_in_email(content)
                    return fallback_result
                except Exception:
                    return {
                        "ai_final_verdict": "Unknown",
                        "confidence": 0.0,
                        "reasoning": "Service temporarily unavailable. Please try again later.",
                        "severity_score": 0,
                        "error": "rate_limited",
                    }
            return {
                "ai_final_verdict": "Unknown",
                "confidence": 0.0,
                "reasoning": f"Service error. Please try again later.",
                "severity_score": 0,
                "error": "api_error",
            }
        except Exception as e:
            # Mask API key if exposed in error
            error_msg = str(e)
            error_msg = error_msg.split('?key=')[0] if '?key=' in error_msg else error_msg
            
            return {
                "ai_final_verdict": "Unknown",
                "confidence": 0.0,
                "reasoning": "Unable to analyze threats. Service temporarily unavailable.",
                "severity_score": 0,
                "error": "gemini_error",
            }


def analyze_threat_fusion(threat_payload: dict) -> dict:
    """Sync-safe wrapper for the fusion call."""
    try:
        loop = asyncio.get_running_loop()
        fut = asyncio.run_coroutine_threadsafe(
            analyze_threat_fusion_async(threat_payload),
            loop,
        )
        return fut.result()
    except RuntimeError:
        return asyncio.run(analyze_threat_fusion_async(threat_payload))
