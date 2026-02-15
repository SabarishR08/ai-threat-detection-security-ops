#backend/services/rdap_service.py

import httpx
import asyncio

async def fetch_rdap(domain: str):
    """
    Free WHOIS/Domain registration lookup using RDAP.
    No API key needed.
    """
    rdap_url = f"https://rdap.org/domain/{domain}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(rdap_url)
            if response.status_code == 200:
                return {
                    "success": True,
                    "data": response.json()
                }
            else:
                return {
                    "success": False,
                    "error": f"RDAP lookup failed: HTTP {response.status_code}"
                }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def rdap_lookup(domain: str):
    """
    Synchronous wrapper for RDAP lookup so Flask can call it directly.
    """
    try:
        return asyncio.run(fetch_rdap(domain))
    except RuntimeError:
        # If already inside an event loop (e.g. socket.io)
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(fetch_rdap(domain))
