import asyncio
from typing import Optional, Tuple

from falsealarm.core.engine import AsyncEngine

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cfduid", "cf_clearance"]
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "server: akamai"],
        "cookies": ["ak_bmsc"]
    },
    "imperva": {
        "headers": ["x-iinfo", "server: imperva"],
        "cookies": ["incap_ses", "visid_incap"]
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amzn-trace-id"],
        "cookies": ["awsalbcors", "awsalb"]
    }
}

async def detect_waf(target: str, engine: AsyncEngine) -> Tuple[bool, Optional[str]]:
    """
    Sends a few benign requests to detect WAF/CDN presence.
    Returns (waf_detected, waf_name).
    """
    if not target.startswith("http"):
        target = f"http://{target}"

    # Send a normal request and a slightly "suspicious" (but benign) request to trigger WAF
    tasks = [
        engine.get(target),
        engine.get(f"{target}/?id=1%27%20OR%20%271%27=%271")
    ]

    responses = await asyncio.gather(*tasks)

    for resp in responses:
        if resp.get("error"):
            continue

        headers = {k.lower(): v.lower() for k, v in resp.get("headers", {}).items()}
        header_keys = set(headers.keys())

        # Build flat list of header strings for substring matching (e.g. "server: cloudflare")
        header_strings = [f"{k}: {v}" for k, v in headers.items()]

        # Extract cookie names
        cookie_header = headers.get("set-cookie", "")
        cookie_names = [c.split("=")[0].strip().lower() for c in cookie_header.split(";") if "=" in c]

        for waf_name, sigs in WAF_SIGNATURES.items():
            # Check headers
            for h_sig in sigs.get("headers", []):
                if ":" in h_sig:
                    if any(h_sig in hs for hs in header_strings):
                        return True, waf_name
                else:
                    if h_sig in header_keys:
                        return True, waf_name

            # Check cookies
            for c_sig in sigs.get("cookies", []):
                if c_sig in cookie_names:
                    return True, waf_name

        # Check for generic WAF block status codes (403/406) on the suspicious request
        if resp.get("status") in [403, 406] and "%27" in resp.get("url", ""):
            # If normal request was 200, but suspicious is 403, it's likely a generic WAF
            normal_status = responses[0].get("status")
            if normal_status in [200, 301, 302]:
                return True, "generic_waf"

    return False, None
