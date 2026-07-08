import httpx
import asyncio
from config import GEMINI_API_KEY, SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY, GEMINI_MODELS
from models import LinkResult


async def check_google_safe_browsing(urls: list[str]) -> dict[str, str]:
    if not SAFE_BROWSING_API_KEY:
        return {}

    results = {}
    payload = {
        "client": {"clientId": "link-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}",
                json=payload,
            )
            res.raise_for_status()
            data = res.json()
            for match in data.get("matches", []):
                url = match.get("threat", {}).get("url", "")
                threat = match.get("threatType", "UNKNOWN")
                results[url] = threat
    except Exception:
        pass

    return results


async def check_virustotal(url: str) -> tuple[bool, str]:
    """
    Check URL against VirusTotal API.
    
    Args:
        url: URL to check
        
    Returns:
        Tuple of (is_malicious, summary)
    """
    if not VIRUSTOTAL_API_KEY:
        return False, ""

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            submit_res = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
            )
            submit_res.raise_for_status()
            analysis_id = submit_res.json()["data"]["id"]

            for _ in range(3):
                await asyncio.sleep(2)
                report_res = await client.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                )
                report_res.raise_for_status()
                report = report_res.json()
                status = report["data"]["attributes"].get("status")
                if status == "completed":
                    stats = report["data"]["attributes"]["stats"]
                    malicious  = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1
                    if malicious > 0 or suspicious > 1:
                        return True, f"{malicious} malicious, {suspicious} suspicious out of {total} engines"
                    return False, f"Clean ({total} engines checked)"

            return False, "Analysis pending"
    except Exception:
        return False, ""


async def call_gemini_rest(model: str, prompt: str) -> str:
    """
    Call Gemini API with a prompt.
    
    Args:
        model: Model ID to use
        prompt: Prompt text
        
    Returns:
        Model response text
    """
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 1000, "temperature": 0.2},
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.post(url, json=payload)
        res.raise_for_status()
        data = res.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


async def get_ai_analysis(results: list[LinkResult]) -> str | None:
    """
    Generate AI analysis of link checking results using Gemini.
    
    Args:
        results: List of LinkResult objects
        
    Returns:
        AI analysis text, or None if unavailable
    """
    summary_lines = []
    for r in results:
        phishing_info = ""
        if r.phishing:
            phishing_info = (
                f" | Risk: {r.phishing.risk_level}"
                f" | Score: {r.phishing.phishing_score}"
                f" | GSB Threat: {r.phishing.safe_browsing_threat or 'none'}"
                f" | Heuristic flags: {', '.join(r.phishing.heuristic_flags) or 'none'}"
                f" | VirusTotal: {r.phishing.virustotal_summary or 'not checked'}"
            )
        summary_lines.append(
            f"URL: {r.url} | HTTP Status: {r.status_code or 'N/A'} | Alive: {r.is_alive}"
            f" | Response: {r.response_time_ms}ms | HTTP Error: {r.error or 'None'}"
            f"{phishing_info}"
        )

    prompt = f"""You are a cybersecurity analyst specializing in phishing and malicious URL detection.

CRITICAL RULE: HTTP 200 OK does NOT mean a URL is safe. Phishing sites are live, working websites
that deliberately return 200 OK. Never use HTTP status to infer safety.

Analyze the following URLs using ALL available signals (heuristic flags, risk score, Safe Browsing, VirusTotal):

{chr(10).join(summary_lines)}

For each URL, assess:
1. Is it likely a phishing/malicious site? Why?
2. What specific lure or attack vector does it use (free storage, brand impersonation, crypto scam, referral recruitment, urgency, etc.)?
3. What do the heuristic flags and score indicate?
4. Overall verdict: SAFE / SUSPICIOUS / DANGEROUS

Pay special attention to:
- Free giveaway / storage lures (e.g. "51gb-free", "labor-day-free")
- Random-looking domains on high-risk TLDs (.top, .xyz, .online, .cash, .io, etc.)
- Crypto/investment scam domains (coin, wallet, token, sbc, etc.)
- Registration or sign-up forms on unknown domains (registration_form.php, signup.php, etc.)
- Referral/affiliate links (?link=, ?ref=, ?aff=) used to recruit victims
- Redirect chains between two unknown domains
- Numeric campaign tracking in query params and fragments
- Any domain that is NOT a well-known brand but contains gift/prize/free/storage/crypto keywords

End with a concise summary and a prioritized list of URLs that need immediate action.
Be direct and specific. Avoid vague language."""

    last_error = ""
    for model in GEMINI_MODELS:
        try:
            return await call_gemini_rest(model, prompt)
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (404, 429, 503):
                last_error = f"{e.response.status_code} on {model}"
                continue
            return None
        except Exception as e:
            last_error = str(e)
            continue
    return None
