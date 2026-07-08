import re
import asyncio
from fastapi import HTTPException, Request
from models import LinkCheckRequest, BulkTextRequest, LinkResult
from security import sanitize_url
from external_services import check_google_safe_browsing, get_ai_analysis
from url_checker import check_single_link
from config import MAX_URLS_PER_REQUEST, CHECK_LINKS_RATE_LIMIT, EXTRACT_LINKS_RATE_LIMIT


def setup_routes(app, limiter):
    @app.post("/check-links", response_model=dict)
    @limiter.limit(CHECK_LINKS_RATE_LIMIT)
    async def check_links(request: Request, body: LinkCheckRequest):
        sanitized = []
        errors = []
        for raw_url in body.urls:
            try:
                sanitized.append(sanitize_url(raw_url))
            except ValueError as e:
                errors.append({"url": raw_url[:100], "error": str(e)})

        if not sanitized:
            raise HTTPException(status_code=400, detail="No valid URLs provided")

        safe_browsing_hits = await check_google_safe_browsing(sanitized)

        tasks = [check_single_link(url, safe_browsing_hits) for url in sanitized]
        results: list[LinkResult] = list(await asyncio.gather(*tasks))

        ai_summary = await get_ai_analysis(results)

        alive_count      = sum(1 for r in results if r.is_alive)
        dangerous_count  = sum(1 for r in results if r.phishing and r.phishing.risk_level == "dangerous")
        suspicious_count = sum(1 for r in results if r.phishing and r.phishing.risk_level == "suspicious")

        return {
            "results": [r.dict() for r in results],
            "skipped": errors,
            "summary": {
                "total": len(results),
                "alive": alive_count,
                "dead": len(results) - alive_count,
                "dangerous": dangerous_count,
                "suspicious": suspicious_count,
                "safe": len(results) - dangerous_count - suspicious_count,
                "ai_analysis": ai_summary,
            },
        }

    @app.post("/extract-links", response_model=dict)
    @limiter.limit(EXTRACT_LINKS_RATE_LIMIT)
    async def extract_links(request: Request, body: BulkTextRequest):
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        found = re.findall(url_pattern, body.text)
        bare_pattern = r'\b(?:www\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'
        bare = re.findall(bare_pattern, body.text)
        raw_urls = list(dict.fromkeys(found + ["https://" + b for b in bare]))

        clean = []
        for u in raw_urls[:MAX_URLS_PER_REQUEST]:
            try:
                clean.append(sanitize_url(u))
            except ValueError:
                pass

        return {"urls": clean, "count": len(clean)}

    @app.get("/health")
    async def health():
        """
        Health check endpoint.
        
        Returns:
            Status and available features
        """
        from config import GEMINI_API_KEY, SAFE_BROWSING_API_KEY, VIRUSTOTAL_API_KEY
        from datetime import datetime
        
        return {
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "features": {
                "google_safe_browsing": bool(SAFE_BROWSING_API_KEY),
                "virustotal": bool(VIRUSTOTAL_API_KEY),
                "heuristics": True,
                "ai_analysis": bool(GEMINI_API_KEY),
            },
        }
