from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import asyncio
import re
import os
import ipaddress
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(title="Link Checker API", docs_url=None, redoc_url=None)  
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set. Add it to your backend/.env file.")

GEMINI_MODELS = ["gemini-2.0-flash-lite", "gemini-2.0-flash", "gemini-1.5-flash"]

MAX_URL_LENGTH = 2048
MAX_URLS_PER_REQUEST = 20
MAX_BULK_TEXT_LENGTH = 50_000

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      
    ipaddress.ip_network("10.0.0.0/8"),        
    ipaddress.ip_network("172.16.0.0/12"),     
    ipaddress.ip_network("192.168.0.0/16"),    
    ipaddress.ip_network("169.254.0.0/16"),    
    ipaddress.ip_network("::1/128"),           
    ipaddress.ip_network("fc00::/7"),          
    ipaddress.ip_network("0.0.0.0/8"),         
]

def sanitize_url(raw: str) -> str:
    """Strip whitespace, normalize scheme, enforce length."""
    url = raw.strip()
    if not url:
        raise ValueError("Empty URL")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL exceeds {MAX_URL_LENGTH} characters")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are allowed")
    if not parsed.netloc:
        raise ValueError("URL has no valid host")
    if re.search(r"(javascript|data|file|vbscript):", url, re.IGNORECASE):
        raise ValueError("Dangerous URL scheme detected")
    if re.search(r"[\x00-\x1f\x7f]", url):
        raise ValueError("URL contains invalid characters")
    return url


def is_private_ip(hostname: str) -> bool:
    """Block SSRF attempts to internal IPs."""
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        blocked_hosts = {"localhost", "local", "internal", "metadata.google.internal"}
        return hostname.lower() in blocked_hosts


def is_safe_url(url: str) -> tuple[bool, str]:
    """Full safety check on a URL before fetching."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if is_private_ip(hostname):
            return False, "Blocked: URL points to internal/private network"
        if hostname in ("169.254.169.254", "metadata.google.internal", "metadata.azure.com"):
            return False, "Blocked: Cloud metadata endpoint"
        return True, ""
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"

class LinkCheckRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError("At least one URL is required")
        if len(v) > MAX_URLS_PER_REQUEST:
            raise ValueError(f"Maximum {MAX_URLS_PER_REQUEST} URLs per request")
        return v


class BulkTextRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def validate_text(cls, v):
        if len(v) > MAX_BULK_TEXT_LENGTH:
            raise ValueError(f"Text exceeds {MAX_BULK_TEXT_LENGTH} character limit")
        return v


class LinkResult(BaseModel):
    url: str
    status_code: int | None
    is_alive: bool
    response_time_ms: float | None
    redirect_url: str | None
    error: str | None
    ai_analysis: str | None
    checked_at: str


async def check_single_link(url: str) -> LinkResult:
    safe, reason = is_safe_url(url)
    if not safe:
        return LinkResult(url=url, status_code=None, is_alive=False, response_time_ms=None,
                          redirect_url=None, error=reason, ai_analysis=None,
                          checked_at=datetime.utcnow().isoformat())

    start = asyncio.get_event_loop().time()
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            max_redirects=5,
        ) as client:
            response = await client.get(
                url,
                headers={"User-Agent": "LinkChecker/1.0"},
            )
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            final_url = str(response.url)
            redirect_url = final_url if final_url != url else None

            if redirect_url:
                safe, reason = is_safe_url(redirect_url)
                if not safe:
                    return LinkResult(url=url, status_code=None, is_alive=False,
                                      response_time_ms=None, redirect_url=None,
                                      error=f"Redirect blocked: {reason}", ai_analysis=None,
                                      checked_at=datetime.utcnow().isoformat())

            return LinkResult(
                url=url,
                status_code=response.status_code,
                is_alive=response.status_code < 400,
                response_time_ms=round(elapsed, 2),
                redirect_url=redirect_url,
                error=None,
                ai_analysis=None,
                checked_at=datetime.utcnow().isoformat(),
            )
    except httpx.TimeoutException:
        return LinkResult(url=url, status_code=None, is_alive=False, response_time_ms=None,
                          redirect_url=None, error="Request timed out", ai_analysis=None,
                          checked_at=datetime.utcnow().isoformat())
    except httpx.ConnectError:
        return LinkResult(url=url, status_code=None, is_alive=False, response_time_ms=None,
                          redirect_url=None, error="Connection refused or DNS failure", ai_analysis=None,
                          checked_at=datetime.utcnow().isoformat())
    except Exception as e:
        return LinkResult(url=url, status_code=None, is_alive=False, response_time_ms=None,
                          redirect_url=None, error="Request failed", ai_analysis=None,
                          checked_at=datetime.utcnow().isoformat())

async def call_gemini_rest(model: str, prompt: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"maxOutputTokens": 800, "temperature": 0.4},
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.post(url, json=payload)
        res.raise_for_status()
        data = res.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]


async def get_ai_analysis(results: list[LinkResult]) -> str:
    summary_lines = [
        f"URL: {r.url} | Status: {r.status_code or 'N/A'} | Alive: {r.is_alive} | "
        f"Response time: {r.response_time_ms}ms | Error: {r.error or 'None'}"
        for r in results
    ]
    prompt = f"""You are a link health analyst. Analyze these results briefly:
{chr(10).join(summary_lines)}
Give a short summary, flag broken links, and list recommendations."""

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

@app.post("/check-links", response_model=dict)
@limiter.limit("30/minute")
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

    tasks = [check_single_link(url) for url in sanitized]
    results = await asyncio.gather(*tasks)

    ai_summary = await get_ai_analysis(list(results))
    alive_count = sum(1 for r in results if r.is_alive)

    return {
        "results": [r.dict() for r in results],
        "skipped": errors,
        "summary": {
            "total": len(results),
            "alive": alive_count,
            "dead": len(results) - alive_count,
            "ai_analysis": ai_summary,
        }
    }


@app.post("/extract-links", response_model=dict)
@limiter.limit("20/minute")
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
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}