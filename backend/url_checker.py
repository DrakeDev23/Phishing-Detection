import asyncio
import httpx
from datetime import datetime
from urllib.parse import urljoin, urlparse
from models import LinkResult, PhishingAnalysis
from security import validate_url_target
from phishing_detector import heuristic_phishing_check, compute_risk_level
from external_services import check_virustotal
from config import MAX_REDIRECTS, REQUEST_TIMEOUT_SECONDS, SEVERITY_WEIGHT, VIRUSTOTAL_API_KEY


REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


async def check_single_link(
    url: str,
    safe_browsing_hits: dict[str, str],
) -> LinkResult:
    start = asyncio.get_event_loop().time()
    status_code  = None
    is_alive     = False
    elapsed      = None
    redirect_url = None
    http_error   = None

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS),
        ) as client:
            current_url = url
            for redirect_count in range(MAX_REDIRECTS + 1):
                safe, reason = await validate_url_target(current_url)
                if not safe:
                    error = f"Redirect blocked: {reason}" if current_url != url else reason
                    return LinkResult(
                        url=url, status_code=None, is_alive=False,
                        response_time_ms=None, redirect_url=redirect_url,
                        error=error, ai_analysis=None, phishing=None,
                        checked_at=datetime.utcnow().isoformat(),
                    )

                async with client.stream(
                    "GET", current_url, headers={"User-Agent": "LinkChecker/1.0"}
                ) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")

                if status_code not in REDIRECT_STATUS_CODES or not location:
                    is_alive = status_code < 400
                    elapsed = round((asyncio.get_event_loop().time() - start) * 1000, 2)
                    break

                if redirect_count == MAX_REDIRECTS:
                    http_error = f"Too many redirects (maximum {MAX_REDIRECTS})"
                    status_code = None
                    break

                next_url = urljoin(current_url, location)
                safe, reason = await validate_url_target(next_url)
                if not safe:
                    return LinkResult(
                        url=url, status_code=None, is_alive=False,
                        response_time_ms=None, redirect_url=redirect_url,
                        error=f"Redirect blocked: {reason}", ai_analysis=None, phishing=None,
                        checked_at=datetime.utcnow().isoformat(),
                    )

                current_url = next_url
                redirect_url = current_url if current_url != url else None

    except httpx.TimeoutException:
        http_error = "Request timed out"
    except httpx.ConnectError:
        http_error = "Connection refused or DNS failure"
    except Exception:
        http_error = "Request failed"

    check_url = redirect_url or url

    is_suspicious_heuristic, heuristic_flags, phishing_score = heuristic_phishing_check(check_url)

    if redirect_url:
        orig_suspicious, orig_flags, orig_score = heuristic_phishing_check(url)
        phishing_score = phishing_score + orig_score
        for f in orig_flags:
            if f not in heuristic_flags:
                heuristic_flags.append(f"[original URL] {f}")
        is_suspicious_heuristic = is_suspicious_heuristic or orig_suspicious

        orig_parsed = urlparse(url)
        redir_parsed = urlparse(redirect_url)
        orig_host = (orig_parsed.hostname or "").lower()
        redir_host = (redir_parsed.hostname or "").lower()

        if orig_host != redir_host:
            from security import is_trusted_domain
            if not is_trusted_domain(orig_host) and not is_trusted_domain(redir_host):
                orig_base = orig_host[4:] if orig_host.startswith("www.") else orig_host
                redir_base = redir_host[4:] if redir_host.startswith("www.") else redir_host
                if orig_base != redir_base:
                    heuristic_flags.append(
                        f"Redirect between two unrecognized domains ({orig_host} → {redir_host}) — common in phishing chains"
                    )
                    phishing_score += SEVERITY_WEIGHT[2]

    gsb_threat = safe_browsing_hits.get(url) or safe_browsing_hits.get(check_url)

    vt_malicious = False
    vt_summary = ""
    if VIRUSTOTAL_API_KEY and (is_suspicious_heuristic or gsb_threat):
        vt_malicious, vt_summary = await check_virustotal(check_url)

    risk_level = compute_risk_level(
        phishing_score, gsb_threat, heuristic_flags, virustotal_malicious=vt_malicious
    )

    phishing = PhishingAnalysis(
        is_suspicious=bool(gsb_threat or vt_malicious or is_suspicious_heuristic),
        risk_level=risk_level,
        phishing_score=phishing_score,
        heuristic_flags=heuristic_flags,
        safe_browsing_threat=gsb_threat,
        virustotal_summary=vt_summary or None,
    )

    return LinkResult(
        url=url,
        status_code=status_code,
        is_alive=is_alive,
        response_time_ms=elapsed,
        redirect_url=redirect_url,
        error=http_error,
        ai_analysis=None,
        phishing=phishing,
        checked_at=datetime.utcnow().isoformat(),
    )
