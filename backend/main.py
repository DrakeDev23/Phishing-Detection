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
from urllib.parse import urlparse, unquote

load_dotenv()

limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])

app = FastAPI(title="Link Checker API", docs_url=None, redoc_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "trvstpulse.vercel.app").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Content-Type"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not set. Add it to your backend/.env file.")

SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

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

KNOWN_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook", "instagram",
    "twitter", "netflix", "steam", "discord", "roblox", "bank", "chase", "wellsfargo",
    "citibank", "hsbc", "barclays", "ebay", "shopify", "dropbox", "linkedin",
    "whatsapp", "telegram", "yahoo", "outlook", "office365",
]

BRAND_OFFICIAL_DOMAINS = {
    "google":     ["google.com", "google.com.hk", "google.co.uk", "google.com.ph",
                   "google.co.jp", "google.com.au", "google.de", "google.fr",
                   "google.co.in", "google.com.br", "google.ca", "google.co.id",
                   # FIX 1: Add google-owned properties so they aren't flagged as brand spoofers
                   "youtube.com", "googlevideo.com", "googleusercontent.com",
                   "googleapis.com", "gstatic.com", "gmail.com", "google.com.sg",
                   "google.com.tw", "google.com.mx", "google.com.ar", "google.co.nz"],
    "paypal":     ["paypal.com"],
    "apple":      ["apple.com", "icloud.com"],
    "microsoft":  ["microsoft.com", "microsoft.com.hk", "live.com", "azure.com",
                   "microsoftonline.com", "office.com", "sharepoint.com"],
    "amazon":     ["amazon.com", "amazon.co.uk", "amazon.co.jp", "amazon.de",
                   "amazon.fr", "amazon.ca", "amazon.com.au", "aws.amazon.com",
                   "amazonwebservices.com"],
    "facebook":   ["facebook.com", "fb.com", "meta.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "x.com"],
    "netflix":    ["netflix.com"],
    "steam":      ["steampowered.com", "steamcommunity.com"],
    "discord":    ["discord.com", "discord.gg"],
    "roblox":     ["roblox.com"],
    "chase":      ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "citibank":   ["citibank.com", "citi.com"],
    "hsbc":       ["hsbc.com", "hsbc.co.uk"],
    "barclays":   ["barclays.co.uk", "barclays.com"],
    "ebay":       ["ebay.com", "ebay.co.uk", "ebay.de"],
    "shopify":    ["shopify.com", "myshopify.com"],
    "dropbox":    ["dropbox.com"],
    "linkedin":   ["linkedin.com"],
    "whatsapp":   ["whatsapp.com", "whatsapp.net"],
    "telegram":   ["telegram.org", "t.me"],
    "yahoo":      ["yahoo.com", "yahoo.co.jp", "yahoo.co.uk"],
    "outlook":    ["outlook.com", "outlook.live.com"],
    "office365":  ["office.com", "office365.com"],
}

# FIX 2: Expanded whitelist of trusted domains — these are never flagged by heuristics.
# This is the PRIMARY fix for false positives on legitimate sites.
TRUSTED_DOMAINS: set[str] = {
    # Google ecosystem
    "google.com", "youtube.com", "gmail.com", "googlemail.com",
    "googlevideo.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "google.co.uk", "google.com.ph", "google.co.jp", "google.de", "google.fr",
    "google.ca", "google.com.au", "google.co.in", "google.com.br", "google.co.id",
    "google.com.sg", "google.com.tw", "google.com.mx", "google.com.ar",
    # Microsoft ecosystem
    "microsoft.com", "live.com", "outlook.com", "hotmail.com", "office.com",
    "office365.com", "azure.com", "microsoftonline.com", "sharepoint.com",
    "onedrive.live.com", "skype.com",
    # Apple ecosystem
    "apple.com", "icloud.com",
    # Amazon ecosystem
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "amazon.fr", "amazon.ca", "amazon.com.au", "aws.amazon.com",
    # Social / communication
    "facebook.com", "fb.com", "meta.com", "instagram.com",
    "twitter.com", "x.com", "reddit.com", "discord.com", "discord.gg",
    "linkedin.com", "whatsapp.com", "telegram.org", "t.me",
    "tiktok.com", "snapchat.com", "pinterest.com",
    # Entertainment
    "netflix.com", "spotify.com", "twitch.tv", "hulu.com",
    "disneyplus.com", "hbomax.com",
    # Tech / developer
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "npmjs.com", "pypi.org", "docker.com", "cloudflare.com",
    "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",
    "shopify.com", "myshopify.com", "stripe.com", "twilio.com",
    "sendgrid.com", "mailchimp.com", "hubspot.com", "salesforce.com",
    # FIX 3: Add security/research sites that legitimately use .io or unusual TLDs
    "shodan.io", "censys.io", "virustotal.com", "urlvoid.com",
    "haveibeenpwned.com", "abuse.ch", "hybrid-analysis.com",
    "any.run", "greynoise.io", "urlscan.io",
    # Storage / productivity
    "dropbox.com", "box.com", "wetransfer.com", "drive.google.com",
    "docs.google.com", "notion.so", "airtable.com", "trello.com",
    "slack.com", "zoom.us", "webex.com", "teams.microsoft.com",
    # Finance
    "paypal.com", "venmo.com", "stripe.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "citibank.com", "citi.com",
    "hsbc.com", "barclays.com", "barclays.co.uk",
    # News / reference
    "wikipedia.org", "britannica.com", "bbc.com", "bbc.co.uk",
    "cnn.com", "reuters.com", "apnews.com", "theguardian.com",
    "nytimes.com", "wsj.com", "forbes.com", "techcrunch.com",
    "wired.com", "arstechnica.com",
    # Other common sites
    "yahoo.com", "ebay.com", "etsy.com", "craigslist.org",
    "medium.com", "substack.com", "wordpress.com", "blogspot.com",
    "tumblr.com", "quora.com", "yelp.com", "tripadvisor.com",
    "booking.com", "airbnb.com", "uber.com", "lyft.com",
    "doordash.com", "grubhub.com", "instacart.com",
    # Gaming
    "steampowered.com", "steamcommunity.com", "roblox.com",
    "epicgames.com", "ea.com", "blizzard.com", "battle.net",
}


def is_trusted_domain(hostname: str) -> bool:
    """
    Returns True if the hostname is an exact match or subdomain of a trusted domain.
    e.g. 'www.youtube.com' and 'accounts.google.com' both return True.

    FIX: Use proper prefix removal instead of lstrip() which strips characters
    not strings. lstrip("www.") would incorrectly strip 'w', 'w', 'w', '.'
    individually rather than the whole prefix "www."
    """
    hostname = hostname.lower()
    # Properly remove www. prefix
    if hostname.startswith("www."):
        hostname = hostname[4:]

    if hostname in TRUSTED_DOMAINS:
        return True
    # Check if it's a subdomain of a trusted root
    for trusted in TRUSTED_DOMAINS:
        if hostname.endswith("." + trusted):
            return True
    return False


SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".pw",
    ".cc", ".ws", ".nu", ".to", ".buzz",
    ".live", ".click", ".link", ".download", ".win", ".loan",
    # FIX 4: Removed ".info", ".biz", ".ru", ".cn" — too many false positives.
    # ".io" removed: used by many legitimate tech/security companies (shodan.io, etc.)
    # Keep these only if paired with other signals via PHISHING_PATTERNS
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "lnkd.in",
}

PHISHING_PATTERNS: list[tuple[str, str, int]] = [
    # Brand spoofing — only fires when NOT on official domain (enforced in heuristic fn)
    (r"(paypa[l1]|pay-pal|paypai)[^.]*\.",                         "PayPal brand spoofing",      3),
    (r"(arnazon|amaz[o0]n-secure|amazon-update)[^.]*\.",           "Amazon brand spoofing",      3),
    (r"(g[o0]{2}gle|googIe|google-verify|google-support)[^.]*\.",  "Google brand spoofing",      3),
    (r"(micros[o0]ft|mircosoft|micro-soft)[^.]*\.",                "Microsoft brand spoofing",   3),
    (r"(app[l1]e-id|apple-support|icloud-verify)[^.]*\.",         "Apple brand spoofing",       3),

    # Free storage / holiday giveaway lures
    (r"\d{2,4}(gb|tb|mb)-?free",          "Fake free-storage lure (e.g. 51gb-free)",  3),
    (r"free-?\d{2,4}(gb|tb|mb)",          "Fake free-storage lure (reversed)",        3),
    (r"labor.?day.{0,30}(free|gb|prize)",  "Fake holiday giveaway lure",               3),
    (r"(black.?friday|cyber.?monday|christmas|easter|holiday).{0,30}(free|gb|prize|gift|reward)", "Fake holiday giveaway lure", 3),

    # High-risk TLD + suspicious keyword combos
    (r"(secure|login|verify|update|confirm|account|signin|password|credential).{0,20}\.(xyz|tk|ml|ga|cf|gq|top|online|site|buzz|live|click)", "Suspicious keyword + high-risk TLD", 3),

    # URL tricks
    (r"@.+\.(com|net|org)",                                        "URL contains @ (credential-bypass trick)",  3),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",             "Direct IP address URL",                     3),
    (r"%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",      "Heavy URL encoding (obfuscation)",          2),

    # Hyphenated domains — reduced weight, only fires on untrusted domains
    (r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.",               "Highly hyphenated domain (4+ segments)",    2),
    # FIX 5: Removed the weight-1 hyphenated pattern — too noisy, caused false positives

    # Urgency / reward language
    (r"(free|gift|prize|winner|lucky|bonus|reward|claim).{0,30}(click|now|here|login)", "Reward/urgency language", 2),

    # Random-looking domain on high-risk TLD
    (r"^https?://[a-z]{2,5}\d{1,4}[a-z]{1,4}\.(top|xyz|online|site|click|live|win|loan)", "Random-looking domain on high-risk TLD", 2),

    # Tracking / campaign IDs
    (r"#\d{13,}$",                         "Numeric timestamp fragment (tracking/campaign ID)", 1),
    (r"\?[a-z0-9]+=\d{3,}(&[a-z0-9]+=\d+)*#",  "Numeric-only query params + fragment (campaign tracking)", 1),

    # Crypto / investment scams
    (r"(coin|crypto|wallet|token|nft|defi|bitcoin|ethereum|binance)[a-z0-9]*\.(io|cash|top|xyz|online|site|finance|capital|exchange|market)", "Crypto-themed domain on high-risk TLD — common investment scam", 3),
    (r"(kringle|xmas|santa|holiday)[a-z0-9]*\.(cash|io|top|xyz|online)", "Suspicious seasonal/gift domain on high-risk TLD", 3),
    (r"(earn|profit|invest|income|revenue|payout|dividend)[a-z0-9-]*\.(cash|io|top|xyz|online|finance)", "Investment lure on high-risk TLD", 3),

    # Credential harvesting paths
    (r"/(registration_form|register_form|signup_form|login_form|verify_form)\.", "Credential harvesting form path detected", 3),
    (r"/(registration|signup|enroll|join|create.?account)[^/]*\.php", "Suspicious registration PHP page", 2),

    # Referral / affiliate scams
    (r"\?(link|ref|referral|aff|affiliate|invite|code)=[a-z0-9_-]+$", "Referral/affiliate parameter — common in scam recruitment", 2),

    # Meme / altcoin scam domains
    (r"(sbc|doge|shib|pepe|floki|luna|bnb|trx|usdt)[a-z0-9]*coin[a-z0-9]*\.", "Meme/altcoin scam domain pattern", 3),
    (r"(sbc|doge|shib|pepe|floki|luna|bnb|trx|usdt)[a-z0-9]*\.(io|cash|finance|exchange|market|capital)", "Altcoin-themed domain on financial TLD", 3),
]

# FIX 6: These patterns fire ONLY when the brand name appears in the domain
# but the domain is NOT an official brand domain.
# This replaces the old loop that checked `if brand in hostname`.
BRAND_IN_DOMAIN_PATTERNS: list[tuple[str, str]] = [
    # Format: (brand_name, regex_to_match_spoofed_domain)
    # The regex matches the hostname portion. Brand must appear + extra chars = spoofed.
    ("paypal",    r"paypal[^.]*\.(?!com$)"),           # paypal-secure.xyz, paypal-login.tk
    ("google",    r"google[^.]*\.(?!com|co\.|google)"),
    ("apple",     r"apple[^.]*\.(?!com$)"),
    ("microsoft", r"microsoft[^.]*\.(?!com$)"),
    ("amazon",    r"amazon[^.]*\.(?!com|co\.|amazon)"),
    ("facebook",  r"facebook[^.]*\.(?!com$)"),
    ("netflix",   r"netflix[^.]*\.(?!com$)"),
    ("instagram", r"instagram[^.]*\.(?!com$)"),
    ("discord",   r"discord[^.]*\.(?!com|gg$)"),
    ("steam",     r"steam[^.]*\.(?!powered\.com|community\.com)"),
    ("roblox",    r"roblox[^.]*\.(?!com$)"),
    ("chase",     r"chase[^.]*\.(?!com$)"),
    ("wellsfargo",r"wellsfargo[^.]*\.(?!com$)"),
    ("hsbc",      r"hsbc[^.]*\.(?!com|co\.uk$)"),
    ("linkedin",  r"linkedin[^.]*\.(?!com$)"),
    ("ebay",      r"ebay[^.]*\.(?!com|co\.uk|de$)"),
    ("yahoo",     r"yahoo[^.]*\.(?!com|co\.)"),
    ("outlook",   r"outlook[^.]*\.(?!com$)"),
    ("whatsapp",  r"whatsapp[^.]*\.(?!com|net$)"),
    ("telegram",  r"telegram[^.]*\.(?!org$)"),
    ("dropbox",   r"dropbox[^.]*\.(?!com$)"),
]

SEVERITY_WEIGHT = {1: 1, 2: 3, 3: 7}

# FIX 7: Raised thresholds — previously too easy to hit SUSPICIOUS.
# Old: SUSPICIOUS=3, DANGEROUS=7
# New: SUSPICIOUS=4, DANGEROUS=10
# This prevents single low-weight flags from marking legitimate sites suspicious.
SCORE_SUSPICIOUS  = 4
SCORE_DANGEROUS   = 10


def sanitize_url(raw: str) -> str:
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
    try:
        addr = ipaddress.ip_address(hostname)
        return any(addr in net for net in BLOCKED_NETWORKS)
    except ValueError:
        blocked_hosts = {"localhost", "local", "internal", "metadata.google.internal"}
        return hostname.lower() in blocked_hosts


def is_safe_url(url: str) -> tuple[bool, str]:
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


def heuristic_phishing_check(url: str) -> tuple[bool, list[str], int]:
    """
    Rule-based phishing detection.
    Returns (is_suspicious, list_of_reasons, phishing_score).

    Key design principles:
    - Trusted domains (TRUSTED_DOMAINS set) are exempt from ALL heuristics.
    - Brand spoofing is detected via precise regex, not naive substring matching.
    - Score thresholds are calibrated to reduce false positives.
    """
    flags: list[str] = []
    score: int = 0
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    fragment = (parsed.fragment or "").lower()
    full_url_lower = url.lower()

    try:
        decoded_url = unquote(full_url_lower)
    except Exception:
        decoded_url = full_url_lower

    # FIX 8: TRUSTED DOMAIN BYPASS — if domain is in our whitelist, skip all heuristics.
    # This is the single most important fix. Legitimate sites like youtube.com,
    # shodan.io, and github.com will never be flagged regardless of their path.
    if is_trusted_domain(hostname):
        return False, [], 0

    def add_flag(reason: str, weight: int) -> None:
        nonlocal score
        flags.append(reason)
        score += SEVERITY_WEIGHT.get(weight, 1)

    # Raw IP address check
    try:
        ipaddress.ip_address(hostname)
        add_flag("URL uses a raw IP address instead of a domain name", 3)
    except ValueError:
        pass

    parts = hostname.split(".")
    bare_host = hostname.lstrip("www.")

    # Subdomain depth — only flag genuinely excessive depth (>=4 non-www levels)
    # FIX 9: We no longer check is_well_known_domain here — that's handled by
    # the trusted domain bypass above. Only unknown domains reach this point.
    subdomain_depth = len(parts) - 2
    if subdomain_depth >= 4:
        add_flag(f"Excessive subdomains ({subdomain_depth} levels deep) — classic domain-disguise technique", 3)
    elif subdomain_depth >= 3:
        # FIX 10: Only flag 3-level subdomains if combined with a sensitive keyword
        sensitive_in_subdomain = any(
            kw in ".".join(parts[:-2])
            for kw in ["login", "secure", "verify", "account", "signin", "bank", "update"]
        )
        if sensitive_in_subdomain:
            add_flag(f"Sensitive keyword in deep subdomain ({hostname})", 2)

    # Suspicious TLD check
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            add_flag(f"High-risk top-level domain: {tld}", 2)
            break

    # URL shortener check
    bare = hostname.lstrip("www.")
    if bare in URL_SHORTENERS:
        add_flag(f"URL shortener detected ({bare}) — real destination is hidden", 2)

    # FIX 11: Replaced the old naive brand-in-hostname loop with precise regex patterns.
    # Old code: `if brand in hostname` — matched "google" in "googlemaps.example.com"
    # and also matched legitimate subdomains incorrectly.
    # New code: per-brand regex that requires the brand + non-official suffix.
    for brand_name, pattern in BRAND_IN_DOMAIN_PATTERNS:
        if brand_name in hostname:  # fast pre-filter before regex
            official_domains = BRAND_OFFICIAL_DOMAINS.get(brand_name, [f"{brand_name}.com"])
            if not any(hostname == d or hostname.endswith("." + d) for d in official_domains):
                add_flag(
                    f"Brand '{brand_name}' in non-official domain '{hostname}' — possible spoofing",
                    3
                )
                break  # Only report once per URL

    # URL length
    url_len = len(url)
    if url_len > 200:
        add_flag(f"Very long URL ({url_len} chars) — may be obfuscating destination", 2)
    elif url_len > 150:
        add_flag(f"Unusually long URL ({url_len} chars)", 1)

    # PHISHING_PATTERNS regex scan
    seen_patterns: set[str] = set()
    for pattern, reason, weight in PHISHING_PATTERNS:
        if reason in seen_patterns:
            continue
        if re.search(pattern, full_url_lower) or re.search(pattern, decoded_url):
            add_flag(reason, weight)
            seen_patterns.add(reason)

    # Sensitive path/query keywords
    # FIX 12: Only flag if ALSO on a suspicious TLD or has other risk signals.
    # Old code flagged any unknown domain with /login, /verify etc. — too broad.
    # New: require at least one TLD risk signal OR explicit phishing path pattern.
    sensitive_path_keywords = [
        "login", "signin", "verify", "account", "secure", "update",
        "password", "credential", "confirm", "auth", "token", "reset",
        "registration_form", "register", "signup", "enroll",
        "create_account", "createaccount", "join", "subscribe",
    ]
    has_sensitive_path = any(kw in path or kw in query for kw in sensitive_path_keywords)
    has_suspicious_tld = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_sensitive_path and has_suspicious_tld:
        add_flag("Sensitive path/query keywords (login/verify/account) paired with high-risk TLD", 2)

    # Homoglyph detection in second-level domain only
    sld = parts[-2] if len(parts) >= 2 else ""
    homoglyph_patterns = [
        (r"[a-z]0[a-z]", "Digit '0' possibly substituted for letter 'o'"),
        (r"[a-z]1[a-z]", "Digit '1' possibly substituted for letter 'l' or 'i'"),
    ]
    # FIX 13: Only flag homoglyphs when a known brand name is nearby (within same SLD)
    brand_in_sld = any(brand in sld for brand in KNOWN_BRANDS)
    if brand_in_sld:
        for pat, msg in homoglyph_patterns:
            if re.search(pat, sld):
                add_flag(f"Possible homoglyph/lookalike attack in SLD '{sld}': {msg}", 2)

    # Random-looking SLD
    if re.match(r"^[a-z]{2,5}\d{3,5}[a-z]{1,4}$", sld):
        add_flag(f"Domain SLD looks randomly generated ('{sld}') — common in phishing infrastructure", 2)

    # Giveaway lure keywords
    giveaway_keywords = [
        r"\d{2,4}gb", r"\d{1,2}tb", "free-storage", "free-data",
        "labor-day", "labour-day", "giveaway", "freebie",
        "claim-now", "claimnow", "get-free", "getfree",
    ]
    for kw in giveaway_keywords:
        if re.search(kw, full_url_lower):
            add_flag(f"Free giveaway/storage lure keyword detected: '{kw}'", 3)
            break

    # Numeric fragment tracking ID
    if fragment and re.match(r"^\d{10,}$", fragment):
        add_flag(f"Numeric-only URL fragment (#{fragment[:20]}) — campaign tracking ID", 1)

    # Single numeric query param on unknown domain
    if query and re.match(r"^[a-z0-9]+=\d+$", query):
        add_flag("Query string is a single numeric parameter — likely campaign tracking", 1)

    # PHP/ASPX credential harvesting pages
    if re.search(r"\.(php|aspx|asp)$", path):
        php_suspicious_paths = ["registration", "signup", "register", "login", "verify", "confirm", "account"]
        if any(kw in path for kw in php_suspicious_paths):
            add_flag("PHP/ASPX form page with sensitive keyword on unrecognized domain — likely credential harvesting", 3)

    # Financial TLDs on unknown domains
    financial_tlds = {".cash", ".finance", ".capital", ".investments", ".trading", ".exchange", ".money", ".fund"}
    for ftld in financial_tlds:
        if hostname.endswith(ftld):
            add_flag(f"Domain uses financial TLD ({ftld}) — commonly used in investment/crypto scams", 3)
            break

    # FIX 14: Explicit high-confidence phishing domain structure check.
    # Catches the classic pattern: <brand>-<action>.<anything> e.g. login-paypal.com,
    # verify-amazon.net, paypal-secure.xyz
    brand_hyphen_pattern = r"^(" + "|".join(KNOWN_BRANDS) + r")-[a-z0-9]+"
    action_hyphen_pattern = r"^[a-z0-9]+-(login|secure|verify|account|update|confirm|signin|support)-?(" + "|".join(KNOWN_BRANDS) + r")"
    if re.search(brand_hyphen_pattern, sld) or re.search(action_hyphen_pattern, sld) or \
       re.search(brand_hyphen_pattern, bare_host) or re.search(action_hyphen_pattern, bare_host):
        add_flag(f"Domain structure matches classic phishing pattern (brand-action or action-brand): '{bare_host}'", 3)

    return score > 0, flags, score


def compute_risk_level(
    score: int,
    gsb_threat: str | None,
    heuristic_flags: list[str],
) -> str:
    if gsb_threat:
        return "dangerous"
    if score >= SCORE_DANGEROUS:
        return "dangerous"
    if score >= SCORE_SUSPICIOUS:
        return "suspicious"
    return "safe"


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


class PhishingAnalysis(BaseModel):
    is_suspicious: bool
    risk_level: str
    phishing_score: int
    heuristic_flags: list[str]
    safe_browsing_threat: str | None
    virustotal_summary: str | None


class LinkResult(BaseModel):
    url: str
    status_code: int | None
    is_alive: bool
    response_time_ms: float | None
    redirect_url: str | None
    error: str | None
    ai_analysis: str | None
    phishing: PhishingAnalysis | None
    checked_at: str


async def check_single_link(
    url: str,
    safe_browsing_hits: dict[str, str],
) -> LinkResult:
    safe, reason = is_safe_url(url)
    if not safe:
        return LinkResult(
            url=url, status_code=None, is_alive=False, response_time_ms=None,
            redirect_url=None, error=reason, ai_analysis=None, phishing=None,
            checked_at=datetime.utcnow().isoformat(),
        )

    start = asyncio.get_event_loop().time()
    status_code  = None
    is_alive     = False
    elapsed      = None
    redirect_url = None
    http_error   = None

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, timeout=10.0, max_redirects=5,
        ) as client:
            response = await client.get(url, headers={"User-Agent": "LinkChecker/1.0"})
            elapsed   = (asyncio.get_event_loop().time() - start) * 1000
            final_url = str(response.url)
            redirect_url = final_url if final_url != url else None

            if redirect_url:
                safe, reason = is_safe_url(redirect_url)
                if not safe:
                    return LinkResult(
                        url=url, status_code=None, is_alive=False,
                        response_time_ms=None, redirect_url=None,
                        error=f"Redirect blocked: {reason}", ai_analysis=None, phishing=None,
                        checked_at=datetime.utcnow().isoformat(),
                    )

            status_code = response.status_code
            is_alive = response.status_code < 400
            elapsed  = round(elapsed, 2)

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
            # FIX: Use is_trusted_domain() instead of a small hardcoded set.
            # Prevents shodan.io -> www.shodan.io from being flagged as suspicious.
            if not is_trusted_domain(orig_host) and not is_trusted_domain(redir_host):
                # Also skip if it's just a www. redirect on the same base domain
                # e.g. shodan.io -> www.shodan.io should never be flagged
                orig_base = orig_host[4:] if orig_host.startswith("www.") else orig_host
                redir_base = redir_host[4:] if redir_host.startswith("www.") else redir_host
                if orig_base != redir_base:
                    heuristic_flags.append(
                        f"Redirect between two unrecognized domains ({orig_host} → {redir_host}) — common in phishing chains"
                    )
                    phishing_score += SEVERITY_WEIGHT[2]

    gsb_threat = safe_browsing_hits.get(url) or safe_browsing_hits.get(check_url)

    vt_summary = ""
    if VIRUSTOTAL_API_KEY and (is_suspicious_heuristic or gsb_threat):
        _, vt_summary = await check_virustotal(check_url)

    risk_level = compute_risk_level(phishing_score, gsb_threat, heuristic_flags)

    phishing = PhishingAnalysis(
        is_suspicious=bool(gsb_threat or is_suspicious_heuristic),
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


async def call_gemini_rest(model: str, prompt: str) -> str:
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