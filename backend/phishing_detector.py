import re
from urllib.parse import urlparse, unquote
from config import (
    PHISHING_PATTERNS,
    BRAND_IN_DOMAIN_PATTERNS,
    BRAND_OFFICIAL_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    KNOWN_BRANDS,
    SEVERITY_WEIGHT,
    SCORE_SUSPICIOUS,
    SCORE_DANGEROUS,
)


def heuristic_phishing_check(url: str) -> tuple[bool, list[str], int]:
    flags: list[str] = []
    score: int = 0
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_url_lower = url.lower()

    # Trusted domains can host compromised pages, open redirects, and user content.
    # They remain useful context elsewhere, but must not bypass phishing analysis.

    try:
        decoded_url = unquote(full_url_lower)
    except Exception:
        decoded_url = full_url_lower

    def add_flag(reason: str, weight: int) -> None:
        nonlocal score
        flags.append(reason)
        score += SEVERITY_WEIGHT.get(weight, 1)

    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        add_flag("URL uses a raw IP address instead of a domain name", 3)
    except ValueError:
        pass

    if parsed.username is not None:
        add_flag("URL contains embedded credentials/userinfo — common host-disguise technique", 3)

    if hostname.startswith("xn--") or ".xn--" in hostname:
        add_flag("Punycode domain detected — review for a possible homograph attack", 2)

    parts = hostname.split(".")
    bare_host = hostname.removeprefix("www.")

    subdomain_depth = len(parts) - 2
    if subdomain_depth >= 4:
        add_flag(f"Excessive subdomains ({subdomain_depth} levels deep) — classic domain-disguise technique", 3)
    elif subdomain_depth >= 3:
        sensitive_in_subdomain = any(
            kw in ".".join(parts[:-2])
            for kw in ["login", "secure", "verify", "account", "signin", "bank", "update"]
        )
        if sensitive_in_subdomain:
            add_flag(f"Sensitive keyword in deep subdomain ({hostname})", 2)

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            # A TLD alone is weak evidence. It becomes meaningful when paired with
            # a credential lure or another independent signal below.
            add_flag(f"Higher-risk top-level domain: {tld}", 1)
            break

    bare = hostname.removeprefix("www.")
    if bare in URL_SHORTENERS:
        add_flag(f"URL shortener detected ({bare}) — real destination is hidden", 1)

    for brand_name, pattern in BRAND_IN_DOMAIN_PATTERNS:
        if brand_name in hostname:
            official_domains = BRAND_OFFICIAL_DOMAINS.get(brand_name, [f"{brand_name}.com"])
            if not any(hostname == d or hostname.endswith("." + d) for d in official_domains):
                add_flag(
                    f"Brand '{brand_name}' in non-official domain '{hostname}' — possible spoofing",
                    3
                )
                break

    url_len = len(url)
    if url_len > 200:
        add_flag(f"Very long URL ({url_len} chars) — may be obfuscating destination", 1)
    elif url_len > 150:
        add_flag(f"Unusually long URL ({url_len} chars)", 1)

    seen_patterns: set[str] = set()
    for pattern, reason, weight in PHISHING_PATTERNS:
        if reason in seen_patterns:
            continue
        if re.search(pattern, full_url_lower) or re.search(pattern, decoded_url):
            add_flag(reason, weight)
            seen_patterns.add(reason)

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

    sld = parts[-2] if len(parts) >= 2 else ""
    homoglyph_patterns = [
        (r"[a-z]0[a-z]", "Digit '0' possibly substituted for letter 'o'"),
        (r"[a-z]1[a-z]", "Digit '1' possibly substituted for letter 'l' or 'i'"),
    ]
    brand_in_sld = any(brand in sld for brand in KNOWN_BRANDS)
    if brand_in_sld:
        for pat, msg in homoglyph_patterns:
            if re.search(pat, sld):
                add_flag(f"Possible homoglyph/lookalike attack in SLD '{sld}': {msg}", 2)

    if has_suspicious_tld and re.match(r"^[a-z]{2,5}\d{3,5}[a-z]{1,4}$", sld):
        add_flag(f"Domain SLD looks randomly generated ('{sld}') — common in phishing infrastructure", 1)

    giveaway_keywords = [
        r"\d{2,4}gb", r"\d{1,2}tb", "free-storage", "free-data",
        "labor-day", "labour-day", "giveaway", "freebie",
        "claim-now", "claimnow", "get-free", "getfree",
    ]
    for kw in giveaway_keywords:
        if re.search(kw, full_url_lower):
            add_flag(f"Free giveaway/storage lure keyword detected: '{kw}'", 3)
            break

    if re.search(r"\.(php|aspx|asp)$", path):
        php_suspicious_paths = ["registration", "signup", "register", "login", "verify", "confirm", "account"]
        if any(kw in path for kw in php_suspicious_paths):
            add_flag("PHP/ASPX form page with sensitive keyword — possible credential harvesting", 3)

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
    virustotal_malicious: bool = False,
) -> str:

    if gsb_threat or virustotal_malicious:
        return "dangerous"
    if score >= SCORE_DANGEROUS:
        return "dangerous"
    if score >= SCORE_SUSPICIOUS:
        return "suspicious"
    return "safe"
