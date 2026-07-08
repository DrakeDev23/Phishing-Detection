import re
import ipaddress
from urllib.parse import urlparse
from config import MAX_URL_LENGTH, BLOCKED_NETWORKS, TRUSTED_DOMAINS


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
    """
    Check if hostname is a private/internal IP address.
    
    Args:
        hostname: Domain or IP address
        
    Returns:
        True if hostname is in blocked networks or known internal hosts
    """
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


def is_trusted_domain(hostname: str) -> bool:
    hostname = hostname.lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]

    if hostname in TRUSTED_DOMAINS:
        return True
    
    for trusted in TRUSTED_DOMAINS:
        if hostname.endswith("." + trusted):
            return True
    
    return False
