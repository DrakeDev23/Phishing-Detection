import asyncio
import re
import ipaddress
import socket
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
        return is_blocked_ip(addr)
    except ValueError:
        blocked_hosts = {"localhost", "local", "internal", "metadata.google.internal"}
        return hostname.lower().rstrip(".") in blocked_hosts


def is_blocked_ip(address: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True when an address must never be requested by the scanner."""
    addr = ipaddress.ip_address(address)
    return (
        any(addr in network for network in BLOCKED_NETWORKS)
        or addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or not addr.is_global
    )


async def resolve_host_addresses(hostname: str, port: int | None) -> set[str]:
    """Resolve all addresses for a host so each can be checked before a request."""
    loop = asyncio.get_running_loop()
    records = await loop.getaddrinfo(
        hostname,
        port or 443,
        type=socket.SOCK_STREAM,
    )
    return {record[4][0] for record in records}


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


async def validate_url_target(url: str) -> tuple[bool, str]:
    """Validate a URL and every DNS result before the backend connects to it."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, "Blocked: only http/https URLs are allowed"

        hostname = parsed.hostname
        if not hostname:
            return False, "Blocked: URL has no valid host"

        # Accessing ``parsed.port`` also rejects invalid or out-of-range ports.
        port = parsed.port
        if is_private_ip(hostname):
            return False, "Blocked: URL points to internal/private network"

        addresses = await resolve_host_addresses(hostname, port)
        if not addresses:
            return False, "Blocked: hostname did not resolve"

        blocked_addresses = [address for address in addresses if is_blocked_ip(address)]
        if blocked_addresses:
            return False, "Blocked: hostname resolves to an internal/private network"

        return True, ""
    except (OSError, ValueError, socket.gaierror):
        return False, "Blocked: hostname could not be resolved safely"
    except Exception:
        return False, "Blocked: invalid URL target"


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
