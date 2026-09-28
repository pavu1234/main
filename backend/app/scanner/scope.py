import asyncio, ipaddress, socket
from urllib.parse import urlparse, urlunparse

BLOCKED_HOSTS = {"localhost", "localhost.localdomain", "metadata.google.internal", "169.254.169.254"}

class ScopeError(ValueError): pass

def normalize_url(url: str) -> str:
    p = urlparse(url.strip())
    if p.scheme not in {"http", "https"}: raise ScopeError("Only http:// and https:// are supported")
    if not p.hostname: raise ScopeError("Target hostname is missing")
    host = p.hostname.lower().rstrip(".")
    netloc = host if p.port is None else f"{host}:{p.port}"
    path = p.path or "/"
    return urlunparse((p.scheme, netloc, path, "", p.query, ""))

def same_host(a: str, b: str) -> bool:
    return (urlparse(a).hostname or "").lower().rstrip(".") == (urlparse(b).hostname or "").lower().rstrip(".")

def _blocked_ip(ip: str) -> bool:
    obj = ipaddress.ip_address(ip)
    return obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved or obj.is_unspecified

async def validate_public_target(url: str, allow_demo_private: bool = False) -> str:
    normalized = normalize_url(url)
    host = urlparse(normalized).hostname or ""
    if host in BLOCKED_HOSTS and not allow_demo_private: raise ScopeError("Target is an internal or blocked hostname")
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS resolution failed: {exc}") from exc
    ips = {i[4][0] for i in infos}
    if not ips: raise ScopeError("DNS resolution returned no addresses")
    if not allow_demo_private and any(_blocked_ip(ip) for ip in ips):
        raise ScopeError("Target resolves to a private, loopback, link-local, reserved, or internal address")
    return normalized
