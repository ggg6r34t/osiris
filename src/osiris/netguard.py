"""SSRF guard for server-side fetches.

Osiris fetches attacker-controlled inputs server-side (URL Analyze, Enrich,
Abuse Router liveness, screenshots). This module blocks requests whose host
resolves to a non-public address — loopback, RFC-1918/private, link-local
(incl. the 169.254.169.254 cloud-metadata endpoint), reserved, multicast — and
rejects non-http(s) schemes, so those tools can't be turned into a pivot into
internal infrastructure.

Set OSIRIS_ALLOW_PRIVATE_TARGETS=true to disable (e.g. deliberately scanning an
internal host on a trusted network).
"""
import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urlparse


class BlockedTargetError(Exception):
    """Raised when a fetch target resolves to a disallowed address/scheme."""


def _allow_private() -> bool:
    return os.getenv("OSIRIS_ALLOW_PRIVATE_TARGETS", "false").lower() == "true"


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def ip_is_blocked(value: str) -> bool:
    ip = _as_ip(value)
    if ip is None:
        return True  # unparseable → block
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


def check_host(host: Optional[str]) -> Optional[str]:
    """Return a human-readable block reason, or None if the host is allowed."""
    if _allow_private():
        return None
    if not host:
        return "missing host"
    host = host.strip().strip("[]")  # tolerate bracketed IPv6
    if _as_ip(host) is not None:
        return f"{host} is a non-public address" if ip_is_blocked(host) else None
    try:
        ips = _resolve(host)
    except socket.gaierror:
        return f"cannot resolve host: {host}"
    if not ips:
        return f"cannot resolve host: {host}"
    for ip in ips:
        if ip_is_blocked(ip):
            return f"{host} resolves to a non-public address ({ip})"
    return None


def assert_host_allowed(host: Optional[str]) -> None:
    reason = check_host(host)
    if reason:
        raise BlockedTargetError(reason)


def assert_url_allowed(url: str) -> None:
    """Validate scheme is http(s) and the host resolves to a public address."""
    parsed = urlparse(url if "://" in (url or "") else "http://" + (url or ""))
    if parsed.scheme not in ("http", "https"):
        raise BlockedTargetError(f"scheme '{parsed.scheme}' is not allowed (http/https only)")
    assert_host_allowed(parsed.hostname)
