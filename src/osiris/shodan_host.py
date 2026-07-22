"""Shodan host exposure — open ports / services / banners for a domain's IP.

Requires SHODAN_API_KEY (the same key the Favicon Pivot uses). Resolves the
domain to an IP and queries Shodan's host API for the exposed attack surface:
ports, detected products/versions, banners, hostnames, and known CVEs.
"""
import os
import socket
import urllib.parse

import requests

from osiris.enrichment import get_proxies, get_request_timeout


def _looks_like_ip(v: str) -> bool:
    parts = v.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _norm(domain: str) -> str:
    d = (domain or "").strip().lower()
    if d.startswith(("http://", "https://")):
        d = urllib.parse.urlparse(d).netloc or d
    return d.strip("/").split("/")[0]


def host_exposure(domain: str) -> dict:
    key = os.getenv("SHODAN_API_KEY")
    target = _norm(domain)
    if not key:
        return {"configured": False, "domain": target}

    if _looks_like_ip(target):
        ip = target
    else:
        try:
            ip = socket.gethostbyname(target)
        except OSError:
            return {"configured": True, "domain": target, "found": False, "error": "could not resolve domain"}

    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
    except requests.RequestException as e:
        return {"configured": True, "domain": target, "ip": ip, "found": False, "error": e.__class__.__name__}

    if r.status_code == 401:
        return {"configured": True, "domain": target, "ip": ip, "found": False, "error": "Shodan rejected the API key (401)"}
    if r.status_code == 404:
        return {"configured": True, "domain": target, "ip": ip, "found": False, "error": "no Shodan data for this IP"}
    if r.status_code != 200:
        return {"configured": True, "domain": target, "ip": ip, "found": False, "error": f"HTTP {r.status_code}"}

    try:
        data = r.json()
    except ValueError:
        return {"configured": True, "domain": target, "ip": ip, "found": False, "error": "bad response"}

    services = []
    for item in data.get("data") or []:
        banner = (item.get("data") or "").strip()
        services.append(
            {
                "port": item.get("port"),
                "transport": item.get("transport"),
                "product": item.get("product"),
                "version": item.get("version"),
                "banner": banner[:400],
            }
        )
    services.sort(key=lambda s: (s["port"] is None, s["port"] or 0))

    vulns = data.get("vulns") or []
    if isinstance(vulns, dict):
        vulns = list(vulns.keys())

    return {
        "configured": True,
        "domain": target,
        "found": True,
        "ip": ip,
        "ports": sorted(data.get("ports") or []),
        "hostnames": data.get("hostnames") or [],
        "org": data.get("org"),
        "isp": data.get("isp"),
        "asn": data.get("asn"),
        "os": data.get("os"),
        "country": data.get("country_name"),
        "last_update": data.get("last_update"),
        "services": services,
        "vulns": sorted(vulns),
        "shodan_url": f"https://www.shodan.io/host/{ip}",
    }
