"""Favicon-hash pivot — find other hosts serving the same favicon.

Phishing kits and cloned portals reuse the same favicon across many hosts, so the
favicon hash is a strong infrastructure pivot. This computes the favicon hash the
way **Shodan** does (MurmurHash3 x86_32 of the base64-encoded icon — implemented
in-house, no extra dependency), always returns a ready Shodan dork link, and — if
SHODAN_API_KEY is set — lists the matching hosts via the Shodan API.
"""
import base64
import os
import re
import urllib.parse

import requests

from osiris.enrichment import get_proxies, get_request_timeout
from osiris.netguard import BlockedTargetError, assert_url_allowed

_LINK_RE = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
_HREF_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)


def _murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 → signed 32-bit int (matches mmh3.hash / Shodan)."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & ~3
    for i in range(0, rounded, 4):
        k1 = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    rem = length & 3
    if rem == 3:
        k1 ^= data[rounded + 2] << 16
    if rem >= 2:
        k1 ^= data[rounded + 1] << 8
    if rem >= 1:
        k1 ^= data[rounded]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hash(content: bytes) -> int:
    """Shodan's favicon hash: mmh3 of the base64-encoded icon bytes."""
    return _murmur3_x86_32(base64.encodebytes(content))


def _norm(domain: str) -> str:
    d = (domain or "").strip()
    if not d.startswith(("http://", "https://")):
        d = "http://" + d
    return d


def _find_favicon_url(page_url: str, html: str) -> str:
    for link in _LINK_RE.findall(html or ""):
        m = _HREF_RE.search(link)
        if m:
            return urllib.parse.urljoin(page_url, m.group(1))
    parsed = urllib.parse.urlparse(page_url)
    return f"{parsed.scheme}://{parsed.netloc}/favicon.ico"


def _shodan_matches(fhash: int) -> dict:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return {"configured": False, "total": 0, "matches": []}
    try:
        r = requests.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": f"http.favicon.hash:{fhash}"},
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
        if r.status_code != 200:
            return {"configured": True, "total": 0, "matches": [], "error": f"HTTP {r.status_code}"}
        data = r.json()
        matches = [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "org": m.get("org"),
                "hostnames": m.get("hostnames") or [],
                "country": (m.get("location") or {}).get("country_code"),
            }
            for m in (data.get("matches") or [])[:100]
        ]
        return {"configured": True, "total": data.get("total", len(matches)), "matches": matches}
    except (requests.RequestException, ValueError) as e:
        return {"configured": True, "total": 0, "matches": [], "error": e.__class__.__name__}


def pivot(domain: str) -> dict:
    page_url = _norm(domain)
    host = urllib.parse.urlparse(page_url).netloc
    session = requests.Session()
    session.headers.update({"User-Agent": os.getenv("OSIRIS_USER_AGENT", "Osiris-Favicon/1.0")})
    timeout = get_request_timeout()
    proxies = get_proxies()
    verify = os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false"

    try:
        assert_url_allowed(page_url)
    except BlockedTargetError as e:
        return {"domain": host, "found": False, "error": f"blocked: {e}"}

    # Find the favicon URL from the page, else fall back to /favicon.ico
    favicon_url = f"{urllib.parse.urlparse(page_url).scheme}://{host}/favicon.ico"
    try:
        pr = session.get(page_url, timeout=timeout, proxies=proxies, verify=verify)
        favicon_url = _find_favicon_url(pr.url, pr.text)
    except requests.RequestException:
        pass

    try:
        assert_url_allowed(favicon_url)
        fr = session.get(favicon_url, timeout=timeout, proxies=proxies, verify=verify)
    except (requests.RequestException, BlockedTargetError) as e:
        return {"domain": host, "found": False, "favicon_url": favicon_url, "error": f"could not fetch favicon ({e.__class__.__name__})"}

    if fr.status_code != 200 or not fr.content:
        return {"domain": host, "found": False, "favicon_url": favicon_url, "error": f"no favicon (HTTP {fr.status_code})"}

    fhash = favicon_hash(fr.content)
    data_uri = "data:image/x-icon;base64," + base64.b64encode(fr.content).decode("ascii")
    return {
        "domain": host,
        "found": True,
        "favicon_url": favicon_url,
        "hash": fhash,
        "preview": data_uri if len(data_uri) < 60000 else None,
        "shodan_dork": f"https://www.shodan.io/search?query=http.favicon.hash%3A{fhash}",
        "shodan": _shodan_matches(fhash),
    }
