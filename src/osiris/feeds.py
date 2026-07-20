"""Threat-feed / blocklist reputation aggregation for a domain or IP.

Answers "is this already known-bad?" by checking several phishing/malware feeds
and rolling the hits into a verdict. Sources:
  - URLhaus (abuse.ch)     — free API, no key
  - Spamhaus DBL / ZEN     — DNS blocklist, no key
  - SURBL (multi)          — DNS blocklist, no key
  - Google Safe Browsing   — opt-in (GOOGLE_SAFE_BROWSING_API_KEY)

Each source degrades gracefully; a source that errors reports listed=None.
"""
import os

import dns.resolver
import requests

from osiris.enrichment import get_proxies, get_request_timeout


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    t = min(get_request_timeout(), 6)
    r.timeout = t
    r.lifetime = t
    return r


def _looks_like_ip(v: str) -> bool:
    parts = v.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def check_urlhaus(host: str) -> dict:
    """URLhaus host lookup (free abuse.ch API)."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host},
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
        data = r.json()
        if data.get("query_status") == "no_results":
            return {"source": "URLhaus", "listed": False}
        if data.get("query_status") == "ok":
            urls = data.get("urls") or []
            online = [u for u in urls if u.get("url_status") == "online"]
            return {
                "source": "URLhaus",
                "listed": True,
                "detail": f"{len(urls)} URL(s), {len(online)} online",
                "reference": f"https://urlhaus.abuse.ch/host/{host}/",
            }
        return {"source": "URLhaus", "listed": False}
    except (requests.RequestException, ValueError):
        return {"source": "URLhaus", "listed": None, "detail": "lookup failed"}


def _dns_bl(query: str, source: str, zone: str) -> dict:
    try:
        answers = _resolver().resolve(query + "." + zone, "A")
        codes = sorted({a.to_text() for a in answers})
        return {"source": source, "listed": True, "detail": ", ".join(codes)}
    except dns.resolver.NXDOMAIN:
        return {"source": source, "listed": False}
    except Exception:  # noqa: BLE001
        return {"source": source, "listed": None, "detail": "lookup failed"}


def check_spamhaus(target: str, is_ip: bool) -> dict:
    if is_ip:
        rev = ".".join(reversed(target.split(".")))
        return _dns_bl(rev, "Spamhaus ZEN", "zen.spamhaus.org")
    return _dns_bl(target, "Spamhaus DBL", "dbl.spamhaus.org")


def check_surbl(host: str) -> dict:
    return _dns_bl(host, "SURBL", "multi.surbl.org")


def check_safe_browsing(target: str, is_ip: bool) -> dict:
    key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")
    if not key:
        return {"source": "Google Safe Browsing", "listed": None, "detail": "not configured"}
    url = "http://" + target if not is_ip else "http://" + target
    body = {
        "client": {"clientId": "osiris", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}",
            json=body,
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
        data = r.json()
        matches = data.get("matches") or []
        if matches:
            types = sorted({m.get("threatType", "") for m in matches})
            return {"source": "Google Safe Browsing", "listed": True, "detail": ", ".join(types)}
        return {"source": "Google Safe Browsing", "listed": False}
    except (requests.RequestException, ValueError):
        return {"source": "Google Safe Browsing", "listed": None, "detail": "lookup failed"}


def check_reputation(target: str) -> dict:
    """Aggregate feed checks for a domain or IP → sources + verdict."""
    target = (target or "").strip().lower().rstrip(".")
    is_ip = _looks_like_ip(target)

    sources = [
        check_urlhaus(target),
        check_spamhaus(target, is_ip),
        check_safe_browsing(target, is_ip),
    ]
    if not is_ip:
        sources.append(check_surbl(target))

    listed = [s for s in sources if s.get("listed") is True]
    verdict = "listed" if listed else ("clean" if any(s.get("listed") is False for s in sources) else "unknown")
    return {
        "target": target,
        "is_ip": is_ip,
        "sources": sources,
        "listed_count": len(listed),
        "verdict": verdict,
    }
