"""Wayback Machine (archive.org) history for a domain — keyless.

Uses the CDX API to summarize a domain's archival history: first and last
capture, how many years it was archived, and a per-year snapshot timeline with
direct links. Useful phishing/clone context — what a domain looked like before,
and when its content changed.
"""
import time
import urllib.parse

import requests

from osiris.enrichment import get_proxies, get_request_timeout

_CDX = "https://web.archive.org/cdx/search/cdx"


def _empty(domain: str, overview: str, error: str | None = None) -> dict:
    out = {"domain": domain, "found": False, "years": 0, "first": None, "last": None,
           "timeline": [], "overview_url": overview}
    if error:
        out["error"] = error
    return out


def _norm(domain: str) -> str:
    d = (domain or "").strip().lower()
    if d.startswith(("http://", "https://")):
        d = urllib.parse.urlparse(d).netloc or d
    return d.strip("/").split("/")[0]


def _fmt_date(ts: str) -> str:
    # CDX timestamp is YYYYMMDDhhmmss
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts


def _snapshot_url(ts: str, original: str) -> str:
    return f"https://web.archive.org/web/{ts}/{original}"


def history(domain: str) -> dict:
    domain = _norm(domain)
    overview = f"https://web.archive.org/web/*/{domain}"
    if not domain:
        return _empty(domain, overview, "no domain")

    timeout = max(get_request_timeout(), 20)
    proxies = get_proxies()
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "collapse": "timestamp:4",  # one capture per year
        "limit": 200,
    }
    rows = None
    for attempt in range(3):  # CDX 503s / rate-limits frequently
        try:
            r = requests.get(_CDX, params=params, timeout=timeout, proxies=proxies)
            if r.status_code == 200:
                rows = r.json()
                break
        except (requests.RequestException, ValueError):
            pass
        time.sleep(1.5 * (attempt + 1))
    if rows is None:
        return _empty(domain, overview, "archive.org unavailable (rate-limited?) — try again")

    # First row is the CDX header; drop it.
    data = rows[1:] if rows and isinstance(rows[0], list) and rows[0] and rows[0][0] == "timestamp" else rows
    if not data:
        return _empty(domain, overview)

    timeline = []
    for row in data:
        if len(row) < 2:
            continue
        ts, original = row[0], row[1]
        status = row[2] if len(row) > 2 else ""
        timeline.append(
            {
                "date": _fmt_date(ts),
                "timestamp": ts,
                "url": _snapshot_url(ts, original),
                "status": status,
            }
        )
    timeline.sort(key=lambda x: x["timestamp"])

    return {
        "domain": domain,
        "found": True,
        "years": len(timeline),
        "first": timeline[0] if timeline else None,
        "last": timeline[-1] if timeline else None,
        "timeline": timeline,
        "overview_url": overview,
    }
