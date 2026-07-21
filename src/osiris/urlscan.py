"""urlscan.io live scanning (requires URLSCAN_API_KEY).

Submits a URL to urlscan.io, which renders it in a real browser on *their*
infrastructure (never ours — no SSRF, and the target never sees our IP), then
polls for the result and normalizes it: verdict + score, targeted brands,
screenshot, page facts, and the contacted-infrastructure map (IPs / domains /
ASNs) for campaign pivoting.

Default visibility is 'unlisted' so a live phishing scan is not exposed in
urlscan's public search (which would tip off the attacker).
"""
import os
import time
from typing import Optional

import requests

from osiris.enrichment import get_proxies, get_request_timeout

_SUBMIT = "https://urlscan.io/api/v1/scan/"
_VALID_VISIBILITY = {"public", "unlisted", "private"}


class UrlscanError(Exception):
    """Raised for configuration or submission errors surfaced to the UI."""


def _key() -> Optional[str]:
    return os.getenv("URLSCAN_API_KEY")


def configured() -> bool:
    return bool(_key())


def _brand_names(brands) -> list:
    out = []
    for b in brands or []:
        if isinstance(b, dict) and b.get("name"):
            out.append(b["name"])
        elif isinstance(b, str):
            out.append(b)
    return out


def scan(url: str, visibility: str = "unlisted", wait_timeout: int = 55) -> dict:
    key = _key()
    if not key:
        raise UrlscanError("urlscan.io not configured — set URLSCAN_API_KEY.")
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if visibility not in _VALID_VISIBILITY:
        visibility = "unlisted"

    headers = {"API-Key": key, "Content-Type": "application/json"}
    proxies = get_proxies()
    timeout = get_request_timeout()

    # 1) Submit
    try:
        r = requests.post(
            _SUBMIT,
            json={"url": url, "visibility": visibility, "tags": ["osiris"]},
            headers=headers,
            timeout=timeout,
            proxies=proxies,
        )
    except requests.RequestException as e:
        raise UrlscanError(f"submit failed: {e.__class__.__name__}") from e
    if r.status_code == 401:
        raise UrlscanError("urlscan.io rejected the API key (401).")
    if r.status_code == 429:
        raise UrlscanError("urlscan.io rate limit hit (429) — try again shortly.")
    if r.status_code >= 400:
        detail = ""
        try:
            detail = r.json().get("message", "")
        except ValueError:
            pass
        raise UrlscanError(f"submit rejected (HTTP {r.status_code}) {detail}".strip())
    sub = r.json()
    uuid = sub.get("uuid")
    api_url = sub.get("api") or f"https://urlscan.io/api/v1/result/{uuid}/"
    result_url = sub.get("result") or f"https://urlscan.io/result/{uuid}/"

    # 2) Poll the result (urlscan returns 404 until the scan finishes)
    deadline = time.time() + wait_timeout
    data = None
    time.sleep(6)
    while time.time() < deadline:
        try:
            rr = requests.get(api_url, headers={"API-Key": key}, timeout=timeout, proxies=proxies)
        except requests.RequestException:
            time.sleep(3)
            continue
        if rr.status_code == 200:
            data = rr.json()
            break
        time.sleep(3)

    if data is None:
        return {
            "configured": True,
            "pending": True,
            "uuid": uuid,
            "result_url": result_url,
            "visibility": visibility,
        }

    # 3) Normalize
    task = data.get("task") or {}
    page = data.get("page") or {}
    verdicts = data.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    lists = data.get("lists") or {}

    return {
        "configured": True,
        "pending": False,
        "uuid": uuid,
        "result_url": task.get("reportURL") or result_url,
        "screenshot": task.get("screenshotURL"),
        "visibility": task.get("visibility") or visibility,
        "verdict": {
            "malicious": bool(overall.get("malicious")),
            "score": overall.get("score", 0),
            "brands": _brand_names(overall.get("brands")),
            "categories": overall.get("categories") or [],
            "tags": overall.get("tags") or [],
        },
        "page": {
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "country": page.get("country"),
            "server": page.get("server"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "title": page.get("title"),
            "tls_issuer": page.get("tlsIssuer"),
            "status": page.get("status"),
        },
        "infrastructure": {
            "ips": lists.get("ips") or [],
            "domains": lists.get("domains") or [],
            "asns": lists.get("asns") or [],
            "servers": lists.get("servers") or [],
            "countries": lists.get("countries") or [],
        },
    }
