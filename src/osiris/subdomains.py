"""Subdomain enumeration via certificate-transparency logs (crt.sh) — keyless.

Maps a domain's attack surface: every subdomain that has ever appeared in a
public TLS certificate. Optionally resolves a capped number to flag which are
currently live (useful for spotting forgotten dev/staging hosts or phishing
subdomains on a compromised domain).
"""
import concurrent.futures
import socket
import time
import urllib.parse

import requests

from osiris.enrichment import get_proxies, get_request_timeout

_CRT = "https://crt.sh/"
_RESOLVE_CAP = 150  # only resolve this many (enumeration can return hundreds)


def _norm(domain: str) -> str:
    d = (domain or "").strip().lower()
    if d.startswith(("http://", "https://")):
        d = urllib.parse.urlparse(d).netloc or d
    return d.strip("/").split("/")[0]


def _resolve(name: str):
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None


def enumerate_subdomains(domain: str, resolve_cap: int = _RESOLVE_CAP) -> dict:
    domain = _norm(domain)
    if not domain:
        return {"domain": domain, "found": False, "error": "no domain", "total": 0, "checked": 0, "resolved": 0, "subdomains": []}

    timeout = max(get_request_timeout(), 25)
    proxies = get_proxies()
    data = None
    for attempt in range(3):  # crt.sh is frequently slow / 5xx
        try:
            r = requests.get(
                _CRT,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=timeout,
                proxies=proxies,
                headers={"User-Agent": "Osiris-Subdomains/1.0"},
            )
            if r.status_code == 200 and r.text.strip():
                data = r.json()
                break
        except (requests.RequestException, ValueError):
            pass
        time.sleep(1.5 * (attempt + 1))
    if data is None:
        return {"domain": domain, "found": False, "error": "crt.sh unavailable (slow / rate-limited) — try again", "total": 0, "checked": 0, "resolved": 0, "subdomains": []}

    names = set()
    suffix = "." + domain
    for entry in data:
        if not isinstance(entry, dict):
            continue
        raw = (entry.get("name_value") or "") + "\n" + (entry.get("common_name") or "")
        for n in raw.split("\n"):
            n = n.strip().lower().lstrip("*.").strip()
            if not n or "@" in n or " " in n:
                continue
            if n == domain or n.endswith(suffix):
                names.add(n)

    ordered = sorted(names)
    to_check = ordered[:resolve_cap]
    resolved_map = {}
    if to_check:
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            futures = {pool.submit(_resolve, n): n for n in to_check}
            for fut in concurrent.futures.as_completed(futures):
                resolved_map[futures[fut]] = fut.result()

    subdomains = []
    for n in ordered:
        if n in resolved_map:
            ip = resolved_map[n]
            subdomains.append({"name": n, "resolves": ip is not None, "ip": ip})
        else:
            subdomains.append({"name": n, "resolves": None, "ip": None})
    # live first, then alphabetical
    subdomains.sort(key=lambda s: (s["resolves"] is not True, s["name"]))

    return {
        "domain": domain,
        "found": True,
        "total": len(ordered),
        "checked": len(to_check),
        "resolved": sum(1 for v in resolved_map.values() if v),
        "subdomains": subdomains,
        "source": "crt.sh",
    }
