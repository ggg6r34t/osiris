"""Live URL / phishing-page analysis.

Safely fetch a URL (HTML only, no JS execution) and surface what a CERT needs to
judge a reported phishing link: the redirect chain, credential-harvesting form
detection (esp. forms posting cross-domain), targeted-brand impersonation
(brand named on the page vs. the actual domain), meta-refresh redirects,
extracted IOCs, and a rolled-up risk level.
"""
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from osiris.enrichment import get_proxies, get_request_timeout
from osiris.ioc import extract_iocs

import os
import requests

_MAX_HTML = 2_000_000  # cap parsed HTML at ~2MB

# Brand → keywords commonly impersonated in phishing.
_BRANDS = {
    "paypal": ["paypal"],
    "microsoft": ["microsoft", "office365", "office 365", "outlook", "onedrive"],
    "apple": ["apple", "icloud", "apple id", "appleid"],
    "google": ["google", "gmail"],
    "amazon": ["amazon"],
    "netflix": ["netflix"],
    "facebook": ["facebook", "meta"],
    "instagram": ["instagram"],
    "linkedin": ["linkedin"],
    "whatsapp": ["whatsapp"],
    "dhl": ["dhl"],
    "ups": ["ups"],
    "fedex": ["fedex"],
    "usps": ["usps"],
    "coinbase": ["coinbase"],
    "binance": ["binance"],
    "chase": ["chase"],
    "wellsfargo": ["wells fargo", "wellsfargo"],
    "bankofamerica": ["bank of america", "bankofamerica"],
    "docusign": ["docusign"],
    "steam": ["steam"],
}


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.title_parts = []
        self.text_parts = []
        self._in_form = False
        self._in_title = False
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._in_form = True
            self._cur = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
        elif tag == "input" and self._in_form and self._cur is not None:
            self._cur["inputs"].append((a.get("type") or "text").lower())
        elif tag == "input" and self._cur is None:
            # capture stray password inputs even outside a <form>
            if (a.get("type") or "").lower() == "password":
                self.forms.append({"action": "", "method": "", "inputs": ["password"], "orphan": True})
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag):
        if tag == "form" and self._in_form and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None
            self._in_form = False
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title_parts.append(data)
        text = data.strip()
        if text:
            self.text_parts.append(text)


def _reg_domain(host: str) -> str:
    """Naive registrable domain: last two labels (good enough for brand/domain
    comparison)."""
    host = (host or "").lower().split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze_url(url: str) -> dict:
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    headers = {"User-Agent": os.getenv("OSIRIS_USER_AGENT", "Mozilla/5.0 (compatible; Osiris-URLAnalyzer/1.0)")}
    verify = os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false"
    try:
        resp = requests.get(
            url,
            timeout=get_request_timeout(),
            allow_redirects=True,
            headers=headers,
            proxies=get_proxies(),
            verify=verify,
            stream=True,
        )
        raw = resp.raw.read(_MAX_HTML, decode_content=True) or b""
        html = raw.decode(resp.encoding or "utf-8", errors="replace")
    except requests.RequestException as e:
        return {"input": url, "error": e.__class__.__name__, "reachable": False}

    chain = [
        {"url": h.url, "status": h.status_code, "server": h.headers.get("server", "")}
        for h in resp.history
    ]
    chain.append({"url": resp.url, "status": resp.status_code, "server": resp.headers.get("server", "")})
    result = assess_page(html, resp.url, chain, resp.status_code)
    result["input"] = url
    result["reachable"] = True
    return result


def assess_page(html: str, final_url: str, chain: list | None = None, status: int = 200) -> dict:
    """Analyze already-fetched HTML for phishing signals (pure — no network)."""
    chain = chain or [{"url": final_url, "status": status, "server": ""}]
    final_host = urlparse(final_url).hostname or ""
    final_reg = _reg_domain(final_host)

    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001
        pass
    title = " ".join(" ".join(parser.title_parts).split())[:200]
    page_text = " ".join(parser.text_parts).lower()

    # Forms
    forms = []
    for f in parser.forms:
        action = f.get("action", "")
        resolved = urljoin(final_url, action) if action else final_url
        action_host = urlparse(resolved).hostname or final_host
        has_pw = "password" in f.get("inputs", [])
        cross = _reg_domain(action_host) != final_reg and bool(action)
        forms.append({
            "action": resolved,
            "method": f.get("method", ""),
            "has_password": has_pw,
            "cross_domain": cross,
            "suspicious_scheme": action.lower().startswith(("javascript:", "data:")),
            "input_count": len(f.get("inputs", [])),
        })

    # Targeted-brand impersonation
    haystack = (title + " " + page_text).lower()
    brands = []
    for brand, kws in _BRANDS.items():
        if any(kw in haystack for kw in kws) and brand not in final_reg:
            brands.append(brand)

    meta_refresh = bool(re.search(r'http-equiv=["\']?refresh["\']?[^>]*url=', html, re.I))

    iocs = extract_iocs(html)

    # Flags + risk
    flags = []
    cred_forms = [f for f in forms if f["has_password"]]
    for f in cred_forms:
        if f["cross_domain"]:
            flags.append({"level": "high", "text": f"Credential form posts to a different domain ({urlparse(f['action']).hostname})"})
        elif f["suspicious_scheme"]:
            flags.append({"level": "high", "text": "Credential form uses javascript:/data: action"})
        else:
            flags.append({"level": "medium", "text": "Password/credential form present"})
    if brands:
        flags.append({"level": "high", "text": f"Page impersonates {', '.join(brands)} but is hosted on {final_reg}"})
    if cred_forms and urlparse(final_url).scheme != "https":
        flags.append({"level": "medium", "text": "Credential form served over plain HTTP"})
    if meta_refresh:
        flags.append({"level": "low", "text": "Meta-refresh redirect on page"})
    cross_domain_hops = len({_reg_domain(urlparse(h["url"]).hostname or "") for h in chain}) > 1
    if cross_domain_hops:
        flags.append({"level": "low", "text": f"Redirects across {len(chain)} hops / multiple domains"})

    highs = sum(1 for f in flags if f["level"] == "high")
    risk = "high" if highs else ("medium" if any(f["level"] == "medium" for f in flags) else "low")

    return {
        "final_url": final_url,
        "status_code": status,
        "final_domain": final_reg,
        "title": title,
        "redirect_chain": chain,
        "forms": forms,
        "credential_forms": len(cred_forms),
        "targeted_brands": brands,
        "meta_refresh": meta_refresh,
        "flags": sorted(flags, key=lambda f: -{"high": 3, "medium": 2, "low": 1}[f["level"]]),
        "risk": risk,
        "iocs": iocs,
    }
