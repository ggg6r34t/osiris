import base64
import copy
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from typing import Callable

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from osiris.clone_detector import detect_clones
from osiris.config import apply_proxy_env
from osiris.data.platforms import PLATFORM_TEMPLATES
from osiris.dnstwist import run_dnstwist
from osiris.domain_matcher import find_similar_domains
from osiris.enrichment import enrich, ip_pivot, is_valid_domain, normalize_domain
from osiris.input_handler import parse_input
from osiris.logger import log_event, log_search_history
from osiris.platform_functions import (
    add_custom_platform,
    load_custom_platforms,
    remove_custom_platform,
)
from osiris.regex_generator import LEVELS as REGEX_LEVELS
from osiris.regex_generator import brand_label, generate_brand_regex
from osiris.run_phishing_dorks import run_phishing_dorks
from osiris import storage
from osiris.search_links import generate_search_links
from osiris.takedown import build_takedown_email
from osiris.text_clone_search import text_clone_search
from osiris.threat_scoring import score_threat
from osiris.utils import build_http_session, dedupe_links, fuzzy_match_platforms
from osiris.variant_generator import generate_typosquatting_domains

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["GET", "POST", "DELETE", "PATCH"],
    allow_headers=["*"],
)


def _run(fn: Callable, *args, **kwargs):
    """Run an upstream domain-intel call, converting unexpected exceptions into a
    502 HTTPException. Exceptions raised inside a handler (rather than a proper
    response) bypass the CORS middleware, so the browser would otherwise see a
    misleading CORS error instead of the real failure. HTTPExceptions pass
    through untouched (they get CORS headers via Starlette's inner handler)."""
    try:
        return fn(*args, **kwargs)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate boundary guard
        raise HTTPException(status_code=502, detail=f"{type(exc).__name__}: {exc}")


_CACHE: dict[str, tuple[float, object]] = {}
_CACHE_TTL_SECONDS = 3600


def _cached(key: str, producer: Callable, refresh: bool = False):
    """Tiny in-process TTL cache for slow/flaky domain-intel lookups. This is a
    single-user local tool, so process memory is sufficient (cleared on restart).
    Exceptions from the producer propagate and are never cached. `refresh=True`
    bypasses the cached value and recomputes."""
    now = time.monotonic()
    if not refresh:
        hit = _CACHE.get(key)
        if hit is not None and now - hit[0] < _CACHE_TTL_SECONDS:
            return hit[1]
    value = producer()
    _CACHE[key] = (now, value)
    return value


def _bounded(fn: Callable, timeout: int):
    """Run fn with a hard wall-clock timeout so a slow/hanging upstream (WHOIS,
    RDAP, cert logs, blocklist downloads) can never spin forever. On timeout we
    return 504 and orphan the worker thread (can't kill it) without blocking."""
    executor = ThreadPoolExecutor(max_workers=1)
    future = executor.submit(fn)
    try:
        result = future.result(timeout=timeout)
        executor.shutdown(wait=False)
        return result
    except FuturesTimeout:
        executor.shutdown(wait=False, cancel_futures=True)
        raise HTTPException(
            status_code=504,
            detail=f"Timed out after {timeout}s — upstream data sources were too "
            "slow. Try again (results cache) or narrow the query.",
        )


def _record(tool: str, input_value: str, summary: dict) -> None:
    """Best-effort history logging — never let it break a tool call."""
    try:
        storage.add_history(tool, input_value, summary)
    except Exception:  # noqa: BLE001
        pass


def _env_proxies() -> dict | None:
    proxies = {}
    if os.getenv("OSIRIS_HTTP_PROXY"):
        proxies["http"] = os.getenv("OSIRIS_HTTP_PROXY")
    if os.getenv("OSIRIS_HTTPS_PROXY"):
        proxies["https"] = os.getenv("OSIRIS_HTTPS_PROXY")
    return proxies or None


def merged_templates() -> dict:
    """Base platform templates deep-merged with user custom platforms.

    Re-reads custom_platforms.json on every call so additions/removals made
    at runtime (via /api/custom-platforms) are reflected immediately.
    """
    templates = copy.deepcopy(PLATFORM_TEMPLATES)
    for category, platforms in (load_custom_platforms() or {}).items():
        if not isinstance(platforms, dict):
            continue
        templates.setdefault(category, {}).update(platforms)
    return templates


# --------------------------------------------------------------------------- #
# Platforms
# --------------------------------------------------------------------------- #
@app.get("/api/platforms")
def get_platforms():
    templates = merged_templates()
    return {
        "categories": list(templates.keys()),
        "platforms": {c: sorted(names) for c, names in templates.items()},
    }


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
class SearchRequest(BaseModel):
    target: str | None = None
    targets: list[str] | None = None
    platforms: list[str] | None = None
    exclude_platforms: list[str] | None = None
    exclude_categories: list[str] | None = None
    fuzzy: bool = False
    dedupe: bool = False
    score: bool = False
    sort_score: bool = False
    max_links: int = 0
    tag: str | None = None
    log: bool = False


@app.post("/api/search")
def search(req: SearchRequest):
    targets = [t.strip() for t in (req.targets or ([req.target] if req.target else [])) if t and t.strip()]
    if not targets:
        raise HTTPException(status_code=422, detail="At least one target is required.")

    templates = merged_templates()
    platforms = parse_input(req.platforms)
    if req.fuzzy:
        platforms = fuzzy_match_platforms(platforms, templates)

    exclude_platforms = {p.strip().lower() for p in (req.exclude_platforms or [])}
    exclude_categories = {c.strip().lower() for c in (req.exclude_categories or [])}

    results: list[dict] = []
    for target in targets:
        links = generate_search_links(target, platforms, templates)

        if exclude_platforms or exclude_categories:
            links = [
                l for l in links
                if l.get("platform", "").lower() not in exclude_platforms
                and l.get("category", "").lower() not in exclude_categories
            ]

        if req.score:
            for link in links:
                threat = score_threat(link.get("url", ""), target)
                link["score"] = threat.get("score")
                link["label"] = threat.get("label")
                link["reasons"] = threat.get("reasons")
            if req.sort_score:
                links.sort(key=lambda l: l.get("score", 0), reverse=True)

        if req.dedupe:
            links = dedupe_links(links, key_fields=("url",))

        if req.max_links and req.max_links > 0:
            links = links[: req.max_links]

        for link in links:
            link["target"] = target
            if req.tag:
                link["tag"] = req.tag

        results.extend(links)

        if req.log:
            log_search_history(target, links)

    if req.log:
        log_event(
            "search_complete",
            {"targets": targets, "links": len(results), "tag": req.tag},
        )

    _record("search", ", ".join(targets), {"count": len(results)})
    return {"targets": targets, "count": len(results), "results": results}


# --------------------------------------------------------------------------- #
# Link reachability check
# --------------------------------------------------------------------------- #
class CheckRequest(BaseModel):
    urls: list[str]
    timeout: int | None = None
    retries: int | None = None
    user_agent: str | None = None
    verify_tls: bool | None = None
    rate_limit: float | None = None  # accepted for parity; concurrency bounds load


MAX_CHECK_URLS = 1000
MAX_BULK_DOMAINS = 25


def _check_one(session: requests.Session, url: str, timeout: int, verify_tls: bool) -> dict:
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True, verify=verify_tls)
        if resp.status_code in {403, 405} or resp.status_code >= 400:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_tls)
        return {"url": url, "ok": resp.status_code < 400, "status": resp.status_code}
    except Exception:  # noqa: BLE001 - one bad URL must not fail the batch
        return {"url": url, "ok": False, "status": None}


@app.post("/api/check")
def check(req: CheckRequest):
    # Cap input to bound resource use. This endpoint issues server-side requests
    # to the supplied URLs; keep it behind localhost-only CORS and do not expose
    # it publicly (SSRF surface inherent to a link checker).
    urls = [u for u in req.urls if u][:MAX_CHECK_URLS]
    if not urls:
        return {"results": []}

    def _int_env(name: str, default: str) -> int:
        # Env values may be stored as float strings (e.g. "12.0" from settings).
        try:
            return int(float(os.getenv(name) or default))
        except (TypeError, ValueError):
            return int(float(default))

    timeout = (
        req.timeout
        if req.timeout is not None
        else _int_env("OSIRIS_CHECK_TIMEOUT", os.getenv("OSIRIS_REQUEST_TIMEOUT", "5"))
    )
    retries = req.retries if req.retries is not None else _int_env("OSIRIS_CHECK_RETRIES", "2")
    verify_tls = (
        req.verify_tls
        if req.verify_tls is not None
        else os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false"
    )
    user_agent = req.user_agent or os.getenv("OSIRIS_USER_AGENT")

    proxies = {}
    if os.getenv("OSIRIS_HTTP_PROXY"):
        proxies["http"] = os.getenv("OSIRIS_HTTP_PROXY")
    if os.getenv("OSIRIS_HTTPS_PROXY"):
        proxies["https"] = os.getenv("OSIRIS_HTTPS_PROXY")

    session = build_http_session(
        user_agent=user_agent, retries=retries, proxies=proxies or None
    )

    rate = (
        req.rate_limit
        if req.rate_limit is not None
        else float(os.getenv("OSIRIS_RATE_LIMIT", "0") or 0)
    )

    if rate and rate > 0:
        # Rate-limited: issue sequentially with a fixed inter-request delay.
        results = []
        for url in urls:
            results.append(_check_one(session, url, timeout, verify_tls))
            time.sleep(1.0 / rate)
    else:
        with ThreadPoolExecutor(max_workers=min(16, len(urls))) as pool:
            results = list(
                pool.map(lambda u: _check_one(session, u, timeout, verify_tls), urls)
            )
    return {"results": results}


# --------------------------------------------------------------------------- #
# Network settings (mirrors cli.py env handling — process-global, per instance)
# --------------------------------------------------------------------------- #
class SettingsRequest(BaseModel):
    user_agent: str | None = None
    verify_tls: bool | None = None
    request_timeout: float | None = None
    rate_limit: float | None = None
    http_proxy: str | None = None
    https_proxy: str | None = None
    tor: bool | None = None


def _current_settings() -> dict:
    return {
        "user_agent": os.getenv("OSIRIS_USER_AGENT", "Osiris/1.0"),
        "verify_tls": os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false",
        "request_timeout": float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "10")),
        "rate_limit": float(os.getenv("OSIRIS_RATE_LIMIT", "0")),
        "http_proxy": os.getenv("OSIRIS_HTTP_PROXY", ""),
        "https_proxy": os.getenv("OSIRIS_HTTPS_PROXY", ""),
    }


@app.get("/api/settings")
def get_settings():
    return _current_settings()


@app.post("/api/settings")
def save_settings(req: SettingsRequest):
    if req.user_agent is not None:
        os.environ["OSIRIS_USER_AGENT"] = req.user_agent
    if req.verify_tls is not None:
        os.environ["OSIRIS_VERIFY_TLS"] = "true" if req.verify_tls else "false"
    if req.request_timeout is not None:
        os.environ["OSIRIS_REQUEST_TIMEOUT"] = str(req.request_timeout)
    if req.rate_limit is not None:
        os.environ["OSIRIS_RATE_LIMIT"] = str(req.rate_limit)

    if req.tor:
        proxy = "socks5h://127.0.0.1:9050"
        os.environ["OSIRIS_HTTP_PROXY"] = proxy
        os.environ["OSIRIS_HTTPS_PROXY"] = proxy
    else:
        if req.http_proxy is not None:
            os.environ["OSIRIS_HTTP_PROXY"] = req.http_proxy
        if req.https_proxy is not None:
            os.environ["OSIRIS_HTTPS_PROXY"] = req.https_proxy

    apply_proxy_env(
        {
            "http_proxy": os.getenv("OSIRIS_HTTP_PROXY", ""),
            "https_proxy": os.getenv("OSIRIS_HTTPS_PROXY", ""),
        }
    )
    return _current_settings()


# --------------------------------------------------------------------------- #
# Custom platforms
# --------------------------------------------------------------------------- #
class CustomPlatformRequest(BaseModel):
    category: str
    name: str
    url: str


class RemoveCustomPlatformRequest(BaseModel):
    category: str
    name: str


@app.get("/api/custom-platforms")
def get_custom_platforms():
    return {"platforms": load_custom_platforms() or {}}


@app.post("/api/custom-platforms")
def create_custom_platform(req: CustomPlatformRequest):
    category = req.category.strip()
    name = req.name.strip()
    url = req.url.strip()
    if not category or not name or not url:
        raise HTTPException(status_code=422, detail="category, name and url are required.")
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        raise HTTPException(
            status_code=422, detail="URL must start with http:// or https://."
        )
    if "{query}" not in url:
        raise HTTPException(status_code=422, detail="URL must include the {query} placeholder.")
    add_custom_platform(category, name, url)
    return {"platforms": load_custom_platforms() or {}}


@app.delete("/api/custom-platforms")
def delete_custom_platform(req: RemoveCustomPlatformRequest):
    remove_custom_platform(req.category.strip(), req.name.strip())
    return {"platforms": load_custom_platforms() or {}}


# --------------------------------------------------------------------------- #
# Domain-intelligence tools (Phase 2)
#
# These make outbound network calls (WHOIS, DNS, HTTP, certificate transparency,
# third-party APIs) and can be slow. Each mirrors a CLI mode and reuses the same
# underlying functions; no server-side files are written and no browser is opened
# server-side (link lists are returned for the client to open).
# --------------------------------------------------------------------------- #
class DomainRequest(BaseModel):
    domain: str
    refresh: bool = False


class TextRequest(BaseModel):
    text: str


class KeywordsRequest(BaseModel):
    keywords: list[str] | str


class DeepSearchRequest(BaseModel):
    target: str
    score: bool = False
    refresh: bool = False


class BulkEnrichRequest(BaseModel):
    domains: list[str]
    refresh: bool = False


class TakedownRequest(BaseModel):
    enrichment: dict | None = None
    domain: str | None = None
    reporter: str = ""
    brand: str = ""


def _valid_domain(domain: str) -> str:
    domain = normalize_domain((domain or "").strip())
    if not domain or not is_valid_domain(domain):
        raise HTTPException(
            status_code=422, detail="Provide a valid domain (e.g. example.com)."
        )
    return domain


@app.post("/api/enrich")
def api_enrich(req: DomainRequest):
    domain = _valid_domain(req.domain)
    result = _cached(
        f"enrich:{domain}",
        lambda: _bounded(lambda: _run(enrich, f"http://{domain}"), 75),
        refresh=req.refresh,
    )
    _record("enrich", domain, {"risk_score": (result or {}).get("risk_score")})
    return result


@app.post("/api/enrich-bulk")
def api_enrich_bulk(req: BulkEnrichRequest):
    domains = []
    for raw in req.domains or []:
        d = normalize_domain((raw or "").strip())
        if d and is_valid_domain(d):
            domains.append(d)
    domains = list(dict.fromkeys(domains))[:MAX_BULK_DOMAINS]
    if not domains:
        raise HTTPException(status_code=422, detail="Provide at least one valid domain.")

    def _one(domain: str) -> dict:
        try:
            data = _cached(
                f"enrich:{domain}",
                lambda: _bounded(lambda: enrich(f"http://{domain}"), 75),
                refresh=req.refresh,
            )
            host = data.get("host") or {}
            whois = data.get("whois") or {}
            return {
                "domain": domain,
                "risk_score": data.get("risk_score"),
                "registrar": (whois.get("domain_info") or {}).get("registrar"),
                "ip": host.get("ip"),
                "country": (host.get("geolocation") or {}).get("country"),
                "lookalikes": len(data.get("lookalike_domains") or []),
            }
        except HTTPException as e:
            return {"domain": domain, "error": str(e.detail)}
        except Exception as e:  # noqa: BLE001
            return {"domain": domain, "error": f"{type(e).__name__}: {e}"}

    with ThreadPoolExecutor(max_workers=min(3, len(domains))) as pool:
        rows = list(pool.map(_one, domains))
    return {"count": len(rows), "results": rows}


@app.post("/api/ip-pivot")
def api_ip_pivot(req: DomainRequest):
    domain = _valid_domain(req.domain)
    result = _cached(
        f"ip-pivot:{domain}",
        lambda: _bounded(lambda: _run(ip_pivot, domain), 60),
        refresh=req.refresh,
    )
    _record("ip-pivot", domain, {"domains": (result or {}).get("domain_count", 0)})
    return result


@app.post("/api/domain-match")
def api_domain_match(req: DomainRequest):
    domain = _valid_domain(req.domain)
    matches = _cached(
        f"domain-match:{domain}",
        lambda: _bounded(lambda: _run(find_similar_domains, domain), 90),
        refresh=req.refresh,
    )
    _record("domain-match", domain, {"matches": len(matches or [])})
    return {"domain": domain, "matches": matches}


@app.post("/api/dnstwist")
def api_dnstwist(req: DomainRequest):
    domain = _valid_domain(req.domain)
    results = _cached(
        f"dnstwist:{domain}",
        lambda: _bounded(lambda: _run(run_dnstwist, domain) or [], 210),
        refresh=req.refresh,
    )
    _record("dnstwist", domain, {"permutations": len(results or [])})
    return {"domain": domain, "results": results}


@app.post("/api/clone-detect")
def api_clone_detect(req: DomainRequest):
    domain = _valid_domain(req.domain)

    def _produce():
        variants = generate_typosquatting_domains(domain)
        clones = _run(detect_clones, domain, variants)
        return {"domain": domain, "variants_checked": len(variants), "clones": clones}

    result = _cached(f"clone-detect:{domain}", lambda: _bounded(_produce, 120), refresh=req.refresh)
    _record("clone-detect", domain, {"clones": len((result or {}).get("clones") or [])})
    return result


class ScreenshotRequest(BaseModel):
    url: str


@app.post("/api/screenshot")
def api_screenshot(req: ScreenshotRequest):
    url = (req.url or "").strip()
    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        raise HTTPException(status_code=422, detail="URL must start with http:// or https://.")

    from osiris.screenshot import ScreenshotUnavailable, capture

    try:
        png = _bounded(lambda: capture(url), 40)
    except ScreenshotUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"Screenshot failed: {e}")

    return {"image": "data:image/png;base64," + base64.b64encode(png).decode()}


@app.post("/api/takedown")
def api_takedown(req: TakedownRequest):
    enrichment = req.enrichment
    if enrichment is None:
        if not req.domain:
            raise HTTPException(
                status_code=422, detail="Provide an enrichment result or a domain."
            )
        domain = _valid_domain(req.domain)
        enrichment = _cached(
            f"enrich:{domain}", lambda: _bounded(lambda: _run(enrich, f"http://{domain}"), 75)
        )
    return build_takedown_email(enrichment, reporter=req.reporter, brand=req.brand)


@app.post("/api/text-clone")
def api_text_clone(req: TextRequest):
    text = (req.text or "").strip()
    if not text:
        raise HTTPException(
            status_code=422, detail="Provide legitimate site text to search for."
        )
    return {"links": _run(text_clone_search, [text], open_browser=False, quiet=True)}


@app.post("/api/phishing-dorks")
def api_phishing_dorks(req: KeywordsRequest):
    raw = req.keywords if isinstance(req.keywords, list) else [req.keywords]
    keywords = [k.strip() for k in raw if k and k.strip()]
    if not keywords:
        raise HTTPException(status_code=422, detail="Provide at least one keyword.")
    return {"links": _run(run_phishing_dorks, keywords, open_browser=False, quiet=True)}


@app.post("/api/deep-search")
def api_deep_search(req: DeepSearchRequest):
    target = (req.target or "").strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target is required.")

    def _produce():
        results: dict = {}
        links: list[dict] = []

        if "." in target:
            base = normalize_domain(target)
            results["enrichment"] = _run(enrich, base, is_url=True)

            typo = _run(find_similar_domains, base, max_whois=0)
            results["typo_domains"] = typo
            links.extend(
                {"platform": "Lookalike Domain", "category": "domain", "url": f"http://{d['domain']}"}
                for d in typo
                if isinstance(d, dict) and d.get("domain")
            )

            clones = _run(
                detect_clones,
                base,
                [d["domain"] for d in typo if isinstance(d, dict) and d.get("domain")],
            )
            results["clone_sites"] = clones
            links.extend(
                {"platform": "Clone Candidate", "category": "domain", "url": f"http://{d}"}
                for d in clones
                if isinstance(d, str)
            )

        text_clones = _run(text_clone_search, [target], open_browser=False, quiet=True)
        results["text_clones"] = text_clones
        links += text_clones

        links += generate_search_links(target, ["all"], merged_templates())

        dorks = _run(run_phishing_dorks, [target], open_browser=False, quiet=True)
        results["phishing_dorks"] = dorks
        links += dorks

        if req.score:
            for link in links:
                threat = score_threat(link.get("url", ""), target)
                link["score"] = threat.get("score")
                link["label"] = threat.get("label")
                link["reasons"] = threat.get("reasons")

        for link in links:
            link["target"] = target

        return {"target": target, "results": results, "count": len(links), "links": links}

    result = _cached(
        f"deep-search:{target}:{req.score}",
        lambda: _bounded(_produce, 200),
        refresh=req.refresh,
    )
    _record("deep-search", target, {"count": (result or {}).get("count", 0)})
    return result


# --------------------------------------------------------------------------- #
# Brand-abuse / violation search via the Panda regex API
#
# Host + credentials come from the environment so nothing sensitive is
# committed: OSIRIS_PANDA_URL, OSIRIS_PANDA_LOGIN, OSIRIS_PANDA_KEY.
# --------------------------------------------------------------------------- #
class RegexRequest(BaseModel):
    regex: str
    id_only: bool = False
    refresh: bool = False


class RegexGenRequest(BaseModel):
    value: str
    level: str = "balanced"


@app.post("/api/generate-regex")
def api_generate_regex(req: RegexGenRequest):
    value = (req.value or "").strip()
    if not value:
        raise HTTPException(status_code=422, detail="Provide a brand or domain.")
    level = req.level if req.level in REGEX_LEVELS else "balanced"
    regex = generate_brand_regex(value, level)
    if not regex:
        raise HTTPException(status_code=422, detail="Couldn't derive a brand from that input.")
    label = brand_label(value)
    brand_len = len(re.sub(r"[\s._-]", "", label))
    return {"regex": regex, "level": level, "brand": label, "short": brand_len < 4}


_DOMAIN_FIELD_CANDIDATES = ("domain", "url", "host", "hostname", "fqdn", "site", "name")
_DOMAIN_RE = re.compile(
    r"\b((?:https?://)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b",
    re.IGNORECASE,
)


def _extract_domain(record: dict) -> str | None:
    """Best-effort domain/URL extraction from an arbitrary Panda record."""
    for field in _DOMAIN_FIELD_CANDIDATES:
        value = record.get(field)
        if isinstance(value, str) and "." in value:
            return value.strip()
    for value in record.values():
        if isinstance(value, str):
            match = _DOMAIN_RE.search(value)
            if match:
                return match.group(1)
    return None


def _normalize_panda(payload: dict) -> list[dict]:
    """Normalize the Panda `data` blob (dict or list) into flat result rows.
    Each row: {id, domain, url, raw}. Pure/offline — unit-tested."""
    data = (payload or {}).get("data") or {}
    if isinstance(data, dict):
        items = list(data.items())
    elif isinstance(data, list):
        items = list(enumerate(data))
    else:
        items = []

    results = []
    for key, value in items:
        if isinstance(value, dict):
            rid = value.get("_id") or key
            domain = _extract_domain(value)
            raw = value
        else:
            rid, domain, raw = value, None, None
        url = None
        if domain:
            url = domain if domain.lower().startswith(("http://", "https://")) else f"http://{domain}"
        results.append({"id": str(rid), "domain": domain, "url": url, "raw": raw})
    return results


@app.post("/api/brand-abuse")
def api_brand_abuse(req: RegexRequest):
    regex = (req.regex or "").strip()
    if not regex:
        raise HTTPException(status_code=422, detail="Provide a regex pattern.")

    base = os.getenv("OSIRIS_PANDA_URL")
    login = os.getenv("OSIRIS_PANDA_LOGIN")
    key = os.getenv("OSIRIS_PANDA_KEY")
    if not base or not login or not key:
        raise HTTPException(
            status_code=503,
            detail="Panda API is not configured. Set OSIRIS_PANDA_URL, "
            "OSIRIS_PANDA_LOGIN and OSIRIS_PANDA_KEY (VPN required to reach it).",
        )

    def _produce():
        session = build_http_session(
            user_agent=os.getenv("OSIRIS_USER_AGENT"), proxies=_env_proxies()
        )
        verify_tls = os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false"
        try:
            timeout = float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "30") or 30)
        except ValueError:
            timeout = 30.0

        resp = session.get(
            base,
            headers={"X-Auth-Login": login, "X-Auth-Key": key},
            params={
                "action": "findByRegexp",
                "id_only": "true" if req.id_only else "false",
                "regexp": regex,  # requests URL-encodes this correctly
            },
            timeout=timeout,
            verify=verify_tls,
        )
        resp.raise_for_status()
        results = _normalize_panda(resp.json())
        return {"regex": regex, "count": len(results), "results": results}

    result = _cached(
        f"brand-abuse:{req.id_only}:{regex}",
        lambda: _bounded(lambda: _run(_produce), 60),
        refresh=req.refresh,
    )
    _record("brand-abuse", regex, {"count": (result or {}).get("count", 0)})
    return result


# --------------------------------------------------------------------------- #
# History + Cases (local SQLite persistence)
# --------------------------------------------------------------------------- #
class CaseCreate(BaseModel):
    name: str
    note: str = ""


class CaseItemCreate(BaseModel):
    kind: str = "note"
    data: dict | str = ""
    note: str = ""
    status: str = "open"


class CaseItemUpdate(BaseModel):
    note: str | None = None
    status: str | None = None


@app.get("/api/history")
def get_history(limit: int = 100):
    return {"history": storage.list_history(limit=limit)}


@app.delete("/api/history")
def delete_history():
    storage.clear_history()
    return {"ok": True}


@app.get("/api/cases")
def get_cases():
    return {"cases": storage.list_cases()}


@app.post("/api/cases")
def create_case(req: CaseCreate):
    name = req.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Case name is required.")
    case_id = storage.create_case(name, req.note)
    return storage.get_case(case_id)


@app.get("/api/cases/{case_id}")
def read_case(case_id: int):
    case = storage.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@app.delete("/api/cases/{case_id}")
def remove_case(case_id: int):
    storage.delete_case(case_id)
    return {"ok": True}


@app.post("/api/cases/{case_id}/items")
def add_item(case_id: int, req: CaseItemCreate):
    if not storage.get_case(case_id):
        raise HTTPException(status_code=404, detail="Case not found.")
    storage.add_case_item(case_id, req.kind, req.data, req.note, req.status)
    return storage.get_case(case_id)


@app.patch("/api/cases/items/{item_id}")
def patch_item(item_id: int, req: CaseItemUpdate):
    storage.update_case_item(item_id, req.note, req.status)
    return {"ok": True}


@app.delete("/api/cases/items/{item_id}")
def remove_item(item_id: int):
    storage.delete_case_item(item_id)
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Monitoring (watchlist + re-run + diff)
# --------------------------------------------------------------------------- #
class WatchRequest(BaseModel):
    target: str


@app.get("/api/watchlist")
def get_watchlist():
    return {"watchlist": storage.list_watch()}


@app.post("/api/watchlist")
def add_watchlist(req: WatchRequest):
    storage.add_watch(_valid_domain(req.target))
    return {"watchlist": storage.list_watch()}


@app.delete("/api/watchlist")
def delete_watchlist(req: WatchRequest):
    storage.remove_watch(req.target.strip())
    return {"watchlist": storage.list_watch()}


@app.post("/api/monitor/run")
def api_monitor_run(req: WatchRequest):
    from osiris.monitor import run_monitor

    target = _valid_domain(req.target)
    report = _bounded(lambda: run_monitor(target), 240)
    new_count = sum(len(r.get("new") or []) for r in report.values())
    _record("monitor", target, {"new": new_count})
    return {"target": target, "report": report}


# --------------------------------------------------------------------------- #
# Alerting (Telegram / webhook) — opt-in via env, off by default
# --------------------------------------------------------------------------- #
@app.get("/api/notify/status")
def api_notify_status():
    from osiris import notify

    return {"channels": notify.channels()}


@app.post("/api/notify/test")
def api_notify_test():
    from osiris import notify

    ch = notify.channels()
    if not (ch["telegram"] or ch["webhook"]):
        return {"configured": False, "channels": ch, "results": {}}
    results = notify.notify(
        "[Osiris] Test alert — alerting is configured and working.",
        {"test": True},
    )
    return {"configured": True, "channels": ch, "results": results}


# --------------------------------------------------------------------------- #
# VIP investigation — protective-intelligence exposure assessment
# --------------------------------------------------------------------------- #
class VipRequest(BaseModel):
    name: str
    aliases: list[str] = []
    emails: list[str] = []
    usernames: list[str] = []
    company: str = ""
    country: str = ""
    known_impersonations: int = 0


@app.post("/api/vip/assess")
def api_vip_assess(req: VipRequest):
    from osiris.vip import assess_vip

    name = (req.name or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="A VIP name is required.")

    scorecard = _bounded(lambda: _run(assess_vip, req.model_dump()), 180)
    _record(
        "vip",
        name,
        {
            "overall_score": scorecard.get("overall_score"),
            "levels": scorecard.get("levels"),
        },
    )
    return scorecard
