"""VIP investigation: a protective-intelligence digital-exposure assessment.

Given a VIP's identifiers (name/aliases, emails, known handles, company, country)
produce a *defensive* exposure scorecard:

  - online-presence volume        (high / medium / low)
  - account impersonations         (investigator-confirmed count + hunt pivots)
  - service-account discoverability (high / medium / low, from breach + resolution)
  - geo-location risk              (high / medium / low, coarse + overridable)
  - family / business associates   (investigator pivots)
  - overall exposure score         (0-100)

Design intent: this measures RISK LEVELS and hands the investigator search
pivots. It deliberately does NOT enumerate or store sensitive personal content
(e.g. specific adult-service accounts). It is meant for authorized executive-
protection / digital-risk-protection work.
"""
import concurrent.futures
import json
import os
import urllib.parse
from typing import Optional

import requests

from osiris.enrichment import get_request_timeout, get_proxies
from osiris.platform_functions import load_platform_templates
from osiris.search_links import generate_search_links

# Direct profile-URL patterns for handle resolution (Sherlock-style). A 200
# response is treated as "handle exists" — a heuristic (some sites soft-404 with
# 200), so results feed a RISK LEVEL rather than a hard claim.
PROFILE_URL_PATTERNS = {
    "GitHub": "https://github.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "X / Twitter": "https://x.com/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Reddit": "https://www.reddit.com/user/{u}/",
    "Telegram": "https://t.me/{u}",
    "Facebook": "https://www.facebook.com/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "Twitch": "https://www.twitch.tv/{u}",
    "Medium": "https://medium.com/@{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Keybase": "https://keybase.io/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Patreon": "https://www.patreon.com/{u}",
    "Linktree": "https://linktr.ee/{u}",
    "About.me": "https://about.me/{u}",
    "Gravatar": "https://gravatar.com/{u}",
}

# Coarse geo-risk starter tiers (overridable — see _load_geo_tiers). Judgement
# call by design — a defensible default, not an authoritative index.
_GEO_HIGH = {
    "afghanistan", "syria", "yemen", "somalia", "south sudan", "libya", "iraq",
    "mali", "sudan", "myanmar", "haiti", "venezuela", "north korea",
    "central african republic", "democratic republic of the congo",
}
_GEO_LOW = {
    "iceland", "norway", "switzerland", "denmark", "finland", "new zealand",
    "canada", "japan", "singapore", "australia", "netherlands", "sweden",
    "ireland", "luxembourg", "austria",
}
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_LEVEL_SCORE = {"low": 12, "medium": 50, "high": 88, "unknown": 40}

# Weights for the overall exposure score (sum = 1.0).
_WEIGHTS = {
    "presence": 0.25,
    "discoverability": 0.35,
    "geo": 0.20,
    "impersonation": 0.20,
}


def _clean_handle(u: str) -> str:
    return u.strip().lstrip("@").strip("/").strip()


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": os.getenv(
                "OSIRIS_USER_AGENT",
                "Mozilla/5.0 (compatible; Osiris-VIP/1.0)",
            )
        }
    )
    return s


def _check_handle(session: requests.Session, platform: str, url: str) -> Optional[dict]:
    timeout = get_request_timeout()
    verify = os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false"
    proxies = get_proxies()
    try:
        r = session.head(
            url, timeout=timeout, allow_redirects=True, verify=verify, proxies=proxies
        )
        if r.status_code in {403, 405} or r.status_code >= 400:
            r = session.get(
                url, timeout=timeout, allow_redirects=True, verify=verify, proxies=proxies
            )
        if r.status_code == 200:
            return {"platform": platform, "url": url}
    except requests.RequestException:
        return None
    return None


def resolve_handles(usernames: list[str]) -> list[dict]:
    """Resolve each handle across PROFILE_URL_PATTERNS; return the profiles that
    appear to exist (HTTP 200). Runs concurrently."""
    handles = sorted({_clean_handle(u) for u in usernames if _clean_handle(u)})
    if not handles:
        return []
    session = _session()
    jobs = []
    for u in handles:
        enc = urllib.parse.quote(u, safe="")
        for platform, pattern in PROFILE_URL_PATTERNS.items():
            jobs.append((u, platform, pattern.replace("{u}", enc)))

    found: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = {
            pool.submit(_check_handle, session, platform, url): username
            for (username, platform, url) in jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                res["username"] = futures[fut]
                found.append(res)
    return sorted(found, key=lambda r: (r["username"], r["platform"]))


def check_hibp(email: str) -> dict:
    """Have I Been Pwned breach lookup for an email. Opt-in via
    HAVEIBEENPWNED_API_KEY; a graceful no-op (configured=False) without a key."""
    key = os.getenv("HAVEIBEENPWNED_API_KEY")
    if not key:
        return {"email": email, "configured": False, "count": 0, "breaches": []}
    url = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(email, safe="")
        + "?truncateResponse=true"
    )
    try:
        r = requests.get(
            url,
            headers={"hibp-api-key": key, "User-Agent": "Osiris-VIP"},
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
        if r.status_code == 404:
            return {"email": email, "configured": True, "count": 0, "breaches": []}
        if r.status_code == 200:
            names = [b.get("Name", "") for b in r.json() if isinstance(b, dict)]
            names = [n for n in names if n]
            return {
                "email": email,
                "configured": True,
                "count": len(names),
                "breaches": names,
            }
        return {
            "email": email,
            "configured": True,
            "count": 0,
            "breaches": [],
            "error": f"HTTP {r.status_code}",
        }
    except requests.RequestException as e:
        return {
            "email": email,
            "configured": True,
            "count": 0,
            "breaches": [],
            "error": e.__class__.__name__,
        }


# --------------------------------------------------------------------------- #
# Mention volume (Brave Search — opt-in, graceful without a key)
# --------------------------------------------------------------------------- #
_BRAVE_API = "https://api.search.brave.com/res/v1/web/search"


def mention_level(sig: dict) -> str:
    """Bucket Brave signals into a mention-volume level. Brave does not expose a
    raw total-result count, so this is a heuristic proxy from knowledge-panel
    presence, web-result density (+ more-available), and news coverage."""
    if not sig or not sig.get("configured") or sig.get("error"):
        return "unknown"
    score = 0
    if sig.get("has_infobox"):
        score += 3  # a knowledge entity is a strong notability signal
    web = sig.get("web_results", 0)
    if web >= 15 and sig.get("more_results_available"):
        score += 2
    elif web >= 8:
        score += 1
    if sig.get("news_results", 0) >= 3:
        score += 1
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def brave_search(query: str) -> dict:
    """Query Brave Search for name-mention signals. Opt-in via
    BRAVE_SEARCH_API_KEY; returns configured=False (no network) without a key."""
    key = os.getenv("BRAVE_SEARCH_API_KEY")
    if not key:
        return {"configured": False, "level": "unknown", "query": query}
    try:
        r = requests.get(
            _BRAVE_API,
            params={"q": query, "count": 20},
            headers={"X-Subscription-Token": key, "Accept": "application/json"},
            timeout=get_request_timeout(),
            proxies=get_proxies(),
        )
        if r.status_code != 200:
            return {
                "configured": True,
                "level": "unknown",
                "query": query,
                "error": f"HTTP {r.status_code}",
            }
        data = r.json()
        web = ((data.get("web") or {}).get("results")) or []
        news = ((data.get("news") or {}).get("results")) or []
        sig = {
            "configured": True,
            "query": query,
            "web_results": len(web),
            "news_results": len(news),
            "has_infobox": bool(data.get("infobox")),
            "more_results_available": bool(
                (data.get("query") or {}).get("more_results_available")
            ),
        }
        sig["level"] = mention_level(sig)
        return sig
    except requests.RequestException as e:
        return {
            "configured": True,
            "level": "unknown",
            "query": query,
            "error": e.__class__.__name__,
        }


# --------------------------------------------------------------------------- #
# Scoring (pure functions — unit-tested)
# --------------------------------------------------------------------------- #
_ORDER = {"low": 1, "medium": 2, "high": 3}


def footprint_level(resolved_count: int, has_handles: bool) -> str:
    """Account-footprint level from how many platforms a handle resolves on."""
    if not has_handles:
        return "unknown"
    if resolved_count >= 8:
        return "high"
    if resolved_count >= 3:
        return "medium"
    return "low"


def presence_level(
    resolved_count: int, has_handles: bool, mention: str = "unknown"
) -> str:
    """Blend account footprint with name-mention volume — presence is High if
    strong on EITHER axis; falls back to whichever signal is available."""
    footprint = footprint_level(resolved_count, has_handles)
    m = mention if mention in _ORDER else "unknown"
    if footprint == "unknown" and m == "unknown":
        return "unknown"
    if footprint == "unknown":
        return m
    if m == "unknown":
        return footprint
    return max((footprint, m), key=lambda lvl: _ORDER[lvl])


def discoverability_level(breach_count: int, resolved_count: int, hibp_on: bool) -> str:
    if not hibp_on and resolved_count == 0:
        return "unknown"
    score = breach_count * 2 + resolved_count
    if breach_count >= 4 or score >= 12:
        return "high"
    if breach_count >= 1 or score >= 5:
        return "medium"
    return "low"


def _geo_file_path() -> Optional[str]:
    """Resolve the optional geo-risk override file: OSIRIS_GEO_RISK_FILE if set,
    else an auto-discovered geo_risk.json at the repo root."""
    override = os.getenv("OSIRIS_GEO_RISK_FILE")
    if override:
        return override
    candidate = os.path.join(_REPO_ROOT, "geo_risk.json")
    return candidate if os.path.exists(candidate) else None


def _load_geo_tiers() -> dict:
    """Built-in tiers merged with an optional override file. The file may be
    either {"high": [...], "medium": [...], "low": [...]} or a flat
    {"country name": "high", ...} map. File entries win over built-ins."""
    tiers = {c: "high" for c in _GEO_HIGH}
    tiers.update({c: "low" for c in _GEO_LOW})

    path = _geo_file_path()
    if not path or not os.path.exists(path):
        return tiers
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return tiers
    if not isinstance(data, dict):
        return tiers

    if any(k in data for k in ("high", "medium", "low")):
        for level in ("high", "medium", "low"):
            for c in data.get(level, []) or []:
                if isinstance(c, str) and c.strip():
                    tiers[c.strip().lower()] = level
    else:
        for c, level in data.items():
            if isinstance(c, str) and level in ("high", "medium", "low"):
                tiers[c.strip().lower()] = level
    return tiers


def geo_level(country: Optional[str]) -> str:
    if not country:
        return "unknown"
    return _load_geo_tiers().get(country.strip().lower(), "medium")


def impersonation_level(count: int) -> str:
    if count >= 3:
        return "high"
    if count >= 1:
        return "medium"
    return "low"


def overall_score(levels: dict) -> int:
    total = 0.0
    for dim, weight in _WEIGHTS.items():
        total += _LEVEL_SCORE.get(levels.get(dim, "unknown"), 40) * weight
    return round(total)


# --------------------------------------------------------------------------- #
# Pivots (investigator-driven; no auto-harvesting)
# --------------------------------------------------------------------------- #
def _dork(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)


def build_pivots(name: str, aliases: list[str], company: str, country: str) -> dict:
    templates = load_platform_templates()
    terms = [t for t in [name, *aliases] if t]

    social = []
    for t in terms:
        social += generate_search_links(t, ["social_networks"], templates)

    family = []
    for t in [name, *aliases]:
        if not t:
            continue
        family.append({"label": f'{t} — family / relatives', "url": _dork(f'"{t}" (wife OR husband OR spouse OR son OR daughter OR family)')})
        family.append({"label": f'{t} — home / address', "url": _dork(f'"{t}" (address OR home OR residence OR lives)')})

    business = []
    if name:
        business.append({"label": f"{name} — LinkedIn", "url": "https://www.linkedin.com/search/results/all/?keywords=" + urllib.parse.quote_plus(name)})
    if company:
        business.append({"label": f"{company} — OpenCorporates", "url": "https://opencorporates.com/companies?q=" + urllib.parse.quote_plus(company)})
        business.append({"label": f"{name or company} @ {company}", "url": _dork(f'"{name}" "{company}"' if name else f'"{company}"')})

    geo = []
    for t in [name, *aliases]:
        if not t:
            continue
        geo.append({"label": f"{t} — geotagged / location", "url": _dork(f'"{t}" (location OR "based in" OR travels OR spotted)')})
    if name and country:
        geo.append({"label": f"{name} in {country}", "url": _dork(f'"{name}" "{country}"')})

    return {
        "social": social,
        "family": family,
        "business": business,
        "geo": geo,
    }


def assess_vip(profile: dict) -> dict:
    """Run the full VIP exposure assessment and return a scorecard.

    profile: {name, aliases[], emails[], usernames[], company, country,
              known_impersonations}
    """
    name = (profile.get("name") or "").strip()
    aliases = [a for a in (profile.get("aliases") or []) if a and a.strip()]
    emails = [e.strip() for e in (profile.get("emails") or []) if e and e.strip()]
    usernames = [u for u in (profile.get("usernames") or []) if u and u.strip()]
    company = (profile.get("company") or "").strip()
    country = (profile.get("country") or "").strip()
    known_impersonations = int(profile.get("known_impersonations") or 0)

    # 1a. Presence — account footprint: resolve known handles across platforms.
    resolved = resolve_handles(usernames)
    resolved_count = len({(r["username"], r["platform"]) for r in resolved})

    # 1b. Presence — mention volume: name search signals (Brave, opt-in).
    if name:
        mention_query = f'"{name}"' + (f" {company}" if company else "")
        mention = brave_search(mention_query)
    else:
        mention = {"configured": False, "level": "unknown", "query": ""}

    # 2. Breach exposure (HIBP, opt-in).
    hibp_on = bool(os.getenv("HAVEIBEENPWNED_API_KEY"))
    breach_results = [check_hibp(e) for e in emails]
    breach_count = sum(b["count"] for b in breach_results)

    # 3. Levels.
    levels = {
        "presence": presence_level(
            resolved_count, bool(usernames), mention.get("level", "unknown")
        ),
        "discoverability": discoverability_level(breach_count, resolved_count, hibp_on),
        "geo": geo_level(country),
        "impersonation": impersonation_level(known_impersonations),
    }
    overall = overall_score(levels)

    pivots = build_pivots(name, aliases, company, country)

    return {
        "profile": {
            "name": name,
            "aliases": aliases,
            "emails": emails,
            "usernames": usernames,
            "company": company,
            "country": country,
            "known_impersonations": known_impersonations,
        },
        "levels": levels,
        "overall_score": overall,
        "presence": {
            "resolved_count": resolved_count,
            "profiles": resolved,
            "checked_platforms": len(PROFILE_URL_PATTERNS),
            "footprint_level": footprint_level(resolved_count, bool(usernames)),
            "mention": mention,
        },
        "discoverability": {
            "hibp_configured": hibp_on,
            "breach_count": breach_count,
            "emails": breach_results,
        },
        "impersonation": {"confirmed": known_impersonations},
        "geo": {"country": country},
        "pivots": pivots,
    }
