"""Offline smoke tests for Osiris core + web API.

These exercise pure logic and the API handler functions directly (no network,
no live server), so they run fast and deterministically. Run with:  pytest
"""
import pytest
from fastapi import HTTPException

from osiris.api import (
    CheckRequest,
    CustomPlatformRequest,
    RegexRequest,
    SearchRequest,
    _cached,
    _normalize_panda,
    api_brand_abuse,
    check,
    create_custom_platform,
    merged_templates,
    search,
)
from osiris.enrichment import calculate_risk_score, ip_in_blocklist
from osiris.input_handler import parse_input
from osiris.run_phishing_dorks import run_phishing_dorks
from osiris.search_links import generate_search_links
from osiris.text_clone_search import text_clone_search
from osiris.threat_scoring import score_threat
from osiris.utils import dedupe_links


# --- search-link generation -------------------------------------------------
def test_generate_search_links_basic():
    tpl = {"web": {"X": "https://x/?q={query}"}}
    assert generate_search_links("acme", ["all"], tpl) == [
        {"platform": "X", "category": "web", "url": "https://x/?q=acme"}
    ]


def test_generate_search_links_tolerates_stray_braces():
    tpl = {"web": {"X": "https://x/{id}?q={query}"}}
    assert generate_search_links("acme", ["all"], tpl)[0]["url"] == "https://x/{id}?q=acme"


def test_generate_search_links_url_encodes_target():
    tpl = {"web": {"X": "https://x/?q={query}"}}
    assert generate_search_links("a b&c", ["all"], tpl)[0]["url"] == "https://x/?q=a+b%26c"


# --- helpers ----------------------------------------------------------------
def test_parse_input_defaults_and_normalizes():
    assert parse_input(None) == ["all"]
    assert parse_input(["Reddit", " reddit ", ""]) == ["reddit"]


def test_dedupe_links():
    assert len(dedupe_links([{"url": "a"}, {"url": "a"}, {"url": "b"}])) == 2


def test_score_threat_shape():
    r = score_threat("https://paypal-login.com/verify", "paypal")
    assert isinstance(r["score"], int)
    assert r["label"] in {"NONE", "LOW", "MEDIUM", "HIGH"}


# --- /api/search handler (pure, no network) ---------------------------------
def test_search_returns_links():
    res = search(SearchRequest(target="acme", platforms=["all"]))
    assert res["count"] > 0
    assert all({"platform", "category", "url"} <= set(r) for r in res["results"])


def test_search_empty_target_raises_422():
    with pytest.raises(HTTPException) as exc:
        search(SearchRequest(targets=[]))
    assert exc.value.status_code == 422


def test_search_exclude_and_max_links():
    res = search(
        SearchRequest(
            target="acme",
            platforms=["all"],
            exclude_categories=["mobile_apps"],
            max_links=5,
        )
    )
    assert res["count"] <= 5
    assert all(r["category"] != "mobile_apps" for r in res["results"])


def test_search_score_sort_descending():
    res = search(
        SearchRequest(target="acme", platforms=["all"], score=True, sort_score=True)
    )
    scores = [r["score"] for r in res["results"]]
    assert scores == sorted(scores, reverse=True)


def test_search_batch_targets_tagged():
    res = search(SearchRequest(targets=["alpha", "beta"], platforms=["reddit"]))
    assert {r["target"] for r in res["results"]} == {"alpha", "beta"}


# --- custom-platform validation ---------------------------------------------
def test_custom_platform_rejects_non_http_scheme():
    with pytest.raises(HTTPException) as exc:
        create_custom_platform(
            CustomPlatformRequest(
                category="web", name="Evil", url="javascript:alert(1)//{query}"
            )
        )
    assert exc.value.status_code == 422


def test_custom_platform_requires_query_placeholder():
    with pytest.raises(HTTPException) as exc:
        create_custom_platform(
            CustomPlatformRequest(category="web", name="X", url="https://x.com/none")
        )
    assert exc.value.status_code == 422


def test_merged_templates_has_defaults():
    t = merged_templates()
    assert "social_networks" in t and len(t["social_networks"]) > 0


# --- link-based tools (pure) ------------------------------------------------
def test_text_clone_builds_four_engine_links():
    links = text_clone_search(["secret text"], open_browser=False, quiet=True)
    assert len(links) == 4
    assert all(l["category"] == "text_clone_detection" for l in links)


def test_phishing_dorks_builds_links():
    links = run_phishing_dorks(["acme login"], open_browser=False, quiet=True)
    assert len(links) == 4


# --- /api/check empty path (no network) -------------------------------------
def test_check_empty_returns_empty():
    assert check(CheckRequest(urls=[])) == {"results": []}


# --- risk scoring correctness (regression guards) ---------------------------
def test_ip_in_blocklist_cidr_semantics():
    assert ip_in_blocklist("1.2.3.4", {"1.2.0.0/16 ; SBL123"}) is True
    assert ip_in_blocklist("1.2.3.45", {"1.2.3.4/32"}) is False
    assert ip_in_blocklist("9.9.9.9", {"1.2.0.0/16"}) is False


def test_cache_memoizes_producer():
    calls = {"n": 0}

    def producer():
        calls["n"] += 1
        return calls["n"]

    key = "test:cache:key"
    first = _cached(key, producer)
    second = _cached(key, producer)
    assert first == second == 1
    assert calls["n"] == 1  # producer invoked only once


def test_panda_normalization_extracts_domains():
    payload = {
        "data": {
            "k1": {"_id": "A1", "domain": "evil-rihotel.com"},
            "k2": {"_id": "A2", "note": "spotted at rl1uhotel.net today"},
            "k3": {"_id": "A3"},  # no resolvable domain
        }
    }
    res = _normalize_panda(payload)
    by_id = {r["id"]: r for r in res}
    assert by_id["A1"]["url"] == "http://evil-rihotel.com"
    assert by_id["A2"]["url"] == "http://rl1uhotel.net"
    assert by_id["A3"]["url"] is None
    assert len(res) == 3


def test_panda_normalization_handles_list_and_full_urls_and_empty():
    assert _normalize_panda({}) == []
    res = _normalize_panda({"data": [{"_id": "X", "url": "https://bad.example/login"}]})
    assert res[0]["url"] == "https://bad.example/login"  # already a URL, not re-prefixed


def test_brand_abuse_requires_config(monkeypatch):
    # With no Panda config, the endpoint returns 503 rather than crashing.
    for var in ("OSIRIS_PANDA_URL", "OSIRIS_PANDA_LOGIN", "OSIRIS_PANDA_KEY"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(HTTPException) as exc:
        api_brand_abuse(RegexRequest(regex=".*evil.*"))
    assert exc.value.status_code == 503


def test_brand_abuse_empty_regex_422():
    with pytest.raises(HTTPException) as exc:
        api_brand_abuse(RegexRequest(regex="   "))
    assert exc.value.status_code == 422


def test_abuseipdb_contributes_to_risk_score():
    base = {"whois": {}, "ssl_certificate": {}, "page_metadata": {}, "host": {}}
    low = calculate_risk_score({**base, "threat_intel": {"abuseipdb": {"abuseConfidenceScore": 0}}})
    high = calculate_risk_score({**base, "threat_intel": {"abuseipdb": {"abuseConfidenceScore": 100}}})
    assert high - low == 15
