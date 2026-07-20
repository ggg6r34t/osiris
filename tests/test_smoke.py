"""Offline smoke tests for Osiris core + web API.

These exercise pure logic and the API handler functions directly (no network,
no live server), so they run fast and deterministically. Run with:  pytest
"""
import re

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
from osiris.regex_generator import brand_label, generate_brand_regex
from osiris.takedown import abuse_email, build_takedown_email
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


def test_ip_in_blocklist_ignores_comment_and_blank_lines():
    # Spamhaus DROP uses ';' comment lines — these must not crash (regression).
    blocklist = {"; Spamhaus DROP List 2024", "", "   ", "1.2.0.0/16"}
    assert ip_in_blocklist("1.2.3.4", blocklist) is True
    assert ip_in_blocklist("8.8.8.8", {"; comment only", "", "   "}) is False


def test_storage_history_and_cases(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(st, "_conn", None)

    st.add_history("enrich", "a.com", {"risk_score": 5})
    hist = st.list_history()
    assert hist[0]["tool"] == "enrich" and hist[0]["summary"]["risk_score"] == 5

    cid = st.create_case("Case 1", "note")
    st.add_case_item(cid, "domain", {"domain": "evil.com"}, "", "open")
    case = st.get_case(cid)
    assert case["name"] == "Case 1" and len(case["items"]) == 1
    item_id = case["items"][0]["id"]
    assert case["items"][0]["data"] == {"domain": "evil.com"}

    st.update_case_item(item_id, note="suspicious", status="escalate")
    assert st.get_case(cid)["items"][0]["status"] == "escalate"

    assert st.list_cases()[0]["item_count"] == 1
    st.delete_case(cid)
    assert st.get_case(cid) is None


def test_storage_watchlist_and_snapshots(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "s.db"))
    monkeypatch.setattr(st, "_conn", None)

    assert st.latest_snapshot("x.com", "dnstwist") is None
    st.save_snapshot("x.com", "dnstwist", ["a", "b"])
    st.save_snapshot("x.com", "dnstwist", ["a", "b", "c"])
    assert st.latest_snapshot("x.com", "dnstwist") == ["a", "b", "c"]

    st.add_watch("x.com")
    st.add_watch("x.com")  # idempotent (UNIQUE)
    assert len(st.list_watch()) == 1
    st.remove_watch("x.com")
    assert st.list_watch() == []


def test_virustotal_and_urlscan_graceful(monkeypatch):
    import osiris.enrichment as en

    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    assert en.check_virustotal("example.com") == {}  # no key → empty, no crash


def test_reverse_ip_parsing(monkeypatch):
    import osiris.enrichment as en

    class FakeResp:
        ok = True
        text = "a.com\nb.com\n a.com \n\nnot_a_host\n"

    monkeypatch.setattr(en, "http_get", lambda *a, **k: FakeResp())
    assert en.reverse_ip("1.2.3.4") == ["a.com", "b.com"]

    class ErrResp:
        ok = True
        text = "error: API count exceeded"

    monkeypatch.setattr(en, "http_get", lambda *a, **k: ErrResp())
    assert en.reverse_ip("1.2.3.4") == []


def test_ip_pivot_shape(monkeypatch):
    import osiris.enrichment as en

    monkeypatch.setattr(en.socket, "gethostbyname", lambda d: "9.9.9.9")
    monkeypatch.setattr(en, "get_hosting_info", lambda d: {"asn": "AS42", "hosted_by": "NET", "geolocation": {"country": "US"}})
    monkeypatch.setattr(en, "reverse_ip", lambda ip: ["a.com", "b.com"])
    r = en.ip_pivot("evil.com")
    assert r["ip"] == "9.9.9.9" and r["asn"] == "AS42"
    assert r["domain_count"] == 2 and r["domains"] == ["a.com", "b.com"]


def test_vt_raises_risk_score():
    from osiris.enrichment import calculate_risk_score

    base = {"whois": {}, "ssl_certificate": {}, "page_metadata": {}, "host": {}}
    lo = calculate_risk_score({**base, "threat_intel": {"virustotal": {"malicious": 0}}})
    hi = calculate_risk_score({**base, "threat_intel": {"virustotal": {"malicious": 9}}})
    assert hi - lo == 20


def test_monitor_diff_pure():
    from osiris.monitor import diff

    assert diff(None, ["a"]) == {"new": [], "gone": [], "first_run": True}
    assert diff(["a", "b"], ["b", "c"]) == {
        "new": ["c"],
        "gone": ["a"],
        "first_run": False,
    }


def test_run_monitor_flags_new(tmp_path, monkeypatch):
    import osiris.monitor as mon
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "m.db"))
    monkeypatch.setattr(st, "_conn", None)

    calls = {"n": 0}

    def fake_match(_target):
        calls["n"] += 1
        return ["a.com", "b.com"] if calls["n"] == 1 else ["a.com", "b.com", "new.com"]

    monkeypatch.setattr(mon, "_match_domains", fake_match)
    monkeypatch.setattr(mon, "_dnstwist_domains", lambda _t: [])

    r1 = mon.run_monitor("x.com")
    assert r1["domain-match"]["first_run"] is True
    assert st.list_watch()[0]["target"] == "x.com"

    r2 = mon.run_monitor("x.com")
    assert r2["domain-match"]["first_run"] is False
    assert r2["domain-match"]["new"] == ["new.com"]
    assert r2["domain-match"]["gone"] == []


def test_notify_channels_detects_env(monkeypatch):
    import osiris.notify as nt

    for var in (
        "OSIRIS_TELEGRAM_BOT_TOKEN",
        "OSIRIS_TELEGRAM_CHAT_ID",
        "OSIRIS_ALERT_WEBHOOK_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    assert nt.channels() == {"telegram": False, "webhook": False}

    monkeypatch.setenv("OSIRIS_TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("OSIRIS_TELEGRAM_CHAT_ID", "c")
    monkeypatch.setenv("OSIRIS_ALERT_WEBHOOK_URL", "http://x/hook")
    assert nt.channels() == {"telegram": True, "webhook": True}


def test_notify_no_op_when_unconfigured(monkeypatch):
    """Unconfigured channels must skip without any network call."""
    import osiris.notify as nt

    for var in (
        "OSIRIS_TELEGRAM_BOT_TOKEN",
        "OSIRIS_TELEGRAM_CHAT_ID",
        "OSIRIS_ALERT_WEBHOOK_URL",
    ):
        monkeypatch.delenv(var, raising=False)

    def boom(*_a, **_k):  # any HTTP attempt is a bug when unconfigured
        raise AssertionError("network call attempted while unconfigured")

    monkeypatch.setattr(nt.requests, "post", boom)
    res = nt.notify("hello")
    assert res["telegram"] == {"ok": False, "skipped": True}
    assert res["webhook"] == {"ok": False, "skipped": True}


def test_notify_build_findings_message():
    import osiris.notify as nt

    empty = {"domain-match": {"new": [], "gone": []}}
    assert nt.build_findings_message("x.com", empty) is None

    report = {"domain-match": {"new": ["a.com", "b.com"]}, "dnstwist": {"new": []}}
    text, payload = nt.build_findings_message("x.com", report)
    assert "x.com" in text and "a.com" in text
    assert payload["new"] == {"domain-match": ["a.com", "b.com"]}


def test_vip_scoring_levels():
    import osiris.vip as vip

    assert vip.presence_level(9, True) == "high"
    assert vip.presence_level(4, True) == "medium"
    assert vip.presence_level(1, True) == "low"
    assert vip.presence_level(0, False) == "unknown"

    assert vip.discoverability_level(4, 0, True) == "high"
    assert vip.discoverability_level(1, 0, True) == "medium"
    assert vip.discoverability_level(0, 0, True) == "low"
    assert vip.discoverability_level(0, 0, False) == "unknown"

    assert vip.geo_level("Syria") == "high"
    assert vip.geo_level("Switzerland") == "low"
    assert vip.geo_level("Brazil") == "medium"
    assert vip.geo_level("") == "unknown"

    assert vip.impersonation_level(5) == "high"
    assert vip.impersonation_level(0) == "low"


def test_vip_geo_override_file(tmp_path, monkeypatch):
    import osiris.vip as vip

    # built-in default: Brazil is medium
    monkeypatch.delenv("OSIRIS_GEO_RISK_FILE", raising=False)
    assert vip.geo_level("Brazil") == "medium"

    # grouped-form override file promotes Brazil to high
    f = tmp_path / "geo.json"
    f.write_text('{"high": ["Brazil"], "low": ["Syria"]}', encoding="utf-8")
    monkeypatch.setenv("OSIRIS_GEO_RISK_FILE", str(f))
    assert vip.geo_level("Brazil") == "high"
    assert vip.geo_level("Syria") == "low"  # file wins over built-in high

    # flat-form map
    f.write_text('{"brazil": "low"}', encoding="utf-8")
    assert vip.geo_level("Brazil") == "low"


def test_vip_overall_score_monotonic():
    import osiris.vip as vip

    low = vip.overall_score(
        {"presence": "low", "discoverability": "low", "geo": "low", "impersonation": "low"}
    )
    high = vip.overall_score(
        {"presence": "high", "discoverability": "high", "geo": "high", "impersonation": "high"}
    )
    assert 0 <= low < high <= 100


def test_vip_hibp_graceful_without_key(monkeypatch):
    import osiris.vip as vip

    monkeypatch.delenv("HAVEIBEENPWNED_API_KEY", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("HIBP called without an API key")

    monkeypatch.setattr(vip.requests, "get", boom)
    res = vip.check_hibp("jane@example.com")
    assert res == {
        "email": "jane@example.com",
        "configured": False,
        "count": 0,
        "breaches": [],
    }


def test_vip_assess_shape_offline(monkeypatch):
    """assess_vip returns a full scorecard without network when no handles/emails."""
    import osiris.vip as vip

    monkeypatch.delenv("HAVEIBEENPWNED_API_KEY", raising=False)
    monkeypatch.setattr(vip, "resolve_handles", lambda _u: [])

    sc = vip.assess_vip(
        {"name": "Jane Executive", "company": "Acme", "country": "Syria"}
    )
    assert set(sc["levels"]) == {"presence", "discoverability", "geo", "impersonation"}
    assert sc["levels"]["geo"] == "high"
    assert isinstance(sc["overall_score"], int)
    assert sc["pivots"]["social"] and sc["pivots"]["family"]


def test_takedown_email_builder():
    enrichment = {
        "domain": "evil-paypa1.com",
        "whois": {"domain_info": {"registrar": "NameSilo"}},
        "host": {
            "ip": "1.2.3.4",
            "asn": "AS123",
            "hosted_by": "EVILNET",
            "abuse_contact": {"email": "abuse@evilnet.example"},
        },
    }
    mail = build_takedown_email(enrichment, reporter="CERT Team", brand="PayPal")
    assert mail["to"] == "abuse@evilnet.example"
    assert "evil-paypa1.com" in mail["subject"]
    assert "1.2.3.4" in mail["body"] and "NameSilo" in mail["body"]
    assert "PayPal" in mail["body"] and mail["body"].rstrip().endswith("CERT Team")


def test_takedown_email_handles_missing_abuse_contact():
    mail = build_takedown_email({"domain": "x.com", "host": {}, "whois": {}})
    assert mail["to"] == ""  # no abuse contact -> empty To
    assert "x.com" in mail["subject"]
    assert abuse_email({"host": {"abuse_contact": {"email": "not-an-email"}}}) is None


def test_cache_refresh_bypasses_cache():
    calls = {"n": 0}

    def producer():
        calls["n"] += 1
        return calls["n"]

    key = "test:refresh:key"
    assert _cached(key, producer) == 1
    assert _cached(key, producer) == 1  # cached
    assert _cached(key, producer, refresh=True) == 2  # bypassed + recomputed
    assert calls["n"] == 2


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


def test_generate_regex_reproduces_reference_pattern():
    # Entering the brand as words reproduces the hand-written reference regex.
    expected = r".*rr?(i|l){1,}uu?(\.|-?)?hh?(o|0){1,}tt?(e|3){1,}(l|i){1,}.*"
    assert generate_brand_regex("riu hotel", "balanced") == expected


def test_generate_regex_strips_tld_and_compiles():
    rx = generate_brand_regex("riuhotel.com", "balanced")
    assert rx.startswith(".*") and rx.endswith(".*")
    re.compile(rx)  # must be a valid regex
    # domain input drops the TLD → single word, no internal separator group
    assert r"(\.|-?)?" not in rx


def test_generate_regex_levels_differ_and_compile():
    cons = generate_brand_regex("riuhotel", "conservative")
    bal = generate_brand_regex("riuhotel", "balanced")
    agg = generate_brand_regex("riuhotel", "aggressive")
    for rx in (cons, bal, agg):
        re.compile(rx)
    assert cons != bal != agg
    assert "{1,}" in bal and "+" in agg


def test_brand_label_variants():
    assert brand_label("riuhotel.com") == "riuhotel"
    assert brand_label("www.brand.co.uk") == "brand"
    assert brand_label("https://brand.com/path") == "brand"
    assert brand_label("riu hotel") == "riu hotel"


def test_generate_regex_empty_returns_blank():
    assert generate_brand_regex("   ", "balanced") == ""


def test_brand_abuse_empty_regex_422():
    with pytest.raises(HTTPException) as exc:
        api_brand_abuse(RegexRequest(regex="   "))
    assert exc.value.status_code == 422


def test_abuseipdb_contributes_to_risk_score():
    base = {"whois": {}, "ssl_certificate": {}, "page_metadata": {}, "host": {}}
    low = calculate_risk_score({**base, "threat_intel": {"abuseipdb": {"abuseConfidenceScore": 0}}})
    high = calculate_risk_score({**base, "threat_intel": {"abuseipdb": {"abuseConfidenceScore": 100}}})
    assert high - low == 15
