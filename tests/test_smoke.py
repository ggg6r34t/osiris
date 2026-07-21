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

    # presence blends footprint with mention volume: high on either axis wins,
    # and mention rescues the name-only (no-handles) case.
    assert vip.presence_level(1, True, "high") == "high"
    assert vip.presence_level(0, False, "medium") == "medium"
    assert vip.presence_level(9, True, "unknown") == "high"

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


def test_vip_mention_level_thresholds():
    import osiris.vip as vip

    assert vip.mention_level({"configured": False}) == "unknown"
    assert vip.mention_level({"configured": True, "error": "HTTP 429"}) == "unknown"
    assert (
        vip.mention_level(
            {"configured": True, "web_results": 2, "news_results": 0, "has_infobox": False}
        )
        == "low"
    )
    assert (
        vip.mention_level(
            {"configured": True, "web_results": 10, "news_results": 3, "has_infobox": False}
        )
        == "medium"
    )
    assert (
        vip.mention_level(
            {
                "configured": True,
                "web_results": 20,
                "news_results": 5,
                "has_infobox": True,
                "more_results_available": True,
            }
        )
        == "high"
    )


def test_vip_brave_graceful_without_key(monkeypatch):
    import osiris.vip as vip

    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("Brave called without an API key")

    monkeypatch.setattr(vip.requests, "get", boom)
    res = vip.brave_search('"Jane Executive"')
    assert res["configured"] is False and res["level"] == "unknown"


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
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    monkeypatch.setattr(vip, "resolve_handles", lambda _u: [])

    sc = vip.assess_vip(
        {"name": "Jane Executive", "company": "Acme", "country": "Syria"}
    )
    assert set(sc["levels"]) == {"presence", "discoverability", "geo", "impersonation"}
    assert sc["levels"]["geo"] == "high"
    assert isinstance(sc["overall_score"], int)
    assert sc["pivots"]["social"] and sc["pivots"]["family"]
    assert sc["presence"]["mention"]["configured"] is False


def test_import_custom_platforms_validation(tmp_path, monkeypatch):
    import osiris.platform_functions as pf
    from osiris.api import ImportCustomPlatformsRequest, import_custom_platforms

    monkeypatch.setattr(pf, "CUSTOM_PLATFORMS_FILE", str(tmp_path / "c.json"))
    req = ImportCustomPlatformsRequest(
        platforms={
            "web": {
                "Good": "https://ex.com/?q={query}",
                "NoQuery": "https://ex.com/",
                "BadScheme": "ftp://ex/{query}",
            },
            "bad": "not-an-object",
        }
    )
    r = import_custom_platforms(req)
    assert r["added"] == 1
    assert r["platforms"]["web"]["Good"] == "https://ex.com/?q={query}"
    assert "web" in r["platforms"] and "NoQuery" not in r["platforms"]["web"]
    assert len(r["skipped"]) == 3  # NoQuery, BadScheme, bad(not-an-object)


def test_vip_roster_storage(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "v.db"))
    monkeypatch.setattr(st, "_conn", None)

    vid = st.create_vip("Jane Executive", {"name": "Jane Executive", "company": "Acme"})
    v = st.get_vip(vid)
    assert v["name"] == "Jane Executive" and v["profile"]["company"] == "Acme"
    assert v["last_score"] is None

    # recording a result updates the snapshot
    st.record_vip_result(vid, 72, "high")
    v = st.get_vip(vid)
    assert v["last_score"] == 72 and v["last_level"] == "high"

    # update profile
    st.update_vip(vid, "Jane E.", {"name": "Jane E.", "company": "Globex"})
    assert st.get_vip(vid)["profile"]["company"] == "Globex"
    assert st.get_vip(vid)["last_score"] == 72  # result snapshot preserved

    assert len(st.list_vips()) == 1
    st.delete_vip(vid)
    assert st.get_vip(vid) is None


def test_integrations_status_no_secret_leak(monkeypatch):
    from osiris.api import api_integrations

    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "supersecretvalue123")
    monkeypatch.delenv("BRAVE_SEARCH_API_KEY", raising=False)
    r = api_integrations()
    assert r["keys"]["VirusTotal"] is True
    assert r["keys"]["Brave Search"] is False
    assert set(r["features"]) == {"screenshots", "ssrf_guard"}
    assert "db_path" in r["storage"]
    # the secret value must never appear anywhere in the response
    import json

    assert "supersecretvalue123" not in json.dumps(r)


def test_playbook_assess_orchestration(tmp_path, monkeypatch):
    import osiris.storage as st
    import osiris.playbooks as pb
    import osiris.enrichment as en
    import osiris.url_analyzer as ua
    import osiris.feeds as fe
    import osiris.abuse_router as ar

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "pb.db"))
    monkeypatch.setattr(st, "_conn", None)
    monkeypatch.setattr(en, "enrich", lambda url: {"risk_score": 85})
    monkeypatch.setattr(ua, "analyze_url", lambda url: {"reachable": True, "risk": "high", "credential_forms": 1, "flags": [{"level": "high", "text": "cross-domain form"}]})
    monkeypatch.setattr(fe, "check_reputation", lambda d: {"verdict": "listed", "listed_count": 2, "sources": [{"source": "URLhaus", "listed": True}]})
    monkeypatch.setattr(ar, "route_abuse", lambda d: {"verdict": {"state": "live", "label": "Live"}, "registrar": {"abuse_email": "abuse@reg.test"}, "hosting": {}, "escalation": [{"order": 1, "target": "Registrar", "label": "Reg", "method": "email", "value": "abuse@reg.test"}]})

    r = pb.run_playbook("assess", "evil.com")
    assert r["risk"]["level"] == "high"
    assert r["case_id"] and r["takedown_id"]  # high risk opens a takedown
    assert [s["status"] for s in r["steps"]] == ["ok", "ok", "ok", "ok"]
    assert st.get_takedown(r["takedown_id"])["contact"] == "abuse@reg.test"
    assert len(st.get_case(r["case_id"])["items"]) == 4


def test_playbook_assess_urlscan_escalation(tmp_path, monkeypatch):
    import osiris.storage as st
    import osiris.playbooks as pb
    import osiris.enrichment as en
    import osiris.url_analyzer as ua
    import osiris.feeds as fe
    import osiris.abuse_router as ar
    import osiris.urlscan as us

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "pbu.db"))
    monkeypatch.setattr(st, "_conn", None)
    # medium-risk preliminary signals (so urlscan escalation fires)
    monkeypatch.setattr(en, "enrich", lambda url: {"risk_score": 50})
    monkeypatch.setattr(ua, "analyze_url", lambda url: {"reachable": True, "risk": "medium", "credential_forms": 0, "flags": []})
    monkeypatch.setattr(fe, "check_reputation", lambda d: {"verdict": "clean", "sources": []})
    monkeypatch.setattr(ar, "route_abuse", lambda d: {"verdict": {"state": "live", "label": "Live"}, "registrar": {}, "hosting": {}, "escalation": []})
    monkeypatch.setattr(us, "configured", lambda: True)
    monkeypatch.setattr(
        us, "scan",
        lambda url, *a, **k: {"pending": False, "result_url": "https://urlscan.io/result/x/", "verdict": {"malicious": True, "score": 90, "brands": ["PayPal"]}},
    )

    r = pb.run_playbook("assess", "evil.com")
    us_steps = [s for s in r["steps"] if s["key"] == "urlscan"]
    assert us_steps and us_steps[0]["status"] == "ok"
    assert r["risk"]["level"] == "high"  # malicious urlscan escalated medium → high
    assert r["takedown_id"]  # high → takedown opened
    assert any("urlscan.io report" in x for x in r["recommendations"])


def test_playbook_assess_urlscan_skipped_when_low(tmp_path, monkeypatch):
    import osiris.storage as st
    import osiris.playbooks as pb
    import osiris.enrichment as en
    import osiris.url_analyzer as ua
    import osiris.feeds as fe
    import osiris.abuse_router as ar
    import osiris.urlscan as us

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "pbu2.db"))
    monkeypatch.setattr(st, "_conn", None)
    monkeypatch.setattr(en, "enrich", lambda url: {"risk_score": 5})
    monkeypatch.setattr(ua, "analyze_url", lambda url: {"reachable": True, "risk": "low", "flags": []})
    monkeypatch.setattr(fe, "check_reputation", lambda d: {"verdict": "clean", "sources": []})
    monkeypatch.setattr(ar, "route_abuse", lambda d: {"verdict": {}, "registrar": {}, "hosting": {}, "escalation": []})
    monkeypatch.setattr(us, "configured", lambda: True)

    def boom(*a, **k):
        raise AssertionError("urlscan.scan should not run on a low-risk domain")

    monkeypatch.setattr(us, "scan", boom)
    r = pb.run_playbook("assess", "benign.com")
    us_steps = [s for s in r["steps"] if s["key"] == "urlscan"]
    assert us_steps and us_steps[0]["status"] == "skipped"


def test_playbook_brand_and_isolation(tmp_path, monkeypatch):
    import osiris.storage as st
    import osiris.playbooks as pb
    import osiris.domain_matcher as dm
    import osiris.dnstwist as dt

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "pb2.db"))
    monkeypatch.setattr(st, "_conn", None)
    monkeypatch.setattr(dm, "find_similar_domains", lambda d, max_whois=0: [{"domain": "evi1.com"}])
    # one step raises → must not abort the run
    def boom(_d):
        raise RuntimeError("dnstwist down")
    monkeypatch.setattr(dt, "run_dnstwist", boom)

    r = pb.run_playbook("brand", "evil.com")
    assert r["candidates"] == ["evi1.com"]
    assert any(s["status"] == "error" for s in r["steps"])  # dnstwist failed gracefully
    assert r["case_id"]

    with pytest.raises(ValueError):
        pb.run_playbook("nope", "x.com")


def test_netguard_blocks_private_and_schemes(monkeypatch):
    import osiris.netguard as ng

    monkeypatch.delenv("OSIRIS_ALLOW_PRIVATE_TARGETS", raising=False)
    # IP literals
    assert ng.ip_is_blocked("127.0.0.1")
    assert ng.ip_is_blocked("10.0.0.5")
    assert ng.ip_is_blocked("169.254.169.254")  # cloud metadata
    assert ng.ip_is_blocked("::1")
    assert not ng.ip_is_blocked("8.8.8.8")
    # host checks (IP literals, no DNS)
    assert ng.check_host("192.168.1.1") is not None
    assert ng.check_host("8.8.8.8") is None
    # scheme + target enforcement
    with pytest.raises(ng.BlockedTargetError):
        ng.assert_url_allowed("file:///etc/passwd")
    with pytest.raises(ng.BlockedTargetError):
        ng.assert_url_allowed("http://127.0.0.1/admin")
    with pytest.raises(ng.BlockedTargetError):
        ng.assert_host_allowed("10.1.2.3")


def test_netguard_allow_override(monkeypatch):
    import osiris.netguard as ng

    monkeypatch.setenv("OSIRIS_ALLOW_PRIVATE_TARGETS", "true")
    assert ng.check_host("127.0.0.1") is None
    ng.assert_url_allowed("http://10.0.0.1/")  # no raise


def test_url_analyze_blocks_internal(monkeypatch):
    import osiris.url_analyzer as ua

    monkeypatch.delenv("OSIRIS_ALLOW_PRIVATE_TARGETS", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("request sent to a blocked target")

    monkeypatch.setattr(ua.requests, "get", boom)
    r = ua.analyze_url("http://169.254.169.254/latest/meta-data/")
    assert r["reachable"] is False and r["error"] == "blocked"


def test_http_get_blocks_private(monkeypatch):
    import osiris.enrichment as en

    monkeypatch.delenv("OSIRIS_ALLOW_PRIVATE_TARGETS", raising=False)
    import osiris.netguard as ng

    with pytest.raises(ng.BlockedTargetError):
        en.http_get("http://127.0.0.1:8000/")


def test_favicon_murmur3_matches_mmh3():
    import osiris.favicon as fav

    # canonical mmh3.hash test vectors (seed 0, x86_32, signed)
    assert fav._murmur3_x86_32(b"") == 0
    assert fav._murmur3_x86_32(b"", 1) == 1364076727
    assert fav._murmur3_x86_32(b"foo") == -156908512
    assert fav._murmur3_x86_32(b"hello") == 613153351
    assert fav._murmur3_x86_32(b"The quick brown fox jumps over the lazy dog") == 776992547


def test_favicon_hash_shodan_style():
    import base64
    import osiris.favicon as fav

    content = b"\x00\x00\x01\x00fake-ico-bytes"
    # Shodan hash = mmh3 of base64.encodebytes(content)
    assert fav.favicon_hash(content) == fav._murmur3_x86_32(base64.encodebytes(content))


def test_favicon_shodan_graceful(monkeypatch):
    import osiris.favicon as fav

    monkeypatch.delenv("SHODAN_API_KEY", raising=False)

    def boom(*a, **k):
        raise AssertionError("Shodan called without a key")

    monkeypatch.setattr(fav.requests, "get", boom)
    r = fav._shodan_matches(12345)
    assert r == {"configured": False, "total": 0, "matches": []}


def test_subdomains_parse(monkeypatch):
    import osiris.subdomains as sd

    class FakeResp:
        status_code = 200
        text = "[...]"

        def json(self):
            return [
                {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
                {"name_value": "dev.example.com", "common_name": "api.example.com"},
                {"name_value": "other.org", "common_name": "notmine.net"},  # filtered out
            ]

    monkeypatch.setattr(sd.requests, "get", lambda *a, **k: FakeResp())
    monkeypatch.setattr(sd, "_resolve", lambda n: "1.2.3.4" if n == "www.example.com" else None)
    r = sd.enumerate_subdomains("example.com")
    names = {s["name"] for s in r["subdomains"]}
    assert names == {"example.com", "www.example.com", "dev.example.com", "api.example.com"}
    assert "other.org" not in names and r["total"] == 4
    assert r["resolved"] == 1
    assert r["subdomains"][0]["name"] == "www.example.com"  # live sorts first


def test_subdomains_graceful(monkeypatch):
    import osiris.subdomains as sd

    monkeypatch.setattr(sd.time, "sleep", lambda *_a: None)

    def boom(*a, **k):
        raise sd.requests.RequestException("503")

    monkeypatch.setattr(sd.requests, "get", boom)
    r = sd.enumerate_subdomains("example.com")
    assert r["found"] is False and r["total"] == 0 and "error" in r


def test_dns_posture_grading(monkeypatch):
    import osiris.dns_posture as dp

    txt = {
        "hardened.test": ["v=spf1 include:x -all"],
        "_dmarc.hardened.test": ["v=DMARC1; p=reject; rua=mailto:x@y"],
        "spoofable.test": ["v=spf1 ~all"],
        "_dmarc.spoofable.test": ["v=DMARC1; p=none"],
    }
    monkeypatch.setattr(dp, "_txt", lambda res, name: txt.get(name, []))
    monkeypatch.setattr(dp, "_has", lambda res, name, rtype: False)

    a = dp.posture("hardened.test")
    assert a["grade"] == "hardened" and a["spoofable"] is False and a["dmarc_policy"] == "reject"

    b = dp.posture("spoofable.test")
    assert b["grade"] == "spoofable" and b["spoofable"] is True and b["dmarc_policy"] == "none"

    c = dp.posture("nodmarc.test")  # nothing configured
    spf = next(x for x in c["checks"] if x["key"] == "spf")
    dmarc = next(x for x in c["checks"] if x["key"] == "dmarc")
    assert spf["status"] == "fail" and dmarc["status"] == "fail" and c["spoofable"] is True


def test_wayback_parse_and_graceful(monkeypatch):
    import osiris.wayback as wb

    assert wb._norm("https://sub.example.com/path?x=1") == "sub.example.com"

    class FakeResp:
        status_code = 200
        ok = True

        def json(self):
            return [
                ["timestamp", "original", "statuscode"],
                ["20180620120000", "http://example.com/", "200"],
                ["20120115000000", "http://example.com/", "200"],
                ["20240301090000", "http://example.com/", "301"],
            ]

    monkeypatch.setattr(wb.requests, "get", lambda *a, **k: FakeResp())
    r = wb.history("example.com")
    assert r["found"] and r["years"] == 3
    assert r["first"]["date"] == "2012-01-15"  # sorted ascending
    assert r["last"]["date"] == "2024-03-01"
    assert r["first"]["url"].startswith("https://web.archive.org/web/20120115000000/")

    # graceful when archive.org is unreachable
    def boom(*a, **k):
        raise wb.requests.RequestException("503")

    monkeypatch.setattr(wb.requests, "get", boom)
    monkeypatch.setattr(wb.time, "sleep", lambda *_a: None)
    g = wb.history("example.com")
    assert g["found"] is False and g["years"] == 0 and "error" in g


def test_urlscan_graceful_and_brand_parsing(monkeypatch):
    import osiris.urlscan as us

    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    assert us.configured() is False

    def boom(*_a, **_k):
        raise AssertionError("network call attempted without an API key")

    monkeypatch.setattr(us.requests, "post", boom)
    with pytest.raises(us.UrlscanError):
        us.scan("http://evil.example")  # no key → raises before any request

    assert us._brand_names([{"name": "PayPal"}, "Chase", {"x": 1}]) == ["PayPal", "Chase"]
    assert us._brand_names(None) == []


def test_ioc_extract_and_refang():
    import osiris.ioc as ioc

    blob = (
        "phish hxxps://paypa1-secure[.]com/login and http://8.8.8.8/x.zip\n"
        "sender attacker[at]evil[.]net md5 44d88612fea8a8f36de82e1278abb02f cve-2023-1234\n"
        "attachment invoice.pdf"
    )
    r = ioc.extract_iocs(blob)
    assert "paypa1-secure.com" in r["domains"]
    assert "8.8.8.8" in r["ips"]
    assert "https://paypa1-secure.com/login" in r["urls"]
    assert "attacker@evil.net" in r["emails"]
    assert "44d88612fea8a8f36de82e1278abb02f" in r["hashes"]["md5"]
    assert "CVE-2023-1234" in r["cves"]
    # file extension is not treated as a domain
    assert not any(d.endswith(".pdf") for d in r["domains"])


def test_ioc_stix_and_misp():
    import osiris.ioc as ioc

    iocs = ioc.extract_iocs("evil.com 1.2.3.4 http://evil.com/a bad@evil.com")
    bundle = ioc.to_stix_bundle(iocs)
    assert bundle["type"] == "bundle" and bundle["id"].startswith("bundle--")
    assert all(o["type"] == "indicator" and o["pattern_type"] == "stix" for o in bundle["objects"])
    assert any("domain-name:value = 'evil.com'" in o["pattern"] for o in bundle["objects"])

    event = ioc.to_misp_event(iocs, info="test")["Event"]
    assert event["info"] == "test"
    types = {a["type"] for a in event["Attribute"]}
    assert {"domain", "ip-dst", "url", "email-src"} <= types
    assert ioc.ioc_count(iocs) == len(event["Attribute"])


def test_ioc_export_dispatch():
    import osiris.ioc as ioc
    import pytest as _pytest

    assert ioc.export_iocs({"domains": ["a.com"]}, "stix")["type"] == "bundle"
    assert "Event" in ioc.export_iocs({"domains": ["a.com"]}, "misp")
    with _pytest.raises(ValueError):
        ioc.export_iocs({}, "bogus")


def test_feeds_aggregate_verdict(monkeypatch):
    import osiris.feeds as fe

    monkeypatch.setattr(fe, "check_urlhaus", lambda h: {"source": "URLhaus", "listed": True, "detail": "1 online"})
    monkeypatch.setattr(fe, "check_spamhaus", lambda t, ip: {"source": "Spamhaus DBL", "listed": False})
    monkeypatch.setattr(fe, "check_surbl", lambda h: {"source": "SURBL", "listed": False})
    monkeypatch.setattr(fe, "check_safe_browsing", lambda t, ip: {"source": "GSB", "listed": None, "detail": "not configured"})

    r = fe.check_reputation("evil.com")
    assert r["verdict"] == "listed" and r["listed_count"] == 1
    assert r["is_ip"] is False


def test_feeds_clean_and_unknown(monkeypatch):
    import osiris.feeds as fe

    monkeypatch.setattr(fe, "check_urlhaus", lambda h: {"source": "URLhaus", "listed": False})
    monkeypatch.setattr(fe, "check_spamhaus", lambda t, ip: {"source": "Spamhaus", "listed": False})
    monkeypatch.setattr(fe, "check_surbl", lambda h: {"source": "SURBL", "listed": False})
    monkeypatch.setattr(fe, "check_safe_browsing", lambda t, ip: {"source": "GSB", "listed": None})
    assert fe.check_reputation("good.com")["verdict"] == "clean"

    # all sources indeterminate -> unknown
    for fn in ("check_urlhaus", "check_spamhaus", "check_surbl", "check_safe_browsing"):
        monkeypatch.setattr(fe, fn, (lambda *a, **k: {"source": "x", "listed": None}))
    assert fe.check_reputation("1.2.3.4")["verdict"] == "unknown"


def test_feeds_safe_browsing_graceful(monkeypatch):
    import osiris.feeds as fe

    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)

    def boom(*_a, **_k):
        raise AssertionError("Safe Browsing called without a key")

    monkeypatch.setattr(fe.requests, "post", boom)
    r = fe.check_safe_browsing("evil.com", False)
    assert r["listed"] is None and "not configured" in r["detail"]


def test_url_assess_phishing_page():
    import osiris.url_analyzer as ua

    html = (
        "<html><head><title>PayPal - Log In</title></head><body>"
        "Sign in to your PayPal account."
        '<form action="https://evil-harvest.ru/collect.php" method="post">'
        '<input type="text" name="email"><input type="password" name="pw"></form>'
        "</body></html>"
    )
    r = ua.assess_page(html, "http://paypa1-login.com/verify")
    assert r["risk"] == "high"
    assert r["final_domain"] == "paypa1-login.com"
    assert "paypal" in r["targeted_brands"]
    assert r["credential_forms"] == 1
    assert r["forms"][0]["cross_domain"] is True
    texts = " ".join(f["text"] for f in r["flags"])
    assert "different domain" in texts and "impersonates" in texts


def test_url_assess_benign_page():
    import osiris.url_analyzer as ua

    r = ua.assess_page("<html><head><title>Docs</title></head><body>Hello</body></html>", "https://example.com/")
    assert r["risk"] == "low"
    assert r["targeted_brands"] == []
    assert r["credential_forms"] == 0


def test_url_reg_domain_helper():
    import osiris.url_analyzer as ua

    assert ua._reg_domain("login.secure.paypal.com") == "paypal.com"
    assert ua._reg_domain("evil.ru:8080") == "evil.ru"


def test_email_triage_spoof_detection():
    import osiris.email_triage as et

    raw = (
        "From: PayPal Security <security@paypa1-alert.com>\n"
        "Reply-To: collect@evil-harvest.ru\n"
        "Return-Path: <bounce@evil-harvest.ru>\n"
        "To: victim@example.com\n"
        "Subject: verify now\n"
        "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\n"
        "Received: from x (mail.evil-harvest.ru [45.66.77.88]) by mx; Mon, 1 Jan 2024 10:00:00 +0000\n"
        "Content-Type: text/html\n\n"
        "<html>Click <a href=\"hxxps://paypa1-verify[.]com/login\">here</a></html>\n"
    )
    r = et.analyze_email(raw)
    assert r["risk"] == "high"
    assert r["auth"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert r["origin_ip"] == "45.66.77.88"
    assert "https://paypa1-verify.com/login" in r["iocs"]["urls"]
    texts = " ".join(f["text"] for f in r["flags"])
    assert "Reply-To" in texts and "SPF" in texts


def test_email_triage_clean_message():
    import osiris.email_triage as et

    raw = (
        "From: Real Sender <alice@example.com>\n"
        "To: bob@example.com\n"
        "Subject: hello\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/plain\n\n"
        "Just a normal message.\n"
    )
    r = et.analyze_email(raw)
    assert r["risk"] == "low"
    assert r["flags"] == []


def test_email_triage_executable_attachment():
    import osiris.email_triage as et

    raw = (
        "From: a@b.com\nTo: c@d.com\nSubject: invoice\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        'Content-Type: multipart/mixed; boundary="X"\n\n'
        "--X\nContent-Type: text/plain\n\nsee attached\n"
        "--X\nContent-Type: application/octet-stream\n"
        'Content-Disposition: attachment; filename="invoice.exe"\n\n'
        "payload\n--X--\n"
    )
    r = et.analyze_email(raw)
    assert any("Executable" in f["text"] for f in r["flags"])
    assert r["attachments"][0]["filename"] == "invoice.exe"
    assert r["attachments"][0]["sha256"]


def test_metrics_aggregation(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "m.db"))
    monkeypatch.setattr(st, "_conn", None)

    # empty DB
    m0 = st.metrics()
    assert m0["takedowns"]["total"] == 0 and m0["takedowns"]["mttr_days_mean"] is None

    # one takedown that went down, one still open
    t1 = st.create_takedown("a.com")
    st.update_takedown(t1, status="reported")
    st.record_takedown_check(t1, "nxdomain")  # → down (contributes to MTTR)
    t2 = st.create_takedown("b.com")
    st.update_takedown(t2, status="reported")
    st.create_case("c1")
    st.add_history("enrich", "x", {})

    m = st.metrics()
    assert m["takedowns"]["total"] == 2
    assert m["takedowns"]["by_status"].get("down") == 1
    assert m["takedowns"]["resolved_count"] == 1
    assert m["takedowns"]["mttr_days_mean"] is not None
    assert m["cases"]["total"] == 1
    assert m["history"]["by_tool"].get("enrich") == 1


def test_takedown_lifecycle(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(st, "_conn", None)

    tid = st.create_takedown("evil-paypa1.com", contact="abuse@reg.test", note="reported")
    t = st.get_takedown(tid)
    assert t["status"] == "new" and t["reported_at"] is None
    assert len(t["events"]) == 1  # created

    # advance to reported -> stamps reported_at
    t = st.update_takedown(tid, status="reported")
    assert t["status"] == "reported" and t["reported_at"] is not None

    # a live check while reported -> no change
    t = st.record_takedown_check(tid, "live")
    assert t["status"] == "reported" and t["status_changed"] is False

    # goes down -> auto 'down'
    t = st.record_takedown_check(tid, "nxdomain")
    assert t["status"] == "down" and t["status_changed"] is True

    # comes back -> auto 'relisted'
    t = st.record_takedown_check(tid, "live")
    assert t["status"] == "relisted" and t["status_changed"] is True

    # open list excludes closed
    st.update_takedown(tid, status="closed")
    assert st.open_takedowns() == []

    st.delete_takedown(tid)
    assert st.get_takedown(tid) is None


def test_takedown_no_autochange_from_terminal(tmp_path, monkeypatch):
    import osiris.storage as st

    monkeypatch.setattr(st, "DB_PATH", str(tmp_path / "t2.db"))
    monkeypatch.setattr(st, "_conn", None)

    tid = st.create_takedown("x.com")
    # a 'new' (never-reported) takedown should not auto-flip to down
    t = st.record_takedown_check(tid, "nxdomain")
    assert t["status"] == "new" and t["status_changed"] is False


def test_abuse_domain_age_helpers():
    import osiris.abuse_router as ar

    assert ar._humanize_days(10) == "10 days"
    assert ar._humanize_days(1) == "1 day"
    assert ar._humanize_days(120) == "4 months"
    assert ar._humanize_days(365) == "12 months"  # < 730d → months
    assert ar._humanize_days(1000) == "2.7 years"  # >= 730d → years
    assert ar._humanize_days(None) is None

    d = ar._parse_rdap_date("1997-09-15T04:00:00Z")
    assert d is not None and d.year == 1997
    assert ar._parse_rdap_date("2020-01-01").year == 2020
    assert ar._parse_rdap_date("garbage") is None
    assert ar._parse_rdap_date(None) is None


def test_abuse_verdict_logic():
    import osiris.abuse_router as ar

    # registrar/registry hold => suspended
    v = ar.liveness_verdict({"A": ["1.2.3.4"], "has_mx": True}, {"alive": True}, ["client hold"])
    assert v["state"] == "suspended"
    # nxdomain
    v = ar.liveness_verdict({"nxdomain": True}, {}, [])
    assert v["state"] == "nxdomain"
    # no records at all
    v = ar.liveness_verdict({"A": [], "AAAA": [], "has_mx": False, "NS": []}, {}, [])
    assert v["state"] == "no-dns-records"
    # no web host but configured
    v = ar.liveness_verdict({"A": [], "AAAA": [], "has_mx": True, "NS": ["ns1.x"]}, {}, [])
    assert v["state"] == "no-a-record"
    # live
    v = ar.liveness_verdict({"A": ["1.2.3.4"]}, {"alive": True, "status_code": 200}, ["active"])
    assert v["state"] == "live"


def test_abuse_email_note_no_mx():
    import osiris.abuse_router as ar

    note = ar._email_note({"A": ["1.2.3.4"], "NS": ["ns1"], "has_mx": False}, {})
    assert "cannot receive email" in note
    note2 = ar._email_note({"A": ["1.2.3.4"], "has_mx": True}, {"provider": "Google Workspace"})
    assert "Google Workspace" in note2


def test_abuse_email_provider_map():
    import osiris.abuse_router as ar

    p = ar.email_provider(["aspmx.l.google.com", "alt1.aspmx.l.google.com"])
    assert p["provider"] == "Google Workspace"
    p2 = ar.email_provider(["acme-com.mail.protection.outlook.com"])
    assert p2["provider"] == "Microsoft 365"
    assert ar.email_provider([]) == {}


def test_abuse_contact_map_and_override(tmp_path, monkeypatch):
    import osiris.abuse_router as ar

    monkeypatch.delenv("OSIRIS_ABUSE_CONTACTS_FILE", raising=False)
    c = ar._lookup_contact("Cloudflare, Inc.")
    assert c.get("form", "").startswith("https://abuse.cloudflare.com")

    f = tmp_path / "abuse.json"
    f.write_text('{"acmehost": {"email": "abuse@acmehost.test"}}', encoding="utf-8")
    monkeypatch.setenv("OSIRIS_ABUSE_CONTACTS_FILE", str(f))
    c2 = ar._lookup_contact("AcmeHost Datacenters")
    assert c2.get("email") == "abuse@acmehost.test"


def test_abuse_rdap_vcard_parsing():
    import osiris.abuse_router as ar

    entity = {
        "roles": ["registrar"],
        "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
        "entities": [
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["email", {}, "text", "abuse@example-reg.test"]]],
            }
        ],
    }
    assert ar._vcard_field(entity, "fn") == "Example Registrar"
    abuse = ar._find_entity([entity], "abuse")
    assert ar._vcard_field(abuse, "email") == "abuse@example-reg.test"


def test_abuse_detect_cdn():
    import osiris.abuse_router as ar

    assert ar.detect_cdn({"NS": ["ns.cloudflare.com"]}, {}, None) == "Cloudflare"
    assert ar.detect_cdn({"NS": []}, {"cf_ray": True}, None) == "Cloudflare"
    assert ar.detect_cdn({"NS": ["ns.example.com"]}, {"server": ""}, "Akamai Technologies") == "Akamai"
    assert ar.detect_cdn({"NS": ["ns.example.com"]}, {}, "Some Host") is None


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
