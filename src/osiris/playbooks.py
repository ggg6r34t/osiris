"""Playbooks — guided, repeatable investigation workflows.

A playbook chains Osiris's individual capabilities (enrich, URL analysis,
reputation, abuse routing, lookalike discovery) into one run against a target,
rolls the signals into an overall risk verdict, files everything into a case,
and surfaces recommended next actions. This is the orchestration layer over the
tools — one click instead of a dozen manual steps.

Each step is isolated: one failing never aborts the run.
"""
from osiris import storage

PLAYBOOKS = {
    "assess": {
        "id": "assess",
        "name": "Domain / phishing assessment",
        "description": "Enrich → page analysis → reputation → abuse routing, plus a urlscan.io deep scan on risky domains (if configured). Files a case and opens a takedown when high-risk.",
        "target_label": "Domain or URL",
    },
    "brand": {
        "id": "brand",
        "name": "Brand-abuse discovery",
        "description": "Find registered lookalikes (Domain Match + DNSTwist) for a brand domain and file the candidates to a case.",
        "target_label": "Brand domain (e.g. acme.com)",
    },
}

_ORDER = {"low": 1, "medium": 2, "high": 3, "unknown": 0}


def list_playbooks() -> list:
    return list(PLAYBOOKS.values())


def _step(key: str, label: str, fn):
    """Run one step in isolation; return a structured result."""
    try:
        data = fn()
        return {"key": key, "label": label, "status": "ok", "data": data, "error": None}
    except Exception as e:  # noqa: BLE001
        return {"key": key, "label": label, "status": "error", "data": None, "error": e.__class__.__name__}


def _max_level(*levels: str) -> str:
    best = "unknown"
    for lv in levels:
        if _ORDER.get(lv, 0) > _ORDER.get(best, 0):
            best = lv
    return best


def _score_to_level(score) -> str:
    if not isinstance(score, (int, float)):
        return "unknown"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _normalize(target: str) -> str:
    from osiris.abuse_router import normalize_target

    return normalize_target(target)


def _run_assess(target: str) -> dict:
    from osiris.abuse_router import route_abuse
    from osiris.enrichment import enrich
    from osiris.feeds import check_reputation
    from osiris.url_analyzer import analyze_url

    domain = _normalize(target)
    url = target if target.startswith(("http://", "https://")) else "http://" + domain

    steps = [
        _step("enrich", "Enrich (WHOIS / DNS / hosting / risk)", lambda: enrich(url)),
        _step("url", "Page analysis (forms / brand / redirects)", lambda: analyze_url(url)),
        _step("reputation", "Threat-feed reputation", lambda: check_reputation(domain)),
        _step("abuse", "Abuse routing + live status", lambda: route_abuse(domain)),
    ]
    by = {s["key"]: s for s in steps}

    # --- risk rollup ---
    reasons = []
    enrich_level = url_level = rep_level = "unknown"
    if by["enrich"]["status"] == "ok":
        score = (by["enrich"]["data"] or {}).get("risk_score")
        enrich_level = _score_to_level(score)
        if enrich_level in ("high", "medium"):
            reasons.append(f"enrichment risk score {score}")
    if by["url"]["status"] == "ok":
        u = by["url"]["data"] or {}
        url_level = u.get("risk", "unknown")
        for f in (u.get("flags") or []):
            if f.get("level") in ("high", "medium"):
                reasons.append(f"page: {f.get('text')}")
    if by["reputation"]["status"] == "ok":
        rep = by["reputation"]["data"] or {}
        if rep.get("verdict") == "listed":
            rep_level = "high"
            listed = [s["source"] for s in rep.get("sources", []) if s.get("listed")]
            reasons.append(f"listed on threat feeds: {', '.join(listed)}")

    level = _max_level(enrich_level, url_level, rep_level)

    # Escalation — deep-scan risky domains with urlscan.io (opt-in via key). Only
    # fires for medium/high preliminary risk so benign domains stay fast and we
    # don't burn urlscan quota. A malicious verdict escalates to high.
    us_report = None
    from osiris.urlscan import configured as _us_configured, scan as _us_scan

    if _us_configured():
        if level in ("medium", "high"):
            us_step = _step("urlscan", "urlscan.io sandbox scan", lambda: _us_scan(url))
            steps.append(us_step)
            if us_step["status"] == "ok":
                usd = us_step["data"] or {}
                uv = usd.get("verdict") or {}
                us_report = usd.get("result_url")
                if uv.get("malicious"):
                    reasons.append(f"urlscan.io flagged malicious (score {uv.get('score')})")
                    level = "high"
        else:
            steps.append(
                {"key": "urlscan", "label": "urlscan.io sandbox scan", "status": "skipped", "data": None, "error": None}
            )

    # --- persist: case + findings ---
    case_id = storage.create_case(f"{domain} — assessment", note=f"Playbook: {PLAYBOOKS['assess']['name']}")
    for s in steps:
        if s["status"] == "ok":
            storage.add_case_item(case_id, f"pb:{s['key']}", {"domain": domain, "summary": _summarize(s)}, note=s["label"])

    # --- recommendations + optional takedown ---
    recommendations = []
    takedown_id = None
    abuse = by["abuse"]["data"] if by["abuse"]["status"] == "ok" else {}
    verdict = (abuse or {}).get("verdict", {})
    best_contact = ""
    if abuse:
        reg = abuse.get("registrar") or {}
        host = abuse.get("hosting") or {}
        best_contact = reg.get("abuse_email") or reg.get("abuse_form") or host.get("abuse_email") or host.get("abuse_form") or ""
        esc = abuse.get("escalation") or []
        if esc:
            top = esc[0]
            recommendations.append(f"Report to {top.get('target')} ({top.get('label')}): {top.get('value') or 'no public contact'}")
        if verdict.get("state") in ("live", "resolves-no-response"):
            recommendations.append(f"Target is {verdict.get('label','live')} — act promptly.")

    if us_report:
        recommendations.append(f"urlscan.io report: {us_report}")

    if level == "high":
        takedown_id = storage.create_takedown(domain, contact=best_contact, note=f"Auto-opened by {PLAYBOOKS['assess']['name']} playbook")
        recommendations.append("High risk — takedown opened and tracked (Cases → Takedowns).")

    return {
        "playbook": "assess",
        "name": PLAYBOOKS["assess"]["name"],
        "target": domain,
        "steps": [{**s, "summary": _summarize(s)} for s in steps],
        "risk": {"level": level, "reasons": reasons[:8]},
        "case_id": case_id,
        "takedown_id": takedown_id,
        "recommendations": recommendations,
    }


def _run_brand(target: str) -> dict:
    from osiris.dnstwist import run_dnstwist
    from osiris.domain_matcher import find_similar_domains

    domain = _normalize(target)

    def match():
        rows = find_similar_domains(domain, max_whois=0)
        return sorted({r["domain"] for r in rows if isinstance(r, dict) and r.get("domain")})

    def twist():
        rows = run_dnstwist(domain) or []
        return sorted({r["domain"] for r in rows if isinstance(r, dict) and r.get("dns_a")})

    steps = [
        _step("domain_match", "Registered lookalikes (Domain Match)", match),
        _step("dnstwist", "Resolving permutations (DNSTwist)", twist),
    ]
    by = {s["key"]: s for s in steps}

    candidates = set()
    for k in ("domain_match", "dnstwist"):
        if by[k]["status"] == "ok":
            candidates.update(by[k]["data"] or [])
    candidates.discard(domain)
    candidates = sorted(candidates)

    case_id = storage.create_case(f"{domain} — brand abuse", note=f"Playbook: {PLAYBOOKS['brand']['name']}")
    for c in candidates:
        storage.add_case_item(case_id, "lookalike", {"domain": c}, note=f"candidate lookalike of {domain}")

    level = "high" if len(candidates) >= 10 else ("medium" if candidates else "low")
    recommendations = []
    if candidates:
        recommendations.append(f"{len(candidates)} candidate lookalikes filed to the case — run 'Domain assessment' on the suspicious ones.")
        recommendations.append("Add this brand to Monitor to catch new lookalikes over time.")
    else:
        recommendations.append("No resolving lookalikes found right now — consider adding to Monitor for ongoing coverage.")

    return {
        "playbook": "brand",
        "name": PLAYBOOKS["brand"]["name"],
        "target": domain,
        "steps": [{**s, "summary": _summarize(s)} for s in steps],
        "risk": {"level": level, "reasons": [f"{len(candidates)} candidate lookalikes"] if candidates else []},
        "case_id": case_id,
        "takedown_id": None,
        "candidates": candidates,
        "recommendations": recommendations,
    }


def _summarize(step: dict) -> str:
    if step["status"] == "skipped":
        return "skipped — low preliminary risk"
    if step["status"] != "ok":
        return f"failed ({step['error']})"
    d = step["data"]
    k = step["key"]
    if k == "urlscan":
        if d and d.get("pending"):
            return "submitted — pending on urlscan.io"
        uv = (d or {}).get("verdict", {})
        return ("malicious" if uv.get("malicious") else "not flagged") + f" (score {uv.get('score', 0)})"
    if k == "enrich":
        return f"risk score {(d or {}).get('risk_score', '?')}"
    if k == "url":
        if d and d.get("reachable") is False:
            return "unreachable/blocked"
        return f"{(d or {}).get('risk','?')} risk · {(d or {}).get('credential_forms',0)} credential form(s)"
    if k == "reputation":
        return f"{(d or {}).get('verdict','?')} ({(d or {}).get('listed_count',0)} feed hits)"
    if k == "abuse":
        v = (d or {}).get("verdict", {})
        return v.get("label", "?")
    if k in ("domain_match", "dnstwist"):
        return f"{len(d or [])} found"
    return "ok"


def run_playbook(playbook_id: str, target: str) -> dict:
    if playbook_id not in PLAYBOOKS:
        raise ValueError(f"unknown playbook: {playbook_id}")
    if playbook_id == "assess":
        return _run_assess(target)
    return _run_brand(target)
