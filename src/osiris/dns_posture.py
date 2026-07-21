"""Email / DNS spoofability posture — keyless.

Grades a domain's anti-spoofing and DNS-hardening posture: SPF, DMARC (with
policy), DKIM (common selectors), DNSSEC, CAA, MTA-STS, BIMI. The headline is
whether the domain is easily *spoofable* — i.e. lacks DMARC enforcement — which
is the core question for both protecting your brand and judging a suspect domain.
"""
import re
import urllib.parse

import dns.resolver

from osiris.enrichment import get_request_timeout

# Common DKIM selectors to probe (selectors are arbitrary, so absence is a warn).
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1", "s2", "mandrill"]


def _norm(domain: str) -> str:
    d = (domain or "").strip().lower()
    if d.startswith(("http://", "https://")):
        d = urllib.parse.urlparse(d).netloc or d
    return d.strip("/").split("/")[0]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    t = min(get_request_timeout(), 8)
    r.timeout = t
    r.lifetime = t
    return r


def _txt(res, name: str) -> list:
    try:
        return [b"".join(rr.strings).decode("utf-8", "replace") for rr in res.resolve(name, "TXT")]
    except Exception:  # noqa: BLE001
        return []


def _has(res, name: str, rtype: str) -> bool:
    try:
        return bool(res.resolve(name, rtype))
    except Exception:  # noqa: BLE001
        return False


def _check(key, label, status, detail, record=None) -> dict:
    return {"key": key, "label": label, "status": status, "detail": detail, "record": record}


def posture(domain: str) -> dict:
    domain = _norm(domain)
    res = _resolver()
    checks = []

    # SPF
    spf = next((t for t in _txt(res, domain) if t.lower().startswith("v=spf1")), None)
    if spf:
        m = re.search(r"([-~?+]all)\b", spf)
        allmech = m.group(1) if m else None
        if allmech in ("-all", "~all"):
            checks.append(_check("spf", "SPF", "pass", f"present ({allmech})", spf))
        else:
            checks.append(_check("spf", "SPF", "warn", f"present but permissive ({allmech or 'no all mechanism'})", spf))
    else:
        checks.append(_check("spf", "SPF", "fail", "no SPF record — sender IPs are unrestricted", None))

    # DMARC (the key anti-spoofing control)
    dmarc = next((t for t in _txt(res, "_dmarc." + domain) if t.lower().startswith("v=dmarc1")), None)
    policy = None
    if dmarc:
        pm = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc, re.I)
        policy = pm.group(1).lower() if pm else "none"
        if policy == "reject":
            checks.append(_check("dmarc", "DMARC", "pass", "p=reject — enforced", dmarc))
        elif policy == "quarantine":
            checks.append(_check("dmarc", "DMARC", "pass", "p=quarantine — enforced", dmarc))
        else:
            checks.append(_check("dmarc", "DMARC", "warn", "p=none — monitoring only, not enforced", dmarc))
    else:
        checks.append(_check("dmarc", "DMARC", "fail", "no DMARC record — spoofed mail is not rejected", None))

    # DKIM (probe common selectors)
    found_selectors = [s for s in _DKIM_SELECTORS if _txt(res, f"{s}._domainkey.{domain}")]
    if found_selectors:
        checks.append(_check("dkim", "DKIM", "pass", f"selector(s) found: {', '.join(found_selectors)}", None))
    else:
        checks.append(_check("dkim", "DKIM", "warn", "no common selector found (may use a custom one)", None))

    # DNSSEC
    if _has(res, domain, "DNSKEY"):
        checks.append(_check("dnssec", "DNSSEC", "pass", "DNSKEY present — signed", None))
    else:
        checks.append(_check("dnssec", "DNSSEC", "info", "not enabled", None))

    # CAA
    caa = _has(res, domain, "CAA")
    checks.append(_check("caa", "CAA", "pass" if caa else "info", "issuance restricted" if caa else "no CAA record", None))

    # MTA-STS
    mtasts = next((t for t in _txt(res, "_mta-sts." + domain) if "v=stsv1" in t.lower()), None)
    checks.append(_check("mta_sts", "MTA-STS", "pass" if mtasts else "info", "present" if mtasts else "not configured", mtasts))

    # BIMI
    bimi = next((t for t in _txt(res, "default._bimi." + domain) if t.lower().startswith("v=bimi1")), None)
    checks.append(_check("bimi", "BIMI", "pass" if bimi else "info", "present" if bimi else "not configured", bimi))

    # Headline verdict — spoofability hinges on DMARC enforcement.
    spoofable = policy in (None, "none")
    if not spoofable and spf:
        grade = "hardened"
    elif policy in ("reject", "quarantine"):
        grade = "partial"
    else:
        grade = "spoofable"
    summary = (
        "No DMARC enforcement — this domain is easily spoofable."
        if spoofable
        else f"DMARC {policy} — spoofed mail is {'rejected' if policy == 'reject' else 'quarantined'}."
    )

    return {
        "domain": domain,
        "grade": grade,
        "spoofable": spoofable,
        "dmarc_policy": policy,
        "summary": summary,
        "checks": checks,
    }
