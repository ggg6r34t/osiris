"""Abuse Router — for any domain, resolve WHO to report abuse to and WHETHER the
domain is still live.

Pulls together (all keyless): domain RDAP (registrar + abuse contact + status
codes + registrant), IP RDAP (hosting network + abuse contact), DNS (A/AAAA/MX/
NS/TXT + SPF/DMARC), an HTTP HEAD probe (liveness + CDN headers), an email-
provider map, and a curated abuse-contact map (overridable via abuse_contacts.json).

It produces a live-status verdict, per-party abuse contacts (email or web form),
an ordered escalation path, blocklist/browser reporting channels, and a pre-filled
report email.
"""
import json
import os
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import dns.resolver
import requests

from osiris.enrichment import (
    get_proxies,
    get_request_timeout,
    get_whois_info,
    ip_geolocation,
)
from osiris.takedown import build_takedown_email

try:
    import ipwhois
except Exception:  # noqa: BLE001
    ipwhois = None

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Curated provider -> abuse contact map. Keys are lowercase substrings matched
# against registrar / hosting org / CDN / email-provider names. Extend via
# abuse_contacts.json at the repo root (or OSIRIS_ABUSE_CONTACTS_FILE).
ABUSE_CONTACTS = {
    "cloudflare": {"email": "abuse@cloudflare.com", "form": "https://abuse.cloudflare.com/"},
    "godaddy": {"email": "abuse@godaddy.com", "form": "https://supportcenter.godaddy.com/AbuseReport"},
    "namecheap": {"email": "abuse@namecheap.com", "form": "https://support.namecheap.com/"},
    "namesilo": {"email": "abuse@namesilo.com", "form": ""},
    "tucows": {"email": "abuse@tucows.com", "form": ""},
    "enom": {"email": "abuse@enom.com", "form": ""},
    "porkbun": {"email": "abuse@porkbun.com", "form": ""},
    "google": {"email": "", "form": "https://support.google.com/legal/troubleshooter/1114905"},
    "amazon": {"email": "abuse@amazonaws.com", "form": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "aws": {"email": "abuse@amazonaws.com", "form": "https://support.aws.amazon.com/#/contacts/report-abuse"},
    "microsoft": {"email": "abuse@microsoft.com", "form": "https://msrc.microsoft.com/report/abuse"},
    "digitalocean": {"email": "abuse@digitalocean.com", "form": "https://www.digitalocean.com/company/contact/abuse"},
    "ovh": {"email": "abuse@ovh.net", "form": ""},
    "hostinger": {"email": "abuse@hostinger.com", "form": ""},
    "hetzner": {"email": "abuse@hetzner.com", "form": "https://abuse.hetzner.com/"},
    "akamai": {"email": "abuse@akamai.com", "form": ""},
    "fastly": {"email": "abuse@fastly.com", "form": ""},
    "sucuri": {"email": "abuse@sucuri.net", "form": ""},
    "linode": {"email": "abuse@linode.com", "form": ""},
    "leaseweb": {"email": "abuse@leaseweb.com", "form": ""},
    "namebright": {"email": "abuse@namebright.com", "form": ""},
    "squarespace": {"email": "abuse@squarespace.com", "form": ""},
    "markmonitor": {"email": "abusecomplaints@markmonitor.com", "form": ""},
    "csc": {"email": "domainabuse@cscglobal.com", "form": ""},
    "gandi": {"email": "abuse@support.gandi.net", "form": ""},
    "ionos": {"email": "abuse@ionos.com", "form": ""},
    "network solutions": {"email": "abuse@web.com", "form": ""},
    "web.com": {"email": "abuse@web.com", "form": ""},
    "dynadot": {"email": "abuse@dynadot.com", "form": ""},
    "name.com": {"email": "abuse@name.com", "form": ""},
    "publicdomainregistry": {"email": "abuse-contact@publicdomainregistry.com", "form": ""},
    "pdr ltd": {"email": "abuse-contact@publicdomainregistry.com", "form": ""},
    "alibaba": {"email": "DomainAbuse@service.aliyun.com", "form": ""},
}

# MX host suffix -> (email service provider, abuse-contact key)
_EMAIL_PROVIDERS = [
    ("google.com", "Google Workspace", "google"),
    ("googlemail.com", "Google Workspace", "google"),
    ("outlook.com", "Microsoft 365", "microsoft"),
    ("protection.outlook.com", "Microsoft 365", "microsoft"),
    ("pphosted.com", "Proofpoint", "proofpoint"),
    ("ppe-hosted.com", "Proofpoint", "proofpoint"),
    ("mimecast.com", "Mimecast", "mimecast"),
    ("messagelabs.com", "Broadcom/Symantec", "broadcom"),
    ("zoho.com", "Zoho Mail", "zoho"),
    ("zoho.eu", "Zoho Mail", "zoho"),
    ("yandex.net", "Yandex Mail", "yandex"),
    ("protonmail.ch", "Proton Mail", "proton"),
    ("proton.me", "Proton Mail", "proton"),
    ("secureserver.net", "GoDaddy Email", "godaddy"),
    ("amazonaws.com", "Amazon SES", "amazon"),
    ("mailgun.org", "Mailgun", "mailgun"),
    ("sendgrid.net", "SendGrid", "sendgrid"),
    ("registrar-servers.com", "Namecheap Private Email", "namecheap"),
]


def _abuse_map() -> dict:
    """Built-in abuse contacts merged with an optional override file."""
    contacts = {k: dict(v) for k, v in ABUSE_CONTACTS.items()}
    path = os.getenv("OSIRIS_ABUSE_CONTACTS_FILE") or os.path.join(
        _REPO_ROOT, "abuse_contacts.json"
    )
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(k, str) and isinstance(v, dict):
                        contacts[k.strip().lower()] = {
                            "email": v.get("email", ""),
                            "form": v.get("form", ""),
                        }
        except (OSError, ValueError):
            pass
    return contacts


def _lookup_contact(*names: Optional[str]) -> dict:
    """Find a curated abuse contact by substring-matching provider names."""
    contacts = _abuse_map()
    for name in names:
        if not name:
            continue
        low = name.lower()
        for key, contact in contacts.items():
            if key in low:
                return {"provider": name, **contact, "matched": key}
    return {}


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    t = get_request_timeout()
    r.timeout = t
    r.lifetime = t
    return r


def dns_records(domain: str) -> dict:
    """A/AAAA/MX/NS/TXT + SPF/DMARC presence. Distinguishes NXDOMAIN."""
    res = _resolver()
    out: dict = {"nxdomain": False}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            answers = res.resolve(domain, rtype)
            out[rtype] = [a.to_text() for a in answers]
        except dns.resolver.NXDOMAIN:
            out["nxdomain"] = True
            out[rtype] = []
        except Exception:  # noqa: BLE001 - NoAnswer/NoNameservers/Timeout
            out[rtype] = []

    txt = " ".join(out.get("TXT", []))
    out["spf"] = "v=spf1" in txt.lower()
    try:
        dmarc = res.resolve("_dmarc." + domain, "TXT")
        out["dmarc"] = any("v=dmarc1" in a.to_text().lower() for a in dmarc)
    except Exception:  # noqa: BLE001
        out["dmarc"] = False

    # MX host names (strip priority + trailing dot)
    mx_hosts = []
    for mx in out.get("MX", []):
        parts = mx.split()
        host = (parts[-1] if parts else mx).rstrip(".").lower()
        if host:
            mx_hosts.append(host)
    out["mx_hosts"] = mx_hosts
    out["has_mx"] = bool(mx_hosts)
    return out


# --------------------------------------------------------------------------- #
# HTTP liveness + CDN detection
# --------------------------------------------------------------------------- #
def http_liveness(domain: str) -> dict:
    from osiris.netguard import BlockedTargetError, assert_host_allowed

    try:
        assert_host_allowed(domain)
    except BlockedTargetError as e:
        return {"alive": False, "status_code": None, "error": "blocked", "blocked_reason": str(e)}
    url = "http://" + domain
    try:
        r = requests.head(
            url,
            timeout=get_request_timeout(),
            allow_redirects=True,
            proxies=get_proxies(),
            headers={"User-Agent": os.getenv("OSIRIS_USER_AGENT", "Osiris-AbuseRouter/1.0")},
        )
        headers = {k.lower(): v for k, v in r.headers.items()}
        return {
            "alive": r.status_code < 500,
            "status_code": r.status_code,
            "server": headers.get("server", ""),
            "cf_ray": "cf-ray" in headers,
            "via": headers.get("via", ""),
            "final_url": r.url,
        }
    except requests.RequestException as e:
        return {"alive": False, "status_code": None, "error": e.__class__.__name__}


def detect_cdn(dns_data: dict, live: dict, hosting_org: Optional[str]) -> Optional[str]:
    ns = " ".join(dns_data.get("NS", [])).lower()
    server = (live.get("server") or "").lower()
    via = (live.get("via") or "").lower()
    org = (hosting_org or "").lower()
    if "cloudflare" in ns or "cloudflare" in server or live.get("cf_ray") or "cloudflare" in org:
        return "Cloudflare"
    if "akam" in ns or "akamai" in server or "akamai" in org:
        return "Akamai"
    if "fastly" in server or "fastly" in via or "fastly" in org:
        return "Fastly"
    if "sucuri" in ns or "sucuri" in server or "sucuri" in org:
        return "Sucuri"
    if "incapsula" in server or "imperva" in ns:
        return "Imperva/Incapsula"
    return None


# --------------------------------------------------------------------------- #
# RDAP (domain + IP)
# --------------------------------------------------------------------------- #
def _vcard_field(entity: dict, field: str) -> Optional[str]:
    vcard = entity.get("vcardArray")
    if not (isinstance(vcard, list) and len(vcard) > 1):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and item and item[0] == field:
            val = item[-1]
            if isinstance(val, list):
                val = " ".join(str(x) for x in val)
            return str(val) if val else None
    return None


def _find_entity(entities: list, role: str) -> Optional[dict]:
    for ent in entities or []:
        if role in (ent.get("roles") or []):
            return ent
        nested = _find_entity(ent.get("entities") or [], role)
        if nested:
            return nested
    return None


def domain_rdap(domain: str) -> dict:
    """Fetch domain RDAP via rdap.org (follows the IANA bootstrap). Returns
    registrar, registrar abuse contact, status codes, dates, registrant."""
    out: dict = {}
    try:
        r = requests.get(
            "https://rdap.org/domain/" + urllib.parse.quote(domain),
            timeout=get_request_timeout(),
            proxies=get_proxies(),
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": os.getenv("OSIRIS_USER_AGENT", "Osiris-AbuseRouter/1.0"),
            },
        )
        if r.status_code == 404:
            return {"not_found": True}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()
    except (requests.RequestException, ValueError) as e:
        return {"error": e.__class__.__name__}

    out["status"] = data.get("status") or []
    for ev in data.get("events") or []:
        action = ev.get("eventAction")
        if action == "registration":
            out["registration"] = ev.get("eventDate")
        elif action == "expiration":
            out["expiration"] = ev.get("eventDate")

    entities = data.get("entities") or []
    registrar = _find_entity(entities, "registrar")
    if registrar:
        out["registrar"] = _vcard_field(registrar, "fn")
        for pid in registrar.get("publicIds") or []:
            if pid.get("type", "").lower().startswith("iana"):
                out["registrar_iana_id"] = pid.get("identifier")
        abuse = _find_entity(registrar.get("entities") or [], "abuse")
        if abuse:
            out["registrar_abuse_email"] = _vcard_field(abuse, "email")
            out["registrar_abuse_phone"] = _vcard_field(abuse, "tel")

    registrant = _find_entity(entities, "registrant")
    if registrant:
        out["registrant"] = {
            "name": _vcard_field(registrant, "fn"),
            "org": _vcard_field(registrant, "org"),
            "email": _vcard_field(registrant, "email"),
            "address": _vcard_field(registrant, "adr"),
        }
    return out


def ip_rdap(ip: str) -> dict:
    """IP RDAP via ipwhois → hosting network + abuse contact email."""
    if ipwhois is None:
        return {}
    try:
        rdap_data = ipwhois.IPWhois(ip).lookup_rdap(depth=1)
    except Exception as e:  # noqa: BLE001
        return {"error": e.__class__.__name__}
    abuse_email = None
    for obj in (rdap_data.get("objects") or {}).values():
        if "abuse" in (obj.get("roles") or []):
            emails = (obj.get("contact") or {}).get("email") or []
            if emails:
                abuse_email = emails[0].get("value")
                break
    return {
        "asn": rdap_data.get("asn"),
        "asn_description": rdap_data.get("asn_description"),
        "network_name": (rdap_data.get("network") or {}).get("name"),
        "abuse_email": abuse_email,
    }


# --------------------------------------------------------------------------- #
# Email provider
# --------------------------------------------------------------------------- #
def email_provider(mx_hosts: list) -> dict:
    for host in mx_hosts:
        for suffix, name, key in _EMAIL_PROVIDERS:
            if host.endswith(suffix):
                contact = _abuse_map().get(key, {})
                return {"provider": name, "abuse_key": key, **contact}
    return {}


# --------------------------------------------------------------------------- #
# Verdict
# --------------------------------------------------------------------------- #
def liveness_verdict(dns_data: dict, live: dict, rdap_status: list) -> dict:
    status_low = " ".join(rdap_status or []).lower()
    notes = []
    if "hold" in status_low:  # clientHold / serverHold
        return {
            "state": "suspended",
            "label": "Suspended / taken down",
            "notes": [f"Domain status: {', '.join(rdap_status)} — put on hold by the registrar/registry (removed from DNS)."],
        }
    if dns_data.get("nxdomain"):
        return {"state": "nxdomain", "label": "NXDOMAIN (does not exist)", "notes": ["Domain does not resolve — never registered, expired, or deleted."]}

    has_a = bool(dns_data.get("A") or dns_data.get("AAAA"))
    has_any = has_a or dns_data.get("has_mx") or bool(dns_data.get("NS"))
    if not has_any:
        return {"state": "no-dns-records", "label": "No DNS records", "notes": ["No A/AAAA/MX/NS records — domain is not configured (dead or parked at the registry)."]}
    if not has_a:
        notes.append("No A/AAAA record — no website is hosted, though the domain is configured (may still send/receive mail if MX is set).")
        return {"state": "no-a-record", "label": "No web host", "notes": notes}
    if live.get("alive"):
        return {"state": "live", "label": "Live", "notes": [f"Resolves and responds (HTTP {live.get('status_code')})."]}
    return {"state": "resolves-no-response", "label": "Resolves, no HTTP response", "notes": ["Has an A record but the web server did not respond — could be down, firewalled, or non-web."]}


def _email_note(dns_data: dict, provider: dict) -> str:
    if dns_data.get("nxdomain") or not (
        dns_data.get("A") or dns_data.get("AAAA") or dns_data.get("has_mx") or dns_data.get("NS")
    ):
        return "No DNS records — a fraudulent address on this domain is not operational."
    if not dns_data.get("has_mx"):
        return ("No MX configured — this domain cannot receive email, so any @domain "
                "address is likely non-functional (spoofed/forged sender).")
    prov = provider.get("provider")
    return f"MX configured — domain can receive email via {prov}." if prov else "MX configured — domain can receive email."


# --------------------------------------------------------------------------- #
# Escalation + reporting channels
# --------------------------------------------------------------------------- #
def _contact_value(email: Optional[str], form: Optional[str]) -> dict:
    if email and "@" in email:
        return {"method": "email", "value": email, "form": form or ""}
    if form:
        return {"method": "form", "value": form, "form": form}
    return {"method": "none", "value": "", "form": ""}


def reporting_channels(domain: str) -> list:
    enc = urllib.parse.quote("http://" + domain, safe="")
    return [
        {"name": "Google Safe Browsing", "method": "form", "value": f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={enc}"},
        {"name": "Microsoft (SmartScreen)", "method": "form", "value": "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"},
        {"name": "APWG", "method": "email", "value": "reportphishing@apwg.org"},
        {"name": "PhishTank", "method": "form", "value": "https://phishtank.org/add_web_phish.php"},
        {"name": "Netcraft", "method": "form", "value": "https://report.netcraft.com/report"},
        {"name": "Spamhaus", "method": "form", "value": "https://www.spamhaus.org/report/"},
        {"name": "National CERT directory (FIRST)", "method": "form", "value": "https://www.first.org/members/teams/"},
    ]


def _parse_rdap_date(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _humanize_days(days: Optional[int]) -> Optional[str]:
    if days is None:
        return None
    days = max(0, int(days))
    if days < 45:
        return f"{days} day{'s' if days != 1 else ''}"
    if days < 730:
        months = round(days / 30.44)
        return f"{months} month{'s' if months != 1 else ''}"
    years = days / 365.25
    return f"{years:.1f} years"


def normalize_target(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if domain.startswith("http"):
        domain = urllib.parse.urlparse(domain).netloc or domain
    if "/" in domain:
        domain = domain.split("/", 1)[0]
    return domain


def domain_status(domain: str) -> dict:
    """Lightweight live-status verdict (DNS + HTTP + RDAP hold codes only) — used
    to re-check tracked takedowns without the full contact resolution."""
    domain = normalize_target(domain)
    dns_data = dns_records(domain)
    live = http_liveness(domain)
    rdap = domain_rdap(domain)
    return liveness_verdict(dns_data, live, rdap.get("status", []))


def route_abuse(domain: str) -> dict:
    domain = normalize_target(domain)

    dns_data = dns_records(domain)
    live = http_liveness(domain)

    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except OSError:
        ip = (dns_data.get("A") or [None])[0]

    rdap = domain_rdap(domain)
    host_rdap = ip_rdap(ip) if ip else {}
    hosting_org = host_rdap.get("network_name") or host_rdap.get("asn_description")
    cdn = detect_cdn(dns_data, live, hosting_org)

    provider = email_provider(dns_data.get("mx_hosts", []))
    verdict = liveness_verdict(dns_data, live, rdap.get("status", []))

    # Registrar identity — RDAP first, WHOIS fallback when RDAP is unavailable
    # or didn't name the registrar (rdap.org rate-limits / some TLDs lack RDAP).
    reg_name = rdap.get("registrar")
    rdap_note = None
    if rdap.get("error") or rdap.get("not_found") or not reg_name:
        rdap_note = "RDAP unavailable — registrar details from WHOIS."
        whois_data = get_whois_info(domain)
        reg_name = reg_name or (whois_data.get("domain_info") or {}).get("registrar")

    # Domain age (since registration) + registration term (registration→expiry).
    reg_dt = _parse_rdap_date(rdap.get("registration"))
    exp_dt = _parse_rdap_date(rdap.get("expiration"))
    age_days = (datetime.now(timezone.utc) - reg_dt).days if reg_dt else None
    term_days = (exp_dt - reg_dt).days if (reg_dt and exp_dt) else None

    # Contact — prefer RDAP abuse email, fall back to the curated map by name.
    reg_map = _lookup_contact(reg_name)
    registrar = {
        "name": reg_name,
        "iana_id": rdap.get("registrar_iana_id"),
        "registration": rdap.get("registration"),
        "expiration": rdap.get("expiration"),
        "age": _humanize_days(age_days),
        "age_days": age_days,
        "recently_registered": age_days is not None and age_days < 90,
        "registered_for": _humanize_days(term_days),
        "status": rdap.get("status", []),
        "abuse_email": rdap.get("registrar_abuse_email") or reg_map.get("email"),
        "abuse_form": reg_map.get("form"),
        "abuse_phone": rdap.get("registrar_abuse_phone"),
    }
    if rdap_note:
        registrar["rdap_note"] = rdap_note

    # Hosting/CDN contact — CDN abuse form takes priority when fronted.
    cdn_map = _lookup_contact(cdn) if cdn else {}
    host_map = _lookup_contact(hosting_org)
    hosting = {
        "ip": ip,
        "asn": host_rdap.get("asn"),
        "network": hosting_org,
        "cdn": cdn,
        "abuse_email": (cdn_map.get("email") if cdn else None) or host_rdap.get("abuse_email") or host_map.get("email"),
        "abuse_form": (cdn_map.get("form") if cdn else None) or host_map.get("form"),
        "geolocation": ip_geolocation(ip) if ip else {},
    }

    email = {
        "mx": dns_data.get("MX", []),
        "mx_hosts": dns_data.get("mx_hosts", []),
        "has_mx": dns_data.get("has_mx", False),
        "spf": dns_data.get("spf", False),
        "dmarc": dns_data.get("dmarc", False),
        "provider": provider.get("provider"),
        "abuse_email": provider.get("email"),
        "abuse_form": provider.get("form"),
        "note": _email_note(dns_data, provider),
    }

    # Escalation path (ordered).
    escalation = []
    escalation.append({"order": 1, "target": "Registrar", **_contact_value(registrar["abuse_email"], registrar["abuse_form"]), "label": registrar["name"] or "Registrar", "why": "Fastest path to suspend the domain itself."})
    if cdn:
        escalation.append({"order": 2, "target": f"CDN — {cdn}", **_contact_value(hosting["abuse_email"], hosting["abuse_form"]), "label": cdn, "why": "Domain is fronted by a CDN; report here (real origin is hidden)."})
    else:
        escalation.append({"order": 2, "target": "Hosting provider", **_contact_value(hosting["abuse_email"], hosting["abuse_form"]), "label": hosting["network"] or "Host", "why": "Can take down the hosted content."})
    if email["has_mx"]:
        escalation.append({"order": 3, "target": "Email provider", **_contact_value(email["abuse_email"], email["abuse_form"]), "label": email["provider"] or "Email host", "why": "Handles mailbox/phishing abuse for this domain."})
    escalation = [e for e in escalation if e.get("method") != "none" or e["order"] <= 2]

    # Pre-filled report email aimed at the best contact.
    best = registrar["abuse_email"] or hosting["abuse_email"] or email["abuse_email"] or ""
    enrichment = {
        "domain": domain,
        "host": {"ip": ip, "asn": hosting["asn"], "hosted_by": hosting["network"], "abuse_contact": {"email": best}},
        "whois": {"domain_info": {"registrar": registrar["name"]}},
    }
    report_email = build_takedown_email(enrichment)
    report_email["to"] = best

    return {
        "domain": domain,
        "verdict": verdict,
        "dns": {k: dns_data.get(k) for k in ("A", "AAAA", "NS", "nxdomain")},
        "registrar": registrar,
        "registrant": rdap.get("registrant") or {},
        "hosting": hosting,
        "email": email,
        "escalation": escalation,
        "reporting_channels": reporting_channels(domain),
        "report_email": report_email,
    }
