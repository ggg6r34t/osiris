"""IOC extraction + interop export (STIX 2.1 / MISP).

Ingest: paste an alert/report blob → refang defanged text → extract structured
indicators (domains, IPs, URLs, emails, file hashes, CVEs).
Export: turn an indicator set into a STIX 2.1 bundle or a MISP-importable event
JSON — both keyless and offline (no live server dependency).
"""
import ipaddress
import re
import uuid
from datetime import datetime, timezone

# --- refang: undo common IOC defanging ------------------------------------- #
def refang(text: str) -> str:
    t = text or ""
    t = re.sub(r"hxxps?", lambda m: "https" if m.group(0).lower().endswith("s") else "http", t, flags=re.I)
    t = re.sub(r"[\[\(\{]\s*\.\s*[\]\)\}]", ".", t)                       # [.] (.) {.}
    t = re.sub(r"[\[\(\{]\s*dot\s*[\]\)\}]", ".", t, flags=re.I)          # [dot]
    t = re.sub(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", "@", t, flags=re.I)     # [at] [@]
    t = re.sub(r"[\[\(\{]\s*:\s*[\]\)\}]", ":", t)                        # [:]
    t = t.replace("[/]", "/")
    return t


_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\]\)]+", re.I)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# TLD-lookalikes that are really file extensions — drop these as "domains".
_FILE_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "exe", "dll", "zip",
    "rar", "7z", "png", "jpg", "jpeg", "gif", "bmp", "svg", "txt", "csv",
    "json", "xml", "html", "htm", "js", "py", "sh", "bin", "dat", "log",
    "msi", "iso", "gz", "tar", "bat", "ps1", "vbs", "jar", "apk", "dmg",
    "php", "asp", "aspx", "jsp", "cgi", "pl", "rb", "go", "css",
}


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _strip(url: str) -> str:
    return url.rstrip(".,);]\"'>")


def extract_iocs(text: str) -> dict:
    """Refang, then extract & dedupe indicators from free text."""
    t = refang(text or "")

    urls = sorted({_strip(u) for u in _URL_RE.findall(t)})
    emails = sorted({e.lower() for e in _EMAIL_RE.findall(t)})
    sha256 = sorted({h.lower() for h in _SHA256_RE.findall(t)})
    sha1 = sorted({h.lower() for h in _SHA1_RE.findall(t)})
    md5 = sorted({h.lower() for h in _MD5_RE.findall(t)})
    cves = sorted({c.upper() for c in _CVE_RE.findall(t)})
    ips = sorted({ip for ip in _IPV4_RE.findall(t) if _valid_ip(ip)})

    # Domains: standalone tokens + those inside URLs/emails; drop IPs & file names.
    domain_pool = set(_DOMAIN_RE.findall(t))
    for u in urls:
        m = re.match(r"https?://([^/:]+)", u, re.I)
        if m:
            domain_pool.add(m.group(1))
    for e in emails:
        domain_pool.add(e.split("@", 1)[1])
    domains = sorted(
        {
            d.lower().rstrip(".")
            for d in domain_pool
            if not _valid_ip(d) and d.rsplit(".", 1)[-1].lower() not in _FILE_EXTS
        }
    )

    return {
        "domains": domains,
        "ips": ips,
        "urls": urls,
        "emails": emails,
        "hashes": {"md5": md5, "sha1": sha1, "sha256": sha256},
        "cves": cves,
    }


def ioc_count(iocs: dict) -> int:
    h = iocs.get("hashes") or {}
    return (
        len(iocs.get("domains") or [])
        + len(iocs.get("ips") or [])
        + len(iocs.get("urls") or [])
        + len(iocs.get("emails") or [])
        + len(iocs.get("cves") or [])
        + len(h.get("md5") or [])
        + len(h.get("sha1") or [])
        + len(h.get("sha256") or [])
    )


# --- STIX 2.1 -------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _indicator(name: str, pattern: str, now: str) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now,
        "modified": now,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
    }


def to_stix_bundle(iocs: dict) -> dict:
    now = _now_iso()
    objs = []
    for d in iocs.get("domains") or []:
        objs.append(_indicator(f"domain: {d}", f"[domain-name:value = '{d}']", now))
    for ip in iocs.get("ips") or []:
        objs.append(_indicator(f"ip: {ip}", f"[ipv4-addr:value = '{ip}']", now))
    for u in iocs.get("urls") or []:
        safe = u.replace("'", "\\'")
        objs.append(_indicator(f"url: {u}", f"[url:value = '{safe}']", now))
    for e in iocs.get("emails") or []:
        objs.append(_indicator(f"email: {e}", f"[email-addr:value = '{e}']", now))
    h = iocs.get("hashes") or {}
    for algo, key in (("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256")):
        for digest in h.get(key) or []:
            objs.append(
                _indicator(f"file {algo}: {digest}", f"[file:hashes.'{algo}' = '{digest}']", now)
            )
    for c in iocs.get("cves") or []:
        objs.append(_indicator(f"vuln: {c}", f"[vulnerability:name = '{c}']", now))
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


# --- MISP event ------------------------------------------------------------ #
def _attr(atype: str, category: str, value: str) -> dict:
    return {"type": atype, "category": category, "value": value, "to_ids": True}


def to_misp_event(iocs: dict, info: str = "Osiris IOC export") -> dict:
    attrs = []
    net = "Network activity"
    pd = "Payload delivery"
    for d in iocs.get("domains") or []:
        attrs.append(_attr("domain", net, d))
    for ip in iocs.get("ips") or []:
        attrs.append(_attr("ip-dst", net, ip))
    for u in iocs.get("urls") or []:
        attrs.append(_attr("url", net, u))
    for e in iocs.get("emails") or []:
        attrs.append(_attr("email-src", pd, e))
    h = iocs.get("hashes") or {}
    for atype, key in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
        for digest in h.get(key) or []:
            attrs.append(_attr(atype, pd, digest))
    for c in iocs.get("cves") or []:
        attrs.append(_attr("vulnerability", "External analysis", c))
    return {
        "Event": {
            "info": info,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "analysis": "0",
            "threat_level_id": "4",
            "distribution": "0",
            "Attribute": attrs,
        }
    }


def export_iocs(iocs: dict, fmt: str, info: str = "Osiris IOC export") -> dict:
    if fmt == "stix":
        return to_stix_bundle(iocs)
    if fmt == "misp":
        return to_misp_event(iocs, info)
    raise ValueError("format must be 'stix' or 'misp'")
