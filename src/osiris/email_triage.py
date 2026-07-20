"""Email / .eml phishing triage.

Parse a raw email (paste or .eml upload) and surface what a CERT needs to triage
a forwarded suspicious message: authentication results (SPF/DKIM/DMARC), the
Received hop chain + best-guess originating IP, From / Reply-To / Return-Path /
display-name spoofing signals, extracted IOCs (URLs, domains, IPs, hashes), and
attachments (name/type/size + hashes) — rolled up into flags and a risk level.
"""
import hashlib
import ipaddress
import re
from email import message_from_bytes, message_from_string
from email.policy import default
from email.utils import parseaddr

from osiris.ioc import extract_iocs

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HREF_RE = re.compile(r"href\s*=\s*[\"']([^\"']+)[\"']", re.I)
_TAG_RE = re.compile(r"<[^>]+>")


def _domain_of(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    return email_addr.split("@", 1)[1].lower() if "@" in email_addr else ""


def _public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def _auth_results(msg) -> dict:
    """Parse SPF/DKIM/DMARC verdicts from Authentication-Results / Received-SPF."""
    blob = " ".join(msg.get_all("Authentication-Results", []))
    out = {"spf": None, "dkim": None, "dmarc": None}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", blob, re.I)
        if m:
            out[mech] = m.group(1).lower()
    if out["spf"] is None:
        rspf = " ".join(msg.get_all("Received-SPF", []))
        m = re.match(r"\s*(\w+)", rspf)
        if m:
            out["spf"] = m.group(1).lower()
    return out


def _received_chain(msg) -> tuple[list, str | None]:
    """Return the Received hops (recent→origin) and a best-guess originating IP.

    Received headers are prepended, so the LAST header is the earliest hop. The
    origin IP is the first public IP found scanning from the earliest hop up."""
    received = msg.get_all("Received", [])
    chain = []
    for r in received:
        collapsed = " ".join(r.split())
        ips = [ip for ip in _IP_RE.findall(collapsed) if _public_ip(ip)]
        chain.append({"raw": collapsed[:300], "ips": ips})
    origin = None
    for hop in reversed(chain):  # earliest hop first
        if hop["ips"]:
            origin = hop["ips"][0]
            break
    return chain, origin


def _bodies(msg) -> tuple[str, list]:
    """Return combined body text (plain + de-tagged HTML) and HTML href links."""
    text_parts, hrefs = [], []
    if msg.is_multipart():
        parts = msg.walk()
    else:
        parts = [msg]
    for part in parts:
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if part.get_filename():
            continue
        try:
            payload = part.get_content()
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(payload, str):
            continue
        if ctype == "text/plain":
            text_parts.append(payload)
        elif ctype == "text/html":
            hrefs.extend(_HREF_RE.findall(payload))
            text_parts.append(_TAG_RE.sub(" ", payload))
    return "\n".join(text_parts), hrefs


def _attachments(msg) -> list:
    out = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        fname = part.get_filename()
        if not fname:
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            payload = b""
        out.append(
            {
                "filename": fname,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "md5": hashlib.md5(payload).hexdigest() if payload else None,
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
            }
        )
    return out


_EXECUTABLE_EXTS = (".exe", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".lnk", ".docm", ".xlsm")


def analyze_email(raw) -> dict:
    msg = message_from_bytes(raw, policy=default) if isinstance(raw, bytes) else message_from_string(raw, policy=default)

    from_hdr = str(msg.get("From", ""))
    from_name, from_addr = parseaddr(from_hdr)
    from_domain = from_addr.split("@", 1)[1].lower() if "@" in from_addr else ""
    reply_to_domain = _domain_of(str(msg.get("Reply-To", "")))
    return_path_domain = _domain_of(str(msg.get("Return-Path", "")))

    auth = _auth_results(msg)
    chain, origin_ip = _received_chain(msg)
    body_text, hrefs = _bodies(msg)
    attachments = _attachments(msg)

    # IOCs from body + href links + subject.
    iocs = extract_iocs("\n".join([body_text, str(msg.get("Subject", "")), *hrefs]))
    for u in hrefs:
        if u.lower().startswith("http") and u not in iocs["urls"]:
            iocs["urls"].append(u)
    iocs["urls"] = sorted(set(iocs["urls"]))

    # --- Flags -------------------------------------------------------------- #
    flags = []
    if auth["dmarc"] in ("fail", "none") or auth["dmarc"] is None:
        flags.append({"level": "high" if auth["dmarc"] == "fail" else "medium",
                      "text": f"DMARC {auth['dmarc'] or 'absent'}"})
    if auth["spf"] in ("fail", "softfail"):
        flags.append({"level": "high", "text": f"SPF {auth['spf']}"})
    if auth["dkim"] in ("fail", "none") or auth["dkim"] is None:
        flags.append({"level": "medium", "text": f"DKIM {auth['dkim'] or 'absent'}"})
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        flags.append({"level": "high", "text": f"Reply-To ({reply_to_domain}) differs from From ({from_domain})"})
    if return_path_domain and from_domain and return_path_domain != from_domain:
        flags.append({"level": "medium", "text": f"Return-Path ({return_path_domain}) differs from From ({from_domain})"})
    # display-name impersonation: a domain in the display name that isn't the From domain
    name_domains = [d.lower() for d in re.findall(r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", from_name or "")]
    if from_domain and any(d != from_domain and not from_domain.endswith(d) for d in name_domains):
        flags.append({"level": "high", "text": f"Display name references {', '.join(set(name_domains))} but sender is {from_domain}"})
    if any((a["filename"] or "").lower().endswith(_EXECUTABLE_EXTS) for a in attachments):
        flags.append({"level": "high", "text": "Executable/macro attachment present"})

    order = {"high": 3, "medium": 2, "low": 1}
    highs = sum(1 for f in flags if f["level"] == "high")
    if highs >= 1:
        risk = "high"
    elif flags:
        risk = "medium"
    else:
        risk = "low"

    return {
        "headers": {
            "from": from_addr,
            "from_name": from_name,
            "from_domain": from_domain,
            "to": str(msg.get("To", "")),
            "subject": str(msg.get("Subject", "")),
            "date": str(msg.get("Date", "")),
            "reply_to": str(msg.get("Reply-To", "")),
            "return_path": str(msg.get("Return-Path", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "x_mailer": str(msg.get("X-Mailer", "")),
        },
        "auth": auth,
        "origin_ip": origin_ip,
        "received_chain": chain,
        "flags": sorted(flags, key=lambda f: -order[f["level"]]),
        "risk": risk,
        "iocs": iocs,
        "attachments": attachments,
    }
