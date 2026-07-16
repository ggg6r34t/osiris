"""Build a pre-filled abuse / takedown report email from enrichment data."""
from typing import Any, Dict, Optional


def abuse_email(enrichment: Dict[str, Any]) -> Optional[str]:
    contact = (enrichment.get("host") or {}).get("abuse_contact") or {}
    email = contact.get("email")
    return email if isinstance(email, str) and "@" in email else None


def build_takedown_email(
    enrichment: Dict[str, Any], reporter: str = "", brand: str = ""
) -> Dict[str, str]:
    """Return {to, subject, body} for an abuse report about the enriched domain."""
    domain = enrichment.get("domain") or enrichment.get("target") or "the domain"
    host = enrichment.get("host") or {}
    whois = enrichment.get("whois") or {}
    registrar = (whois.get("domain_info") or {}).get("registrar")
    ip = host.get("ip")
    asn = host.get("asn")
    network = host.get("hosted_by")

    subject = f"Abuse report: phishing / brand abuse at {domain}"

    brand_phrase = f"the {brand} brand" if brand else "a brand we represent"
    lines = [
        "To whom it may concern,",
        "",
        f"We are reporting the domain {domain} for hosting content that abuses "
        f"{brand_phrase} (phishing / impersonation / trademark violation).",
        "",
        "Details:",
        f"  Domain:     {domain}",
    ]
    if ip:
        lines.append(f"  IP address: {ip}")
    if asn:
        lines.append(f"  ASN:        {asn}")
    if network:
        lines.append(f"  Network:    {network}")
    if registrar:
        lines.append(f"  Registrar:  {registrar}")
    lines += [
        "",
        "We request that you investigate and take appropriate action (suspension or",
        "takedown) at the earliest opportunity. Supporting evidence (screenshots and",
        "URLs) is available on request.",
        "",
        "Regards,",
        reporter or "[your name / team]",
    ]

    return {"to": abuse_email(enrichment) or "", "subject": subject, "body": "\n".join(lines)}
