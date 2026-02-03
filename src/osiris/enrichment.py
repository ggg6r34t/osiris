import os
import ssl
import re
from typing import Any, Dict, Optional
from functools import lru_cache
import whois
import dns.resolver
import hashlib
import requests
import socket
import ipwhois
from difflib import SequenceMatcher
import csv
import json
from datetime import datetime
from OpenSSL import crypto
from urllib.parse import urlparse
from dateutil.tz import UTC
from bs4 import BeautifulSoup

SUSPICIOUS_TLDS = { "tk", "ml", "ga", "cf", "gq", "top", "xyz", "cn", "work", "zip" }
SUSPICIOUS_REGISTRARS = {"Alibaba", "NameSilo", "PDR Ltd.", "Shinjiru", "Epik"}
LOW_TRUST_CAS = {"Let's Encrypt", "ZeroSSL", "cPanel", "Sectigo", "Self-Signed"}
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"


def get_request_timeout() -> float:
    try:
        return float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "10"))
    except ValueError:
        return 10.0

def get_proxies() -> Optional[dict]:
    http_proxy = os.getenv("OSIRIS_HTTP_PROXY") or os.getenv("HTTP_PROXY")
    https_proxy = os.getenv("OSIRIS_HTTPS_PROXY") or os.getenv("HTTPS_PROXY")
    proxies = {}
    if http_proxy:
        proxies["http"] = http_proxy
    if https_proxy:
        proxies["https"] = https_proxy
    return proxies or None


def http_get(url: str, **kwargs):
    timeout = kwargs.pop("timeout", get_request_timeout())
    proxies = kwargs.pop("proxies", get_proxies())
    verify = kwargs.pop("verify", os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false")
    return requests.get(url, timeout=timeout, proxies=proxies, verify=verify, **kwargs)

def normalize_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc
    elif parsed.scheme == "" and "/" in target:
        return urlparse("http://" + target).netloc
    else:
        return target.strip().lower()

def is_valid_domain(domain):
    return "." in domain and not domain.startswith("http")

def is_port_open(host: str, port: int = 443, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except (socket.timeout, socket.error):
        return False


def get_whois_info(domain: str) -> Dict[str, Any]:
    whois_info: Dict[str, Any] = {}

    try:
        w = whois.whois(domain)

        # Normalize date fields
        def parse_date(d):
            if isinstance(d, list): d = d[0]
            if isinstance(d, datetime):
                return d.replace(tzinfo=UTC) if d.tzinfo is None else d
            return None

        creation_date = parse_date(w.creation_date)
        updated_date = parse_date(w.updated_date)
        expiration_date = parse_date(w.expiration_date)

        # Format helper
        def fmt(d): return d.isoformat() if isinstance(d, datetime) else None

        # Scam indicators
        domain_age_days = (datetime.now(UTC) - creation_date).days if creation_date else None
        tld = domain.split(".")[-1].lower()

        scam_indicators = {
            "registrar_is_suspicious": any(r in (w.registrar or "") for r in SUSPICIOUS_REGISTRARS),
            "no_emails_found": not w.emails,
            "recently_created": domain_age_days is not None and domain_age_days < 90,
            "missing_name_servers": not w.name_servers,
            "suspicious_tld": tld in SUSPICIOUS_TLDS
        }

        whois_info = {
            "domain_info": {
                "domain": domain,
                "tld": tld,
                "registrar": w.registrar,
                "status": w.status
            },
            "registration_dates": {
                "creation_date": fmt(creation_date),
                "updated_date": fmt(updated_date),
                "expiration_date": fmt(expiration_date),
                "domain_age_days": domain_age_days,
                "recently_created": scam_indicators["recently_created"]
            },
            "contacts": {
                "emails": w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            },
            "name_servers": w.name_servers if w.name_servers else [],
            "scam_indicators": scam_indicators
        }

    except Exception as e:
        whois_info = {
            "error": str(e)
        }

    return whois_info


def ip_geolocation(ip):
    try:
        r = http_get(f"http://ip-api.com/json/{ip}")
        data = r.json()
        return {
            "country": data.get("country"),
            "isp": data.get("isp"),
        }
    except Exception:
        return {}

def get_ip_info(ip: str, token: str = None) -> dict:
    try:
        headers = {}
        params = {"token": token} if token else {}
        url = f"https://ipinfo.io/{ip}/abuse"
        resp = http_get(url, headers=headers, params=params)
        if resp.ok:
            data = resp.json()
            return {
                "email": data.get("email"),
                "address": data.get("address"),
                "country": data.get("country"),
                "phone": data.get("phone"),
            }
        return {"error": "Failed to retrieve IP info"}
    except Exception as e:
        return {"error": str(e)}

def get_ssl_cert_info(domain: str, verbose: bool = False):
    def log_err(msg):
        if verbose:
            print(f"[!] {msg}")
        return {"error": msg}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            der_cert = s.getpeercert(binary_form=True)
            if not der_cert:
                return log_err("No certificate retrieved")

        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, der_cert)

        subject = {k.decode(): v.decode() for k, v in cert.get_subject().get_components()}
        issuer = {k.decode(): v.decode() for k, v in cert.get_issuer().get_components()}

        issuer_name = issuer.get("CN", "Unknown")
        is_self_signed = subject == issuer
        low_trust = is_self_signed or any(ca.lower() in issuer_name.lower() for ca in LOW_TRUST_CAS)

        return {
            "subject": subject,
            "issuer": issuer,
            "serial_number": cert.get_serial_number(),
            "valid_from": cert.get_notBefore().decode(),
            "valid_to": cert.get_notAfter().decode(),
            "sha1_fingerprint": cert.digest("sha1").decode(),
            "is_self_signed": is_self_signed,
            "low_trust_ca": low_trust,
        }

    except (ssl.SSLError, ssl.CertificateError) as e:
        return log_err(f"SSL handshake failed: {e}")
    except socket.timeout:
        return log_err("Timeout during SSL connection")
    except socket.gaierror:
        return log_err("DNS resolution failed")
    except ConnectionRefusedError:
        return log_err("Connection refused on port 443")
    except Exception as e:
        return log_err(f"Unexpected SSL error: {e}")


def resolve_dns(domain: str) -> dict:
    result = {"domain": domain}
    for record_type in ["A", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result[record_type] = [r.to_text() for r in answers]
        except Exception:
            result[record_type] = []
    return result

def get_hosting_info(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)
        obj = ipwhois.IPWhois(ip)
        rdap_data = obj.lookup_rdap(depth=1)
        geo = ip_geolocation(ip)

        # Try RDAP abuse contact
        abuse_email = (
            rdap_data.get("objects", {})
            .get("abuse", {})
            .get("contact", {})
            .get("email")
        )

        # Fallback to ipinfo if abuse email is missing
        if not abuse_email:
            abuse_info = get_ip_info(ip, token=os.getenv("IPINFO_TOKEN"))
        else:
            abuse_info = {"email": abuse_email}

        return {
            "domain": domain,
            "ip": ip,
            "asn": rdap_data.get("asn"),
            "hosted_by": rdap_data.get("network", {}).get("name"),
            "abuse_contact": abuse_info,
            "geolocation": geo,
        }

    except Exception as e:
        return {"domain": domain, "host_error": str(e)}

def get_favicon_hash(domain: str) -> dict:
    """
    Fetch favicon from target domain and return its MD5 hash and URL.
    """
    try:
        if not domain.startswith("http"):
            domain = "http://" + domain
        parsed = urlparse(domain)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        favicon_url = f"{base_url}/favicon.ico"

        response = http_get(favicon_url)
        if response.status_code != 200 or "image" not in response.headers.get("Content-Type", ""):
            return {"error": f"Favicon not found at {favicon_url}"}

        favicon_hash = hashlib.md5(response.content).hexdigest()
        return {
            "favicon_url": favicon_url,
            "favicon_hash_md5": favicon_hash
        }
    except Exception as e:
        return {"error": str(e)}

def get_page_hash(url: str) -> str:
    try:
        r = http_get(url)
        html = r.text.encode("utf-8")
        return hashlib.sha256(html).hexdigest()
    except Exception:
        return None

def analyze_page_metadata(url: str):
    try:
        r = http_get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        title = soup.title.string if soup.title else ""
        meta_desc = soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_desc.get("content") if meta_desc else ""
        h1_tags = [h.get_text(strip=True) for h in soup.find_all("h1")]
        phishing_keywords = ["login", "account", "verify", "password", "update"]
        suspicious = any(k.lower() in (title.lower() + meta_desc.lower()) for k in phishing_keywords)
        return {"title": title, "meta_description": meta_desc, "h1": h1_tags, "phishing_keywords_found": suspicious}
    except Exception as e:
        return {"error": str(e)}

def content_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()

def get_passive_dns_history(domain: str):
    api_key = os.getenv("SECURITYTRAILS_API_KEY")
    if not api_key:
        return {"error": "No API key"}
    try:
        r = http_get(
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            headers={"APIKEY": api_key},
        )
        if r.ok:
            return r.json()
        return {"error": "No data"}
    except Exception as e:
        return {"error": str(e)}

def check_abuseipdb(ip: str):
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "No API key"}
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = http_get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}

def save_report(results: list, base_filename: str):
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    json_path = f"{base_filename}_{ts}.json"
    csv_path = f"{base_filename}_{ts}.csv"

    with open(json_path, "w") as jf:
        json.dump(results, jf, indent=2)

    with open(csv_path, "w", newline='') as cf:
        writer = csv.DictWriter(cf, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    return json_path, csv_path

@lru_cache(maxsize=4)
def load_ip_blocklist(url):
    try:
        r = http_get(url)
        if r.ok:
            return {line.strip() for line in r.text.splitlines() if line and not line.startswith("#")}
    except:
        return set()
    return set()

def ip_in_blocklist(ip, blocklist):
    return any(ip.startswith(bl.split("/")[0]) for bl in blocklist)

def calculate_risk_score(data):
    score = 0
    whois_info = data.get("whois", {}).get("scam_indicators", {})
    ssl_info = data.get("ssl_certificate", {})
    page_meta = data.get("page_metadata", {})
    abuse_info = data.get("threat_intel", {})

    # WHOIS factors
    if whois_info.get("recently_created"):
        score += 20
    if whois_info.get("suspicious_tld"):
        score += 10
    if whois_info.get("registrar_is_suspicious"):
        score += 10
    if whois_info.get("no_emails_found"):
        score += 5

    # SSL / CT Logs
    if ssl_info.get("low_trust_ca"):
        score += 10

    # Blocklist check
    ip = data.get("host", {}).get("ip")
    if ip:
        spamhaus = load_ip_blocklist(SPAMHAUS_DROP_URL)
        firehol = load_ip_blocklist(FIREHOL_URL)
        if ip_in_blocklist(ip, spamhaus):
            score += 20
        if ip_in_blocklist(ip, firehol):
            score += 10

    # AbuseIPDB
    if isinstance(abuse_info, dict) and abuse_info.get("abuseConfidenceScore", 0) >= 50:
        score += 15

    # Metadata phishing keywords
    if page_meta.get("phishing_keywords_found"):
        score += 15

    # Hosting country risk
    high_risk_countries = {"Russia", "China", "North Korea", "Iran"}
    country = data.get("host", {}).get("geolocation", {}).get("country")
    if country in high_risk_countries:
        score += 10

    return min(score, 100)



# Optional: known_brand_hashes = {...} for advanced clone detection

def enrich(target: str, is_url: bool = False):
    from osiris.domain_matcher import find_similar_domains
    is_url = is_url or str(target).startswith("http")
    domain = normalize_domain(target)

    whois_data = get_whois_info(domain)
    dns_data = resolve_dns(domain)
    host_data = get_hosting_info(domain)
    page_hash = get_page_hash(f"http://{domain}") if is_url else None
    favicon_data = get_favicon_hash(domain)
    passive_dns_data = get_passive_dns_history(domain)
    page_data = analyze_page_metadata(f"http://{domain}") if is_url else {}
    ip = dns_data.get("A")[0] if dns_data and "A" in dns_data else None
    geo_data = ip_geolocation(ip) if ip else {}
    abuse_data = check_abuseipdb(ip) if ip else {}
    threat_data = {"abuseipdb": abuse_data}
    ssl_cert = get_ssl_cert_info(domain, verbose=True)
    lookalikes = find_similar_domains(domain)

    enrichment_data = {
        "target": target,
        "domain": domain,
        "whois": whois_data,
        "dns": dns_data,
        "host": host_data,
        "ip_geolocation": geo_data,
        "ssl_certificate": ssl_cert,
        "passive_dns": passive_dns_data,
        "threat_intel": threat_data,
        "lookalike_domains": lookalikes,
        "content_hash": page_hash,
        "favicon": favicon_data,
        "page_metadata": page_data,
    }

    enrichment_data["risk_score"] = calculate_risk_score(enrichment_data)
    return enrichment_data





# Scoring Criteria
# | Factor                                    | Points | Details                          |
# | ----------------------------------------- | ------ | -------------------------------- |
# | Recently created domain (<90 days)        | +20    | WHOIS check                      |
# | Suspicious TLD                            | +10    | From `SUSPICIOUS_TLDS`           |
# | Suspicious registrar                      | +10    | From `SUSPICIOUS_REGISTRARS`     |
# | No WHOIS emails found                     | +5     | Missing contact info             |
# | CT logs show unexpected/self-signed certs | +10    | From `ct_logs` & CA trust list   |
# | ASN is in Spamhaus DROP                   | +20    | IP range abuse                   |
# | ASN in FireHOL blocklist                  | +10    | Known malicious ASN              |
# | AbuseIPDB score ≥ 50                      | +15    | High abuse confidence            |
# | Phishing keywords in metadata             | +15    | From `page_metadata`             |
# | Hosting in high-risk country              | +10    | e.g., Russia, China, North Korea |
