import os
import requests
import socket
import urllib3.exceptions
from requests.sessions import HTTPAdapter
from urllib3 import Retry

from osiris.enrichment import get_whois_info
from osiris.variant_generator import generate_typosquatting_domains

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
ALIENVAULT_PASSIVETOTAL = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"

# Configure session with retries
def get_request_timeout() -> float:
    try:
        return float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "30"))
    except ValueError:
        return 30.0


session = requests.Session()
retries = Retry(
    total=5,
    backoff_factor=2,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    raise_on_status=False,
)
adapter = HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)
session.headers.update({'User-Agent': os.getenv("OSIRIS_USER_AGENT", "Osiris/1.0 (+https://github.com/ggg6r34t/osiris)")})

http_proxy = os.getenv("OSIRIS_HTTP_PROXY") or os.getenv("HTTP_PROXY")
https_proxy = os.getenv("OSIRIS_HTTPS_PROXY") or os.getenv("HTTPS_PROXY")
if http_proxy or https_proxy:
    session.proxies.update({
        **({"http": http_proxy} if http_proxy else {}),
        **({"https": https_proxy} if https_proxy else {}),
    })

def fetch_crtsh_domains(domain):
    try:
        response = session.get(CRT_SH_URL.format(domain=domain), timeout=get_request_timeout())
        response.raise_for_status()
        data = response.json()
        found = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            found.update(name_value.splitlines())
        return list(found)

    except (requests.exceptions.ConnectionError, urllib3.exceptions.ProtocolError, socket.error) as ce:
        print(f"[!] Network or socket error from crt.sh: {ce}")
    except Exception as e:
        print(f"[!] crt.sh error: {e}")

    # Fallback: try CertSpotter
    return fetch_certspotter_domains(domain)


def fetch_certspotter_domains(domain):
    try:
        response = session.get(CERTSPOTTER_URL.format(domain=domain), timeout=get_request_timeout())
        response.raise_for_status()
        data = response.json()
        found = set()
        for entry in data:
            dns_names = entry.get("dns_names", [])
            for name in dns_names:
                if domain in name:
                    found.add(name)
        print(f"→ Used fallback CertSpotter: found {len(found)} domains")
        return list(found)
    except Exception as e:
        print(f"[!] CertSpotter fallback failed: {e}")
        return fetch_otx_domains(domain)


def fetch_otx_domains(domain):
    try:
        response = session.get(ALIENVAULT_PASSIVETOTAL.format(domain=domain), timeout=get_request_timeout())
        response.raise_for_status()
        data = response.json()
        found = set()
        for result in data.get("url_list", []):
            url = result.get("url", "")
            if domain in url:
                found.add(url)
        print(f"→ Used fallback AlienVault OTX: found {len(found)} URLs")
        return list(found)
    except Exception as e:
        print(f"[!] AlienVault fallback failed: {e}")
        return []

def find_similar_domains(domain):
    print(f"🔍 Finding similar/typosquatted domains for: {domain}")

    variants = generate_typosquatting_domains(domain)
    print(f"→ Generated {len(variants)} typo variants.")

    cert_domains = fetch_crtsh_domains(domain)
    print(f"→ Found {len(cert_domains)} domains via certificates")

    suspicious = []
    for cert_domain in cert_domains:
        for variant in variants:
            if variant in cert_domain:
                whois_info = get_whois_info(cert_domain)
                suspicious.append({
                    "domain": cert_domain,
                    "matched_variant": variant,
                    "whois": whois_info
                })
                break

    return suspicious
