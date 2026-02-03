import hashlib
from typing import Optional

import requests

from osiris.utils import is_port_open, build_http_session

def get_website_hash(url, timeout=5, verify_tls: bool = True, session: Optional[requests.Session] = None):
    try:
        sess = session or build_http_session()
        response = sess.get(url, timeout=timeout, verify=verify_tls)
        if response.status_code == 200:
            return hashlib.sha256(response.text.encode('utf-8')).hexdigest()
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
    return None

def detect_clones(original_domain, domain_list):
    clones = []
    session = build_http_session()

    base_urls = [f"https://{original_domain}", f"http://{original_domain}"]
    original_hash = None
    for base_url in base_urls:
        original_hash = get_website_hash(base_url, session=session)
        if original_hash:
            break

    if not original_hash:
        print(f"[!] Could not hash original site {original_domain}")
        return clones

    for domain in domain_list:
        if not is_port_open(domain, 80) and not is_port_open(domain, 443):
            print(f"[-] Skipping {domain} (no open HTTP/HTTPS port)")
            continue

        test_urls = [f"https://{domain}", f"http://{domain}"]
        test_hash = None
        for test_url in test_urls:
            test_hash = get_website_hash(test_url, session=session)
            if test_hash:
                break

        if test_hash and test_hash == original_hash:
            print(f"[✅] Clone detected: {domain}")
            clones.append(domain)
        else:
            print(f"[ ] {domain} does not match original hash")

    return clones
