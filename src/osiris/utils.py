import os
import socket
import time
from typing import Optional, Dict
import pyfiglet
from fuzzywuzzy import process
import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.panel import Panel
from rich.box import ROUNDED

from osiris.intro_text import intro_message

console = Console()

DEFAULT_USER_AGENT = os.getenv(
    "OSIRIS_USER_AGENT",
    "Osiris/1.0 (+https://github.com/ggg6r34t/osiris)"
)


def build_http_session(
    user_agent: Optional[str] = None,
    retries: int = 2,
    backoff: float = 0.5,
    proxies: Optional[Dict[str, str]] = None,
) -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent or DEFAULT_USER_AGENT})
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["HEAD", "GET"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    if proxies:
        session.proxies.update(proxies)
    return session

def safe_str(value):
    if isinstance(value, list):
        return ", ".join(map(str, value))
    return str(value)

def fetch_text_content(url: str, timeout: int = 5) -> str:
    import requests
    from bs4 import BeautifulSoup

    try:
        r = requests.get(url, timeout=timeout)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.get_text(separator=" ", strip=True)
    except Exception as e:
        return ""

def is_port_open(host, port: int = 443, timeout=2, verbose=False):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except socket.timeout:
        if verbose:
            print(f"[!] Timeout while connecting to {host}:{port}")
    except socket.gaierror:
        if verbose:
            print(f"[!] Hostname could not be resolved: {host}")
    except ConnectionRefusedError:
        if verbose:
            print(f"[!] Connection refused: {host}:{port}")
    except OSError as e:
        if verbose:
            print(f"[!] OS error on {host}:{port} - {e}")
    return False


def fuzzy_match_platforms(input_platforms, platform_templates):
    """
    Perform fuzzy matching against categories and platform names in the provided templates.
    Returns normalized (lowercase) matches.
    """
    categories = list(platform_templates.keys())
    platforms = []
    for platforms_data in platform_templates.values():
        platforms.extend(platforms_data.keys())

    choices = categories + platforms
    matched = set()
    for ip in input_platforms:
        best = process.extract(ip, choices, limit=2)
        for match, score in best:
            if score > 70:
                matched.add(match.lower())
    return list(matched)

def check_link_status(
    links,
    timeout: int = 5,
    user_agent: Optional[str] = None,
    retries: int = 2,
    backoff: float = 0.5,
    allow_redirects: bool = True,
    verify_tls: bool = True,
    rate_limit_per_sec: float = 0,
    proxies: Optional[Dict[str, str]] = None,
):
    checked = []
    session = build_http_session(user_agent=user_agent, retries=retries, backoff=backoff, proxies=proxies)

    for link in links:
        url = link.get("url") if isinstance(link, dict) else None
        if not url:
            continue
        try:
            resp = session.head(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify_tls)
            if resp.status_code in {403, 405} or resp.status_code >= 400:
                resp = session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=verify_tls)
            if resp.status_code < 400:
                checked.append(link)
            else:
                console.print(f"[yellow]Skipped:[/yellow] {url} (HTTP {resp.status_code})")
        except requests.RequestException as e:
            console.print(f"[red]Failed:[/red] {url} — {e.__class__.__name__}")
        if rate_limit_per_sec and rate_limit_per_sec > 0:
            time.sleep(1 / rate_limit_per_sec)
    return checked

def group_links_by_category(links):
    grouped = []
    for link in links:
        if not isinstance(link, dict):
            continue
        entry = dict(link)
        entry.setdefault("platform", "")
        entry.setdefault("category", "")
        entry.setdefault("url", "")
        grouped.append(entry)
    return grouped


def dedupe_links(links, key_fields=("url",)):
    seen = set()
    deduped = []
    for link in links:
        if not isinstance(link, dict):
            continue
        key = tuple(str(link.get(field, "")).strip().lower() for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(link)
    return deduped

def print_search_links(grouped):
    table = Table(show_header=True, header_style="bold magenta", box=ROUNDED, expand=True)
    table.add_column("Platform", style="cyan", justify="left")
    table.add_column("Category", style="magenta", justify="left")
    table.add_column("URL", style="green", justify="left")

    for link in grouped:
        table.add_row(link['platform'], link['category'], link['url'])

    panel = Panel.fit(table, title="[bold magenta]Search Links[/bold magenta]", border_style="magenta")
    console.print(panel)

def print_enrichment_result(data: dict):
    # --- WHOIS ---
    whois = data.get("whois", {})
    whois_panel = Panel.fit("", title="[bold magenta]WHOIS Information[/bold magenta]",
                            border_style="magenta")
    if "error" in whois:
        whois_panel = Panel(f"[red]WHOIS Error: {whois['error']}[/red]",
                            title="[bold magenta]WHOIS Information[/bold magenta]", border_style="red")
        console.print(whois_panel)
    else:
        reg = whois.get("registration_dates", {})
        scam = whois.get("scam_indicators", {})
        contacts = whois.get("contacts", {})
        ns = whois.get("name_servers", [])
        domain_info = whois.get("domain_info", {})

        whois_table = Table.grid(padding=(0,1))
        whois_table.add_column(justify="right", style="bold")
        whois_table.add_column(ratio=3, style="cyan", overflow="fold")

        whois_table.add_row("Domain:", str(domain_info.get("domain", "N/A")))
        whois_table.add_row("TLD:", str(domain_info.get("tld", "N/A")))
        whois_table.add_row("Registrar:", str(domain_info.get("registrar", "N/A")))
        whois_table.add_row("Status:", str(domain_info.get("status", "N/A")))
        whois_table.add_row("Creation Date:", str(reg.get("creation_date", "N/A")))
        whois_table.add_row("Updated Date:", str(reg.get("updated_date", "N/A")))
        whois_table.add_row("Expiration Date:", str(reg.get("expiration_date", "N/A")))
        whois_table.add_row("Domain Age (days):", str(reg.get("domain_age_days", "N/A")))
        whois_table.add_row("Emails:", ", ".join(contacts.get("emails", [])) or "None")
        whois_table.add_row("Name Servers:", ", ".join(ns) or "None")

        for k, v in scam.items():
            if isinstance(v, bool):
                val = Text("Yes" if v else "No", style="red" if v else "green")
            else:
                val = Text(str(v))
            whois_table.add_row(k.replace("_", " ").capitalize() + ":", val)

        whois_panel = Panel(whois_table, title="[bold magenta]WHOIS Information[/bold magenta]", border_style="magenta")
        console.print(whois_panel)

    # --- DNS ---
    dns_data = data.get("dns", {})
    dns_table = Table.grid(padding=(0,1))
    dns_table.add_column(justify="right", style="bold")
    dns_table.add_column(ratio=3, style="cyan", overflow="fold")

    for rtype in ["A", "MX", "NS", "TXT"]:
        recs = dns_data.get(rtype, [])
        dns_table.add_row(f"{rtype} Records:", ", ".join(recs) if recs else "None")
    dns_panel = Panel(dns_table, title="[bold cyan]DNS Records[/bold cyan]", border_style="cyan")
    console.print(dns_panel)

    # --- Hosting Info ---
    host = data.get("host", {})
    geo = host.get("geolocation", {})
    abuse = host.get("abuse_contact", {})

    hosting_table = Table.grid(padding=(0,1))
    hosting_table.add_column(justify="right", style="bold")
    hosting_table.add_column(ratio=3, style="cyan", overflow="fold")

    hosting_table.add_row("IP:", host.get('ip', "N/A"))
    hosting_table.add_row("ASN:", str(host.get('asn', "N/A")))
    hosting_table.add_row("Host Name:", str(host.get('hosted_by', "N/A")))
    hosting_table.add_row("Country:", geo.get('country', "N/A"))
    hosting_table.add_row("ISP:", geo.get('isp', "N/A"))
    hosting_table.add_row("Abuse Contact Email:", abuse.get('email', "N/A"))
    hosting_table.add_row("Abuse Contact Address:", abuse.get('address', "N/A"))
    hosting_table.add_row("Abuse Contact Country:", abuse.get('country', "N/A"))
    hosting_table.add_row("Abuse Contact Phone:", abuse.get('phone', "N/A"))

    hosting_panel = Panel(hosting_table, title="[bold green]Hosting Info[/bold green]", border_style="green")
    console.print(hosting_panel)

    # --- IP Geolocation ---
    ip_geo = data.get("ip_geolocation", {})
    if ip_geo:
        geo_table = Table.grid(padding=(0,1))
        geo_table.add_column(justify="right", style="bold")
        geo_table.add_column(ratio=3, style="cyan", overflow="fold")
        for k, v in ip_geo.items():
            geo_table.add_row(k.capitalize() + ":", str(v))
        geo_panel = Panel(geo_table, title="[bold green]IP Geolocation[/bold green]", border_style="green")
        console.print(geo_panel)

    # --- SSL Certificate ---
    ssl_cert = data.get("ssl_certificate", {})
    if "error" in ssl_cert:
        console.print(Panel(f"[red]Error: {ssl_cert['error']}[/red]",
                            title="[bold yellow]SSL Certificate Info[/bold yellow]", border_style="red"))
    else:
        ssl_table = Table.grid(padding=(0,1))
        ssl_table.add_column(justify="right", style="bold")
        ssl_table.add_column(ratio=3, style="cyan", overflow="fold")

        ssl_table.add_row("Issuer:", str(ssl_cert.get('issuer', 'N/A')))
        ssl_table.add_row("Subject:", str(ssl_cert.get('subject', 'N/A')))
        ssl_table.add_row("Serial Number:", str(ssl_cert.get('serial_number', 'N/A')))
        ssl_table.add_row("Valid From:", str(ssl_cert.get('valid_from', 'N/A')))
        ssl_table.add_row("Valid Until:", str(ssl_cert.get('valid_to', 'N/A')))
        ssl_table.add_row("SHA1 Fingerprint:", str(ssl_cert.get('sha1_fingerprint', 'N/A')))
        ssl_table.add_row("Self-Signed:", "[red]Yes[/red]"
        if ssl_cert.get('is_self_signed') else "[green]No[/green]")
        ssl_table.add_row("Low Trust CA:", "[red]Yes[/red]"
        if ssl_cert.get('low_trust_ca') else "[green]No[/green]")

        ssl_panel = Panel(ssl_table, title="[bold yellow]SSL Certificate Info[/bold yellow]", border_style="yellow")
        console.print(ssl_panel)

    # --- Passive DNS ---
    passive_dns = data.get("passive_dns", {})
    if "records" in passive_dns and passive_dns["records"]:
        pdns_table = Table(show_header=True, header_style="bold cyan")
        pdns_table.add_column("Record", overflow="fold")
        for rec in passive_dns["records"]:
            pdns_table.add_row(str(rec))
        pdns_panel = Panel(pdns_table, title="[bold cyan]Passive DNS[/bold cyan]", border_style="cyan")
        console.print(pdns_panel)
    else:
        console.print(Panel("[green]No Passive DNS records found or error.[/green]",
                            title="[bold cyan]Passive DNS[/bold cyan]", border_style="cyan"))

    # --- Threat Intel ---
    threat = data.get("threat_intel", {})
    if isinstance(threat, tuple):
        threat = threat[0] if threat else {}
    abuseipdb = threat.get("abuseipdb", {})
    score = abuseipdb.get("abuseConfidenceScore", None)

    threat_text = ""
    if score is not None:
        score_color = "red" if score >= 50 else "green"
        threat_text += f"AbuseIPDB Confidence Score: [{score_color}]{score}[/{score_color}]\n"
    else:
        threat_text += "AbuseIPDB Confidence Score: N/A\n"

    page_meta = data.get("page_metadata", {})
    threat_text += f"Page Title: {page_meta.get('title', 'N/A')}\n"
    threat_text += f"Meta Description: {page_meta.get('meta_description', 'N/A')}\n"
    h1s = ", ".join(page_meta.get('h1', [])) or "None"
    threat_text += f"H1 Headings: {h1s}\n"
    phishing_flag = page_meta.get("phishing_keywords_found", False)
    phishing_str = "[red]Yes[/red]" if phishing_flag else "[green]No[/green]"
    threat_text += f"Phishing Keywords Found: {phishing_str}"

    threat_panel = Panel(threat_text, title="[bold red]Threat Intelligence[/bold red]", border_style="red")
    console.print(threat_panel)

    # --- Page Content ---
    favicon = data.get("favicon", {})
    page_content_text = ""
    if "error" in favicon:
        page_content_text += f"[red]Favicon Error: {favicon['error']}[/red]\n"
    else:
        page_content_text += f"Favicon URL: {favicon.get('favicon_url', 'N/A')}\n"
        page_content_text += f"Favicon MD5 Hash: {favicon.get('favicon_hash_md5', 'N/A')}\n"
    if data.get("content_hash"):
        page_content_text += f"Content SHA256 Hash: {data['content_hash']}"
    page_content_panel = Panel(page_content_text, title="[bold magenta]Page Content[/bold magenta]",
                               border_style="magenta")
    console.print(page_content_panel)

    # --- Lookalike Domains ---
    lookalikes = data.get("lookalike_domains", [])
    if not lookalikes:
        console.print(Panel("[green]None found.[/green]",
                            title="[bold magenta]Lookalike Domains[/bold magenta]", border_style="magenta"))
    else:
        for entry in lookalikes:
            domain = entry.get("domain", "N/A")
            variant = entry.get("matched_variant", "N/A")
            whois = entry.get("whois", {})
            domain_info = whois.get("domain_info", {})
            reg_dates = whois.get("registration_dates", {})
            scam = whois.get("scam_indicators", {})
            contacts = whois.get("contacts", {})
            name_servers = whois.get("name_servers", [])

            lookalike_table = Table.grid(padding=(0,1))
            lookalike_table.add_column(justify="right", style="bold")
            lookalike_table.add_column(ratio=3, style="cyan", overflow="fold")

            lookalike_table.add_row("Domain:", domain)
            lookalike_table.add_row("Matched Variant:", variant)
            lookalike_table.add_row("Registrar:", domain_info.get("registrar", "N/A"))
            lookalike_table.add_row("Status:", safe_str(domain_info.get("status", "N/A")))
            lookalike_table.add_row("Creation Date:", reg_dates.get("creation_date", "N/A"))
            lookalike_table.add_row("Updated Date:", reg_dates.get("updated_date", "N/A"))
            lookalike_table.add_row("Expiration Date:", reg_dates.get("expiration_date", "N/A"))
            lookalike_table.add_row("Domain Age (days):", str(reg_dates.get("domain_age_days", "N/A")))
            lookalike_table.add_row("Recently Created:", "[red]Yes[/red]"
            if scam.get("recently_created") else "[green]No[/green]")
            lookalike_table.add_row("Suspicious Registrar:", "[red]Yes[/red]"
            if scam.get("registrar_is_suspicious") else "[green]No[/green]")
            lookalike_table.add_row("No Emails Found:", "[red]Yes[/red]"
            if scam.get("no_emails_found") else "[green]No[/green]")
            lookalike_table.add_row("Suspicious TLD:", "[red]Yes[/red]"
            if scam.get("suspicious_tld") else "[green]No[/green]")
            lookalike_table.add_row("Missing Name Servers:", "[red]Yes[/red]"
            if scam.get("missing_name_servers") else "[green]No[/green]")
            emails_str = ", ".join(contacts.get("emails", [])) or "None"
            lookalike_table.add_row("Contact Emails:", emails_str)
            ns_str = ", ".join(name_servers) or "None"
            lookalike_table.add_row("Name Servers:", ns_str)

            panel = Panel(lookalike_table, title=f"[bold magenta]Lookalike Domain: {domain}[/bold magenta]",
                          border_style="magenta")
            console.print(panel)

    # --- Risk Summary ---
    score = data.get('risk_score', 'N/A')
    score_style = "bold red" if isinstance(score, int) and score >= 50 else "bold green"
    score_text = Text(str(score), style=score_style)
    console.print(Panel(f"Overall Risk Score: {score_text}", title="[bold red]Risk Summary[/bold red]",
                        border_style="red"))

def print_banner():
    # Stylized banner title
    ascii_banner = pyfiglet.figlet_format("Osiris", font="ansi_shadow")
    banner = f"[bold cyan]{ascii_banner}[/bold cyan]"

    # Subtitle with emojis and styling
    subtitle = (
        "[bold white]🔍 OSINT CLI Tool[/bold white] for tracking "
        "[magenta]phishing[/magenta], [red]scams[/red], "
        "[yellow]impersonation[/yellow], and [blue]brand abuse[/blue] at scale."
    )

    # Print all elements with spacing
    console.print("\n" * 1)
    console.print(banner)
    console.print(subtitle)
    console.print("\n")
    console.print(f"💡 {intro_message}", style="dim")
