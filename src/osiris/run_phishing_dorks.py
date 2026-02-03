import urllib.parse
from rich.console import Console
from osiris.link_opener import open_links_in_browser

console = Console()

PHISHING_DORK_ENGINES = {
    "Google": "https://www.google.com/search?q=site:*+intitle:{query}",
    "Bing": "https://www.bing.com/search?q=site:*+intitle:{query}",
    "DuckDuckGo": "https://duckduckgo.com/?q=site:*+intitle:{query}",
    "Yahoo": "https://search.yahoo.com/search?p=site:*+intitle:{query}",
}

def run_phishing_dorks(keywords: list[str], open_browser=False, browser_name=None, randomize=False, quiet: bool = False) -> list[dict]:
    """
    Generates phishing detection dork URLs using provided keywords.
    Optionally opens them in browser.
    Returns list of dicts with platform, category, url.
    """
    phishing_links = []

    for keyword in keywords:
        if not keyword.strip():
            continue
        encoded = urllib.parse.quote_plus(keyword.strip())
        for engine, template in PHISHING_DORK_ENGINES.items():
            url = template.format(query=encoded)
            phishing_links.append({
                "platform": engine,
                "category": "phishing_dork_search",
                "url": url
            })

    if not quiet:
        console.print("\n🔍 Phishing Dork Search Links:\n")
        for link in phishing_links:
            console.print(f"[bold magenta]{link['platform']}[/bold magenta]: {link['url']}")
        console.print("\n")

    if open_browser:
        open_links_in_browser(phishing_links, randomize=randomize, browser_name=browser_name)

    return phishing_links
