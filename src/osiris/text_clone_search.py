import urllib.parse
from rich.console import Console

from osiris.link_opener import open_links_in_browser

console = Console()

DORK_ENGINES = {
    "Google": "https://www.google.com/search?q=site:*+{query}",
    "Bing": "https://www.bing.com/search?q=site:*+{query}",
    "DuckDuckGo": "https://duckduckgo.com/?q=site:*+{query}",
    "Yahoo": "https://search.yahoo.com/search?p=site:*+{query}",
}

def generate_text_clone_search_links(texts: list[str]) -> list[dict]:
    """
    Generates clone detection dork search URLs across multiple engines.
    Returns a list of dicts with platform, category, and URL.
    """
    clone_links = []
    for snippet in texts:
        if not snippet.strip():
            continue
        quoted_text = f'"{snippet.strip()}"'
        encoded_text = urllib.parse.quote_plus(quoted_text)
        for engine, template in DORK_ENGINES.items():
            search_url = template.format(query=encoded_text)
            clone_links.append({
                "platform": engine,
                "category": "text_clone_detection",
                "url": search_url
            })

    return clone_links


def text_clone_search(texts: list[str], open_browser=True, browser_name=None, randomize=False, quiet: bool = False) -> list[dict]:
    """
    Generates and optionally opens clone detection links.
    Returns the generated link list.
    """
    links = generate_text_clone_search_links(texts)

    if not quiet:
        print("\n🔍 Clone Detection Dork Search Links:\n")
        for link in links:
            console.print(f"[bold cyan]{link['platform']}[/bold cyan]: {link['url']}")
        print("\n")

    if open_browser:
        open_links_in_browser(links, randomize=randomize, browser_name=browser_name)

    return links
