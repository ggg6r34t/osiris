import urllib.parse


def generate_search_links(target, platforms, platform_templates):
    """
    Generate search links for a target using the specified platform templates.
    """
    links = []
    target_encoded = urllib.parse.quote_plus(str(target))

    for category, platforms_data in platform_templates.items():
        for platform, url_template in platforms_data.items():
            if "all" in platforms or category in platforms or platform.lower() in platforms:
                # Use str.replace (not str.format) so custom templates containing
                # stray braces (e.g. "…/{id}?q={query}") can't raise KeyError/
                # ValueError and break the whole search.
                url = url_template.replace("{query}", target_encoded)
                links.append({
                    "platform": platform,
                    "category": category,
                    "url": url
                })
    return links
