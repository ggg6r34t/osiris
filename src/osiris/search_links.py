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
                if "{query}" in url_template:
                    url = url_template.format(query=target_encoded)
                else:
                    url = url_template
                links.append({
                    "platform": platform,
                    "category": category,
                    "url": url
                })
    return links
