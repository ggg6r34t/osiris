import json
import os
from rich.console import Console

from osiris.data.platforms import PLATFORM_TEMPLATES

console = Console()


# Look for a custom file in the project root
CUSTOM_PLATFORMS_FILE = os.path.join(os.path.dirname(__file__), "../../custom_platforms.json")

def load_platform_templates(custom_path=None, use_default=True):
    """
    Load and merge platform templates from the default and optional custom JSON file.
    If you use_default is False, only the custom templates will be loaded (if provided).
    """
    templates = PLATFORM_TEMPLATES.copy() if use_default else {}

    if custom_path:
        if not os.path.isfile(custom_path):
            print(f"[!] Custom platforms file not found: {custom_path}")
            return templates

        try:
            with open(custom_path, 'r', encoding='utf-8') as f:
                custom_templates = json.load(f)

            if isinstance(custom_templates, dict):
                for category, platforms in custom_templates.items():
                    if isinstance(platforms, dict):
                        if category in templates:
                            templates[category].update(platforms)
                        else:
                            templates[category] = platforms
                    else:
                        print(f"[!] Skipped invalid platforms for category '{category}' (expected dict).")
            else:
                print(f"[!] Custom platforms file format invalid: must be a dictionary.")

        except json.JSONDecodeError:
            print(f"[!] Failed to parse JSON in custom platforms file: {custom_path}")

    return templates

def add_custom_platform(category, name, url):
    if not url or "{query}" not in url:
        console.print("[bold red]Error:[/bold red] URL must include `{query}` placeholder.")
        return

    if os.path.exists(CUSTOM_PLATFORMS_FILE):
        with open(CUSTOM_PLATFORMS_FILE, "r") as f:
            try:
                custom_data = json.load(f)
            except json.JSONDecodeError:
                custom_data = {}
    else:
        custom_data = {}

    if category not in custom_data:
        custom_data[category] = {}
    custom_data[category][name] = url

    with open(CUSTOM_PLATFORMS_FILE, "w") as f:
        json.dump(custom_data, f, indent=4)

    console.print(f"[bold green]✓ Added:[/bold green] {name} to \\[{category}]")


def load_custom_platforms():
    if os.path.exists(CUSTOM_PLATFORMS_FILE):
        with open(CUSTOM_PLATFORMS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_custom_platforms(platforms):
    with open(CUSTOM_PLATFORMS_FILE, "w") as f:
        json.dump(platforms, f, indent=2)

def list_custom_platforms():
    platforms = load_custom_platforms()
    if not platforms:
        console.print("[yellow]No custom platforms added.[/yellow]")
        return

    console.print("\n[bold cyan]User-Added Custom Platforms:[/bold cyan]\n")
    for category, entries in platforms.items():
        console.print(f"[bold green]{category}[/bold green]")
        for name, url in entries.items():
            console.print(f"  • {name}: {url}")

def remove_custom_platform(category, name):
    platforms = load_custom_platforms()
    if category in platforms and name in platforms[category]:
        del platforms[category][name]
        if not platforms[category]:
            del platforms[category]
        save_custom_platforms(platforms)
        console.print(f"[green]Removed custom platform '{name}' from category '{category}'.[/green]")
    else:
        console.print(f"[red]Platform '{name}' not found in category '{category}'.[/red]")


# Load and merge custom platforms
if os.path.exists(CUSTOM_PLATFORMS_FILE):
    try:
        with open(CUSTOM_PLATFORMS_FILE, "r", ) as f:
            custom_templates = json.load(f)
            for category, platforms in custom_templates.items():
                if category not in PLATFORM_TEMPLATES:
                    PLATFORM_TEMPLATES[category] = {}
                PLATFORM_TEMPLATES[category].update(platforms)
    except Exception as e:
        print(f"[!] Failed to load custom_platforms.json: {e}")
