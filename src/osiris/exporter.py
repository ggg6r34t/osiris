import csv
import json
from pathlib import Path
from rich.console import Console

console = Console()

def export_data(data, fmt, output, save_dir="exports"):
    export_path = Path(save_dir)
    export_path.mkdir(parents=True, exist_ok=True)

    filename = export_path / f"{output}.{fmt}"

    if not isinstance(data, list):
        console.print("[red]Export failed:[/red] data must be a list of dicts.")
        return

    if fmt == "csv":
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["platform", "category", "url"], extrasaction="ignore")
            writer.writeheader()
            writer.writerows(data)

    elif fmt == "json":
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    elif fmt == "txt":
        with open(filename, "w", encoding="utf-8") as f:
            for entry in data:
                category = entry.get("category", "N/A") if isinstance(entry, dict) else "N/A"
                platform = entry.get("platform", "N/A") if isinstance(entry, dict) else "N/A"
                url = entry.get("url", "N/A") if isinstance(entry, dict) else "N/A"
                f.write(f"[{category}] {platform}: {url}\n")

    console.print(f"[green]Exported results to [bold]{filename}[/bold]")


def export_to_json(results, filepath="searchgenius_results.json"):
    with open(filepath, "w") as f:
        json.dump(results, f, indent=2)
