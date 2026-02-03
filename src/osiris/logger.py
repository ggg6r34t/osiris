from pathlib import Path
from datetime import datetime
import csv
import json
from typing import Any, Dict, Optional


EVENT_LOG_FILE = Path("logs/events.jsonl")

def log_search_history(target, links):
    Path("logs").mkdir(exist_ok=True)
    log_file = Path("logs/history.csv")

    is_new = not log_file.exists()
    with log_file.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(["timestamp", "target", "platform", "category", "url"])

        for link in links:
            writer.writerow([
                datetime.utcnow().isoformat(),
                target,
                link["platform"],
                link["category"],
                link["url"]
            ])


def log_event(event: str, data: Optional[Dict[str, Any]] = None, level: str = "info") -> None:
    EVENT_LOG_FILE.parent.mkdir(exist_ok=True)
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "level": level,
        "event": event,
        "data": data or {},
    }
    try:
        with EVENT_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass
