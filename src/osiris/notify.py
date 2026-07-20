"""Optional alerting via Telegram and/or a generic webhook.

Opt-in via environment; a no-op when unconfigured, so it is safe to call from
monitoring runs. Configure any/all of:
  OSIRIS_TELEGRAM_BOT_TOKEN + OSIRIS_TELEGRAM_CHAT_ID   (Telegram bot)
  OSIRIS_ALERT_WEBHOOK_URL                              (generic JSON webhook)

Note: alerts send finding data to an external service (Telegram) or wherever the
webhook points — keep that in mind for sensitive investigations.
"""
import os
from typing import Optional

import requests

_TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _timeout() -> float:
    try:
        return float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "10") or 10)
    except ValueError:
        return 10.0


def channels() -> dict:
    """Which alert channels are currently configured (no network)."""
    return {
        "telegram": bool(
            os.getenv("OSIRIS_TELEGRAM_BOT_TOKEN")
            and os.getenv("OSIRIS_TELEGRAM_CHAT_ID")
        ),
        "webhook": bool(os.getenv("OSIRIS_ALERT_WEBHOOK_URL")),
    }


def send_telegram(text: str) -> dict:
    token = os.getenv("OSIRIS_TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("OSIRIS_TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return {"ok": False, "skipped": True}
    try:
        r = requests.post(
            _TELEGRAM_API.format(token=token),
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=_timeout(),
        )
        return {"ok": r.ok, "status": r.status_code}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def send_webhook(text: str, data: Optional[dict] = None) -> dict:
    url = os.getenv("OSIRIS_ALERT_WEBHOOK_URL")
    if not url:
        return {"ok": False, "skipped": True}
    try:
        r = requests.post(url, json={"text": text, "data": data or {}}, timeout=_timeout())
        return {"ok": r.ok, "status": r.status_code}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def notify(text: str, data: Optional[dict] = None) -> dict:
    """Send to every configured channel. Returns per-channel results."""
    return {"telegram": send_telegram(text), "webhook": send_webhook(text, data)}


def build_findings_message(target: str, report: dict) -> Optional[tuple[str, dict]]:
    """Return (text, payload) for the NEW findings in a monitor report, or None
    if there is nothing new."""
    lines = []
    payload: dict = {"target": target, "new": {}}
    for tool, r in (report or {}).items():
        new = r.get("new") or []
        if new:
            payload["new"][tool] = new
            preview = ", ".join(new[:10]) + (" …" if len(new) > 10 else "")
            lines.append(f"- {tool}: {len(new)} new — {preview}")
    if not lines:
        return None
    return (f"[Osiris] New lookalikes for {target}\n" + "\n".join(lines), payload)


def notify_new_findings(target: str, report: dict) -> Optional[dict]:
    """Alert on new monitoring findings (no-op if nothing new / unconfigured)."""
    built = build_findings_message(target, report)
    if built is None:
        return None
    text, payload = built
    return notify(text, payload)
