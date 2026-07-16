"""Optional headless screenshot capture via Playwright.

Playwright is an optional dependency — if it (or its Chromium browser) isn't
installed, `capture` raises ScreenshotUnavailable with an actionable message so
the API can return a clean 503 instead of a crash. Install with:

    pip install -r requirements-screenshots.txt
    playwright install chromium
"""


class ScreenshotUnavailable(RuntimeError):
    """Raised when Playwright / Chromium isn't installed."""


def capture(url: str, timeout_ms: int = 20000) -> bytes:
    """Return a PNG screenshot of `url` (above-the-fold). Sync Playwright API —
    the caller runs this in a worker thread with no asyncio loop."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise ScreenshotUnavailable(
            "Screenshots need Playwright. Run: pip install -r "
            "requirements-screenshots.txt && playwright install chromium"
        ) from e

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox"])
            try:
                page = browser.new_page(
                    viewport={"width": 1280, "height": 800},
                    ignore_https_errors=True,
                )
                page.goto(url, wait_until="load", timeout=timeout_ms)
                return page.screenshot(full_page=False)
            finally:
                browser.close()
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        if "Executable doesn't exist" in msg or "playwright install" in msg:
            raise ScreenshotUnavailable(
                "Chromium isn't installed. Run: playwright install chromium"
            ) from e
        raise
