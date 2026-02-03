import random
import webbrowser
import time
from typing import Optional

def list_available_browsers():
    try:
        # Try to fetch default browser first
        print("Default Browser:", webbrowser.get().name)

        # Attempt to get all available browsers (webbrowser.get() handles browser names)
        print("\nAvailable Browsers:")
        browsers = ["firefox", "chrome", "safari", "edge", "opera", "brave", "vivaldi"]
        for browser in browsers:
            try:
                webbrowser.get(browser)
                print(f"  • {browser}")
            except webbrowser.Error:
                pass
    except Exception as e:
        print(f"[!] Error while listing browsers: {e}")

def open_links_in_browser(links, randomize=False, browser_name=None, delay: float = 0.5, max_open: Optional[int] = None):
    if randomize:
        random.shuffle(links)
    try:
        browser = webbrowser.get(browser_name) if browser_name else webbrowser
    except webbrowser.Error as e:
        print(f"[!] Could not get browser '{browser_name}': {e}")
        print("[*] Falling back to system default browser.")
        browser = webbrowser
    opened = 0
    for link in links:
        if isinstance(max_open, int) and max_open > 0 and opened >= max_open:
            break
        url = link.get("url") if isinstance(link, dict) else None
        if not url:
            continue
        browser.open(url)
        opened += 1
        time.sleep(max(0.0, delay)) # Delay between tabs
