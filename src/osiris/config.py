import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG = {
    "user_agent": os.getenv("OSIRIS_USER_AGENT", "Osiris/1.0 (+https://github.com/ggg6r34t/osiris)"),
    "request_timeout": float(os.getenv("OSIRIS_REQUEST_TIMEOUT", "10")),
    "rate_limit_per_sec": float(os.getenv("OSIRIS_RATE_LIMIT", "0")),
    "check_timeout": int(os.getenv("OSIRIS_CHECK_TIMEOUT", "5")),
    "check_retries": int(os.getenv("OSIRIS_CHECK_RETRIES", "2")),
    "max_links": int(os.getenv("OSIRIS_MAX_LINKS", "0")),
    "http_proxy": os.getenv("OSIRIS_HTTP_PROXY", os.getenv("HTTP_PROXY", "")),
    "https_proxy": os.getenv("OSIRIS_HTTPS_PROXY", os.getenv("HTTPS_PROXY", "")),
    "verify_tls": os.getenv("OSIRIS_VERIFY_TLS", "true").lower() != "false",
    "json_output": False,
}

DEFAULT_CONFIG_PATHS = [
    Path("osiris.config.json"),
    Path("osiris.json"),
    Path.home() / ".osiris.json",
]


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    explicit = config_path is not None
    paths = [Path(config_path)] if config_path else DEFAULT_CONFIG_PATHS

    config: Dict[str, Any] = dict(DEFAULT_CONFIG)
    for path in paths:
        if path and path.exists() and path.is_file():
            try:
                with path.open("r", encoding="utf-8") as f:
                    file_config = json.load(f)
                if isinstance(file_config, dict):
                    config.update(file_config)
            except Exception as e:
                # An explicitly-requested config that fails to parse must not be
                # silently ignored — the user believes it was applied.
                if explicit:
                    print(f"[!] Failed to read config file {config_path}: {e}", file=sys.stderr)
            return config

    if explicit:
        print(f"[!] Config file not found: {config_path}", file=sys.stderr)

    return config


def apply_proxy_env(config: Dict[str, Any]) -> None:
    http_proxy = config.get("http_proxy") or ""
    https_proxy = config.get("https_proxy") or ""
    if http_proxy:
        os.environ["HTTP_PROXY"] = http_proxy
        os.environ["http_proxy"] = http_proxy
    if https_proxy:
        os.environ["HTTPS_PROXY"] = https_proxy
        os.environ["https_proxy"] = https_proxy
