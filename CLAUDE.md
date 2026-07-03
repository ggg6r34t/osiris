# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Osiris is a Python 3.9+ OSINT CLI tool for investigating trademark violations, people, scams, and phishing across
categorized platforms (social networks, mobile app stores, marketplaces, messengers, etc.). It generates
per-platform search links for a target, and separately offers domain-focused investigation features: WHOIS/DNS/
hosting enrichment, typosquatting/lookalike domain detection, website clone detection, and phishing dork search.

There is no test suite in this repo.

## Running the tool

```bash
pip install -r requirements.txt
./osiris <target> [options]          # root launcher, adds src/ to sys.path then calls osiris.cli.main
python3 osiris <target> [options]    # equivalent
osiris <target> [options]            # only if installed via `pip install -e .`
```

`./osiris` (in the repo root, not `src/osiris/`) is a thin launcher: it prepends `src/` to `sys.path` and calls
`osiris.cli.main()`. There is no build step; changes under `src/osiris/` take effect immediately.

A minimal FastAPI wrapper exists at `api_server.py` (exposes `/search/`), run via `uvicorn api_server:app`. Note it
calls `generate_search_links(target, category)` with only two args — this is out of sync with the current
three-arg signature in `search_links.py` (which also needs `platform_templates`), so it will not work unmodified.

## Architecture

Everything lives under `src/osiris/`, installed as the `osiris` package (`package_dir={"": "src"}` in `setup.py`).
`cli.py` is the single entry point and orchestrator — it owns argument parsing (`argparse`) and all control flow;
every other module is a focused, mostly-stateless helper that `cli.py` calls into. There's no plugin system or
dynamic dispatch: adding a CLI flag means editing `parse_args()` and the corresponding branch in `main()` directly.

Key modules and how they relate:

- **`data/platforms.py`** — `PLATFORM_TEMPLATES`: the static dict of `{category: {platform_name: url_template}}`
  defining every built-in search target. URL templates use a `{query}` placeholder. This is the data source for
  most search-link generation.
- **`platform_functions.py`** — merges `PLATFORM_TEMPLATES` with user-defined platforms from
  `custom_platforms.json` (repo-root-adjacent file, gitignored) and/or a `--load-custom-template` JSON file.
  `load_platform_templates()` is the function `cli.py` calls before every search to get the effective template set.
- **`search_links.py`** — `generate_search_links(target, platforms, platform_templates)`: the core matching logic
  that expands templates into concrete URLs for a target, filtered by requested platforms/categories.
- **`input_handler.py`** / **`utils.py`** (`fuzzy_match_platforms`) — normalize and fuzzy-match the `--platforms`
  argument against known platform/category names.
- **`enrichment.py`** — domain intelligence: WHOIS, DNS resolution, hosting/ASN info, SSL cert info, AbuseIPDB/
  SecurityTrails/ipinfo lookups (all optional, gated by env vars), and `calculate_risk_score`. `enrich()` is the
  single entry point used by both `--enrich` and `--deep-search`.
- **`domain_matcher.py`** / **`variant_generator.py`** / **`dnstwist.py`** — three different approaches to finding
  suspicious/lookalike domains for a base domain (custom variant generation + WHOIS check, vs. shelling out to the
  `dnstwist` library). `--domain-match` uses `domain_matcher`, `--dnstwist` uses `dnstwist.py`.
- **`clone_detector.py`** / **`text_clone_search.py`** — website clone detection: one compares candidate domains
  against a known base domain (page hash/metadata similarity from `enrichment.py`), the other searches engines via
  dorks for pages containing specific legitimate site text.
- **`run_phishing_dorks.py`** — generates search-engine dork queries for phishing detection.
  Used standalone and as part of `--deep-search`.
- **`threat_scoring.py`** — `score_threat(url, target)`: heuristic scoring used by `--score`/`--sort-score` to
  annotate/rank generated links.
- **`link_opener.py`** — opens result links in a browser (`--open`), with randomization/delay/max-open controls.
- **`exporter.py`** — writes result lists to CSV/JSON/TXT under `--save-dir` (default `exports/`, gitignored).
- **`logger.py`** — two independent logging concerns: `log_search_history` appends CSV rows to `logs/history.csv`
  per search, `log_event` appends JSONL structured events to `logs/events.jsonl` (both dirs gitignored).
- **`config.py`** — `load_config()` merges `DEFAULT_CONFIG` (built from `OSIRIS_*` env vars) with an optional JSON
  config file (`--config`, or auto-discovered `osiris.config.json` / `osiris.json` / `~/.osiris.json`).
  `apply_proxy_env()` pushes proxy settings into process env vars for libraries that read them directly.
  CLI flags always take precedence over config file, which takes precedence over env var defaults — this
  precedence chain is assembled manually in `cli.py main()`, not inside `config.py`.
- **`utils.py`** — grab-bag of shared helpers: HTTP session building, link status checking (with retries/rate
  limiting/proxy support), grouping/deduping links, and all Rich console output formatting (banner, tables,
  enrichment printing).

### `--deep-search` flow

`--deep-search` in `cli.py` is the "run everything" mode: it composes `enrich`, `find_similar_domains`,
`detect_clones`, `text_clone_search`, `generate_search_links`, and `run_phishing_dorks` into one combined result
set, then applies the same scoring/dedup/check/export pipeline as a normal search. When modifying any of those
individual features, check whether `--deep-search`'s composition in `cli.py` needs a corresponding update.

### Custom platforms vs. custom templates

These are two distinct, easily-confused mechanisms:
- `--add-custom-platform` / `--remove-custom-platform` / `--list-custom-platforms` persist to
  `custom_platforms.json` (gitignored) via `platform_functions.py`, and are auto-merged into
  `PLATFORM_TEMPLATES` at import time.
- `--load-custom-template FILE` loads a one-off JSON file at runtime and, unless `--platforms` is also given,
  *replaces* rather than merges with the defaults (see `use_default_templates` logic in `cli.py`).

## Configuration surface

Runtime behavior (timeouts, rate limits, proxy, TLS verification, User-Agent) is configurable via, in precedence
order: CLI flags > `--config` JSON file (or auto-discovered `osiris.config.json`/`osiris.json`/`~/.osiris.json`) >
`OSIRIS_*` environment variables. Optional enrichment API keys (`ABUSEIPDB_API_KEY`, `SECURITYTRAILS_API_KEY`,
`IPINFO_TOKEN`) are read directly from env in `enrichment.py` and silently degrade features when absent.
