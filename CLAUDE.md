# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Osiris is a **single-operator investigation workbench** for brand abuse, phishing, and executive protection
(Python 3.9+ backend / Next.js frontend). It started as an OSINT link engine and grew into a platform spanning a
case's lifecycle — **discover → assess → decide → act → monitor**:

- **Discover** — per-platform OSINT search-link generation across categorized platforms; lookalike/typosquat
  discovery (cert-transparency Domain Match, DNSTwist), clone detection, IP-pivot/reverse-IP.
- **Assess** — domain enrichment (WHOIS/DNS/hosting/SSL/favicon + VirusTotal/urlscan/AbuseIPDB threat intel + a
  computed risk score); a VIP protective-intelligence exposure scorecard.
- **Act** — the Abuse Router (who to report a domain to + is it still live), pre-filled takedown emails,
  screenshots, IOC/PDF/CSV exports.
- **Persist & monitor** — cases/history in SQLite, a monitoring watchlist with change-detection diff, and
  Telegram/webhook alerting.

It is deliberately **local and single-operator**: no auth, local SQLite, opt-in enrichment (graceful without
keys), and several signals are analyst-guiding heuristics (handle resolution, mention volume, geo tier, liveness
verdicts). Two surfaces share the same `src/osiris/` core: a **CLI** (`cli.py`) and a **web workbench**
(FastAPI `api.py` + `web/` Next.js) — the web workbench is now the primary interface.

There **is** a test suite: `tests/test_smoke.py` (offline; `python -m pytest tests/test_smoke.py -q`).

## Running the tool

**Web workbench (primary):**
```bash
./run.sh            # builds the frontend if needed, then starts FastAPI (:8000) + Next.js (:3000)
./run.sh --build    # force a fresh production build first
# dev, hot-reload: `uvicorn osiris.api:app --port 8000 --reload` + `cd web && npm run dev`
```
The FastAPI app is `osiris.api:app`. `run.sh` loads `.env` (gitignored). See `SETUP.md` for keys and manual steps.

**CLI:**
```bash
pip install -r requirements.txt
./osiris <target> [options]          # root launcher, adds src/ to sys.path then calls osiris.cli.main
python3 osiris <target> [options]    # equivalent
osiris <target> [options]            # only if installed via `pip install -e .`
osiris --monitor                     # re-run watchlist targets, fire alerts on new findings (cron-friendly)
```

`./osiris` (in the repo root, not `src/osiris/`) is a thin launcher: it prepends `src/` to `sys.path` and calls
`osiris.cli.main()`. There is no build step for the Python side; changes under `src/osiris/` take effect immediately.

`api_server.py` is a legacy stub (calls `generate_search_links` with a stale two-arg signature) — **ignore it**;
the real API is `osiris.api`.

## Architecture

Everything lives under `src/osiris/`, installed as the `osiris` package (`package_dir={"": "src"}` in `setup.py`),
with two entry points over a shared set of helpers:

- **`cli.py`** — the CLI entry point and orchestrator: owns `argparse` and all control flow. No plugin system or
  dynamic dispatch — adding a CLI flag means editing `parse_args()` and the corresponding branch in `main()`.
- **`api.py`** — the FastAPI app and the web workbench's orchestrator: one endpoint per feature. Shared robustness
  helpers wrap every handler — `_run()` (upstream errors → CORS-safe HTTPException 502), `_bounded(fn, timeout)`
  (hard wall-clock timeout → 504), `_cached(key, producer, refresh)` (~1h in-process TTL, `refresh` bypasses),
  `_record()` (best-effort history logging). Adding a web feature = a new module + a new endpoint here.

Both call into focused, mostly-stateless helper modules:

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
  SecurityTrails/ipinfo/VirusTotal/urlscan lookups (all optional, gated by env vars), reverse-IP/`ip_pivot`, and
  `calculate_risk_score`. `enrich()` (parallelized via ThreadPoolExecutor) is the single entry point used by
  `--enrich`, the web Enrich endpoint, and `--deep-search`. Also exposes shared HTTP helpers (`http_get`,
  `get_request_timeout`, `get_proxies`) reused by the newer feature modules.
- **`domain_matcher.py`** / **`variant_generator.py`** / **`dnstwist.py`** — three different approaches to finding
  suspicious/lookalike domains for a base domain (custom variant generation + WHOIS check, vs. shelling out to the
  `dnstwist` library). `--domain-match` uses `domain_matcher`, `--dnstwist` uses `dnstwist.py`.
- **`clone_detector.py`** / **`text_clone_search.py`** — website clone detection: one compares candidate domains
  against a known base domain (page hash/metadata similarity from `enrichment.py`), the other searches engines via
  dorks for pages containing specific legitimate site text.
- **`run_phishing_dorks.py`** — generates search-engine dork queries for phishing detection.
  Used standalone and as part of `--deep-search`.
- **`abuse_router.py`** — the Abuse Router: for any domain, resolves who to report abuse to (registrar via domain
  RDAP over `rdap.org` — **needs a User-Agent header or it 403s** — hosting/CDN via IP RDAP, email provider from
  MX) with email-or-web-form contacts, plus a live-status verdict from DNS/MX/RDAP status codes, an escalation
  path, blocklist/browser reporting channels, and a pre-filled report (reuses `takedown.py`). Curated abuse map is
  overridable via `abuse_contacts.json` / `OSIRIS_ABUSE_CONTACTS_FILE`.
- **`vip.py`** — VIP protective-intelligence exposure scorecard: account footprint (handle resolution across ~20
  platforms) + name-mention volume (Brave, opt-in) → presence level, breach exposure (HIBP, opt-in), geo tier
  (overridable via `geo_risk.json` / `OSIRIS_GEO_RISK_FILE`), impersonation count → High/Med/Low + overall score,
  with investigator pivots. Scoring functions are pure/unit-tested; network signals degrade gracefully.
- **`monitor.py`** — monitoring: `run_monitor(target)` re-runs lookalike tools, diffs vs. the last snapshot
  (`storage`), and fires alerts on new findings. Pure `diff()` is unit-tested. Driven by the web Monitor tab and
  `osiris --monitor` (cron).
- **`notify.py`** — opt-in alerting (Telegram + generic webhook), a no-op when unconfigured. `notify_new_findings`
  is called from `run_monitor`; `channels()`/`notify()` back the `/api/notify/*` endpoints.
- **`takedown.py`** — builds a pre-filled abuse/takedown email (`{to, subject, body}`) from enrichment-shaped data.
- **`screenshot.py`** — optional headless page capture via Playwright (import-guarded; raises a typed
  "not installed" error so the UI degrades gracefully). Install via `requirements-screenshots.txt`.
- **`storage.py`** — the persistence layer: stdlib `sqlite3` (`osiris.db`, gitignored; thread-safe shared conn,
  lazy schema — new tables are added to `_SCHEMA` as `CREATE IF NOT EXISTS`, applied on next process start, no
  migration). Tables: history, cases + case_items, watchlist, monitor_snapshots, takedowns + takedown_events.
  The takedown helpers own the lifecycle state machine (`record_takedown_check` auto-transitions reported→down and
  down→relisted from a liveness state); `abuse_router.domain_status()` supplies that state. Used by `api.py`,
  `monitor.py`, and `cli.py` (`--check-takedowns`).
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

### Web workbench (`web/`)

Next.js (App Router, TypeScript, React) frontend calling `osiris.api` (base URL `NEXT_PUBLIC_API_BASE_URL`,
default `http://localhost:8000`). `lib/api.ts` + `lib/types.ts` are the typed client; `components/` holds the
sections (`SearchPanel`, `DomainTools` + `domain/*` sub-tools, `VipView`, `Workspace` cases/monitor/history,
etc.). A feature is typically: a `src/osiris/` module → an `api.py` endpoint → a client fn in `lib/api.ts` +
types → a component. **Heed `web/AGENTS.md`:** this Next.js version has breaking changes vs. training data —
consult `node_modules/next/dist/docs/` before writing frontend code. Verify with `npx tsc --noEmit` + `npx eslint .`
in `web/`, and `python -m pytest tests/test_smoke.py -q` for the backend.

Local config files (all gitignored, with committed `*.example.json` templates where relevant):
`.env`, `osiris.db`, `custom_platforms.json`, `geo_risk.json`, `abuse_contacts.json`.

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
