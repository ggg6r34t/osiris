# 🔍 Osiris

**A single-operator investigation workbench for brand abuse, phishing, and executive protection.**

Osiris began as an OSINT link engine and grew into a full **investigation platform** — a CLI *and* a web
workbench that carries a case through its whole lifecycle: **discover → assess → decide → act → monitor**. It
generates OSINT pivots, enriches and scores domains, resolves who to report abuse to, profiles a VIP's digital
exposure, files findings into cases, and watches targets for change — alerting you when something new appears.

Think of it as a personal **Digital Risk Protection (DRP)** / brand-abuse & executive-protection console, scoped
to one operator. Everything runs locally; enrichment integrations are opt-in and degrade gracefully without keys.

---

## 🚀 What it does

**Discover**
- OSINT search-link generation across categorized platforms (social, apps, web, messengers, marketplaces, …),
  with fuzzy matching, filtering, batch mode, threat scoring, reachability checks, and CSV/JSON/TXT export.
- Lookalike / typosquat discovery (certificate-transparency **Domain Match**, **DNSTwist** permutations),
  **Clone Detect**, and **IP Pivot** (reverse-IP co-hosted domains).

**Assess**
- **Enrich** — WHOIS/DNS/hosting/SSL/favicon + threat intel (VirusTotal, urlscan, AbuseIPDB) and a computed
  risk score; bulk mode + exports.
- **VIP Investigation** — a protective-intelligence exposure scorecard for a person (online presence, service
  discoverability, geo risk, impersonations → High/Med/Low + overall score, with investigator pivots).

**Act**
- **Abuse Router** — for any domain, resolves *who to report to* (registrar, hosting/CDN, email provider) with
  abuse-email or web-form links + an escalation path, and reads DNS/MX/RDAP to tell whether it's still live or
  already taken down. Pre-filled takedown emails, screenshots, IOC/PDF/CSV exports.

**Persist & monitor**
- **Cases & history** — a local investigation workspace (SQLite) with per-finding status/notes.
- **Monitoring** — a watchlist that re-runs lookalike scans and highlights new domains vs. the last run, with
  optional **Telegram / webhook alerts** and a cron-friendly `osiris --monitor`.

---

## 🧩 Use cases

- Run a brand-abuse / phishing investigation end to end: find lookalikes, assess them, route the takedown, file
  the case, and monitor for new impersonations.
- Check whether a fraudulent domain or email is still operational (or already suspended) from its DNS/MX/RDAP state.
- Produce a defensive digital-exposure profile for an executive/VIP (authorized protective-intelligence / DRP).
- Triage and enrich domains at scale, then export IOCs/reports for downstream tools.
- Extend it to your environment: custom search platforms, abuse-contact and geo-risk overrides — all via JSON.

> **Scope:** Osiris is a **local, single-operator** tool by design — no auth, local SQLite, opt-in enrichment,
> and several signals (handle resolution, mention volume, geo tier, liveness verdicts) are heuristics meant to
> guide an analyst, not to be authoritative. That's the line between it and a hosted, multi-tenant DRP product.

---

## 📦 Installation

1. **Ensure you have Python 3.9 or higher installed.** Check your version:

   ```bash
   python3 --version
   ```

   If you see Python 2.x, install or upgrade to Python 3 (e.g., via your package manager or from https://python.org).

2. **(Optional but recommended) Create and activate a virtual environment** to isolate dependencies:
   - On macOS/Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - On Windows PowerShell:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```

3. Clone the repository and navigate into the project directory:

   ```bash
   git clone https://github.com/ggg6r34t/osiris.git
   cd osiris
   ```

4. Install the required dependencies:

   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

   💡 If `pip` still points to Python 2, use `pip3` instead:

   ```bash
   pip3 install -r requirements.txt
   ```

5. Make the main script executable (if needed):

   ```bash
   chmod +x osiris
   ```

6. (Optional) Install the CLI entrypoint so `osiris` works anywhere:

```bash
pip install -e .
```

---

## 🧠 Usage

Run a search on a target across selected platforms:

```bash
./osiris Tesla --platforms web social_networks --export csv --open
```

Or, if installed with `pip install -e .`:

```bash
osiris Tesla --platforms web social_networks --export csv --open
```

Or directly with Python:

```bash
python3 osiris Tesla --platforms web social_networks --export csv --open
```

Use `-h` or `--help` to see all available options and flags:

```bash
./osiris --help
```

````

---

## 🧩 Adding Custom Platforms

You can extend the default platform database by providing your own custom platforms using the
`--add-custom-platform` flag.

```bash
./osiris --add-custom-platform "web" "Google" "https://www.google.com/search?q={query}"
````

### Custom JSON Format

```json
{
  "web": {
    "Google": "https://www.google.com/search?q={query}"
  },
  "social_networks": {
    "Facebook": "https://www.facebook.com/search/top?q={query}"
  }
}
```

---

### Arguments

| Argument                      | Description                                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------------------------ |
| `target`                      | Target name, company, or username                                                                      |
| `-p --platforms`              | List of platforms or categories to search                                                              |
| `--config FILE`               | Load configuration from a JSON file                                                                    |
| `--json`                      | Output machine-readable JSON to stdout                                                                 |
| `--targets-file FILE`         | Load multiple targets from a file (one target per line)                                                |
| `--tag STRING`                | Add a tag to logs/exports for investigation grouping                                                   |
| `-f --fuzzy`                  | Enable fuzzy matching for platforms                                                                    |
| `-d --dnstwist DOMAIN`        | Run `dnstwist` to find similar-looking domains                                                         |
| `-e --enrich [DOMAIN]`        | Enrich a domain with WHOIS, DNS, hosting, and abuse contact info. Can be used with or without `target` |
| `-x --export csv/json/txt`    | Export format for results (`csv`, `json`, `txt`)                                                       |
| `-o --output FILENAME`        | Output file base name (no extension)                                                                   |
| `-O --open`                   | Open search links in browser                                                                           |
| `-b --browser BROWSER`        | Browser to use for opening links (e.g., 'firefox', 'chrome'). Defaults to system browser.              |
| `-l --list-browsers`          | List all available browsers on the system (Windows only; others may require manual setup).             |
| `-s --save-dir DIRECTORY`     | Directory to save exported files                                                                       |
| `-r --randomize`              | Randomize link opening order                                                                           |
| `--open-delay SECONDS`        | Delay between opening browser tabs                                                                     |
| `--max-open N`                | Maximum number of links to open (0 = no limit)                                                         |
| `-c --check`                  | Check link status before opening                                                                       |
| `--check-timeout SECONDS`     | Timeout for link status checks                                                                         |
| `--check-retries N`           | Retry count for link status checks                                                                     |
| `--user-agent STRING`         | Override default User-Agent for HTTP requests                                                          |
| `--insecure`                  | Disable TLS verification for link status checks                                                        |
| `--request-timeout SECONDS`   | Default HTTP timeout for enrichment and network requests                                               |
| `--rate-limit N`              | Max HTTP requests per second for link checks (0 = no limit)                                            |
| `--max-links N`               | Maximum number of links to return after filtering (0 = no limit)                                       |
| `--dedupe`                    | Remove duplicate URLs from results                                                                     |
| `--exclude-platforms NAMES`   | Exclude specific platform names                                                                        |
| `--exclude-categories NAMES`  | Exclude specific categories                                                                            |
| `--score`                     | Annotate results with threat score labels                                                              |
| `--sort-score`                | Sort results by threat score (requires `--score`)                                                      |
| `--proxy URL`                 | Proxy URL for HTTP/HTTPS requests                                                                      |
| `--tor`                       | Route HTTP(S) requests through Tor (socks5h://127.0.0.1:9050)                                          |
| `-C --clone-detect DOMAIN`    | Detect cloned versions of a given domain                                                               |
| `-t --text-detect TEXT`       | Detect clones by comparing suspicious pages against provided legitimate text                           |
| `-D --deep-search`            | Perform an extensive OSINT scan                                                                        |
| `-m --domain-match DOMAIN`    | Detect lookalike or suspicious domains similar to the provided domain                                  |
| `-a --add-custom-platform`    | Add a custom platform                                                                                  |
| `-R --remove-custom-platform` | Remove a user-added custom platform                                                                    |
| `-L --list-custom-platform`   | List all user-added custom platforms                                                                   |
| `-T --load-custom-template`   | Load custom platform templates (overrides defaults unless --platforms is used)                         |
| `-g --log`                    | Log search history                                                                                     |
| `-P --list-platforms`         | List all supported platforms and categories                                                            |
| `-n --no-banner`              | Disable the ASCII banner display at startup                                                            |
| `-h --help`                   | Show this help message and exit                                                                        |

---

## 🌐 Web workbench

The primary interface is a web workbench under `web/` (Next.js) backed by a FastAPI server (`osiris.api`),
organized into sections — **Search**, **Domain Tools**, **VIP**, **Cases**, **Custom Platforms**, and
**Settings**:

- **Search** — target (single or batch), platform/category picker, and an Options panel exposing the CLI's
  search flags: fuzzy matching, dedupe, threat scoring + sort-by-score, max-links, exclude platforms/categories,
  tag, and server-side logging. Results are grouped by category with per-row/per-category/all selection, staggered
  **Open selected** in new tabs (max-open / randomize), **Check** reachability (live/dead badges +
  "reachable only" filter), copy, and CSV/JSON/TXT export.
- **Domain Tools** — the domain-intelligence modes: **Enrich** (WHOIS/DNS/hosting/SSL/favicon/threat-intel with a
  computed risk score), **URL Analyze** (fetches a suspected phishing page — HTML only, no JS — and flags
  credential-harvesting forms, cross-domain form posts, brand impersonation, redirect chains and page IOCs with a
  risk level), **URLScan** (submits a URL to **urlscan.io** for a sandboxed browser render — from urlscan's infra,
  not yours — returning a screenshot, malicious verdict + score, targeted brands, and the contacted-infrastructure
  map for campaign pivoting; defaults to an **unlisted** scan so it isn't exposed in urlscan's public search;
  needs `URLSCAN_API_KEY`), **Wayback** (archive.org history for a domain — first/last capture, years archived, and a
  per-year snapshot timeline; keyless), **Reputation** (checks a domain/IP against phishing & malware feeds — URLhaus, Spamhaus, SURBL, and
  Google Safe Browsing if a key is set — and rolls the hits into a listed/clean verdict), **Abuse Router** (for
  any domain: resolves *who to report abuse to* — registrar, hosting/CDN,
  email provider — with abuse-email **or web-form** links and an ordered escalation path, plus a live-status verdict
  from DNS/MX/RDAP status codes to tell whether a fraudulent domain/email is still up or already taken down; includes
  blocklist/browser reporting channels and a pre-filled report email; keyless RDAP+DNS, abuse map overridable via
  `abuse_contacts.json`), **Domain Match** (certificate-transparency lookalikes), **DNSTwist** (permutation scan),
  **IP Pivot** (reverse-IP: other domains co-hosted on the same IP + ASN/host facts), **Clone Detect**
  (byte-identical typosquat clones), **Brand Abuse (regex)** (regex search over the internal Panda
  dataset, with a built-in **Generate regex from a brand** helper that turns a brand/domain into a
  homoglyph/typosquat pattern), **Text Clone** and **Phishing Dorks** (dork-link builders), and **Deep Search** (all of the above
  combined). These make outbound network calls and can be slow; results are cached in-process for ~1 hour so
  re-querying is instant.
- **Cases** — a local investigation workspace (SQLite `osiris.db`, gitignored): **Cases** (group findings,
  per-item status/notes, "Add to case" from Enrich), **Takedowns** (track a domain's takedown through its
  lifecycle — new → reported → down → **relisted** — with an event timeline, aging, and auto re-checks that flag
  when a reported domain goes dark or comes back; "Track takedown" from the Abuse Router, `osiris --check-takedowns`
  for cron, Telegram/webhook alerts on change), **Monitor** (watchlist that re-runs Domain Match + DNSTwist
  and highlights newly-registered lookalikes vs. the last run — also `osiris --monitor` for cron), **Metrics**
  (operational KPIs over the local data: open takedowns, **MTTR** from reported→down, relisted count, aging
  buckets, and activity by tool), and **History**
  (recent runs). Enrich also has **bulk** mode, per-tool **CSV/JSON export**, a **↻ refresh** (cache bypass), a
  **takedown/abuse-email** generator, and **screenshots** of suspect pages.
- **Intake** — turn reports into structured intelligence. **IOC Extract** takes a pasted alert/report/email body,
  **refangs** defanged text (`hxxp`, `evil[.]com`, `user[at]host`), and extracts deduped indicators (domains, IPs,
  URLs, emails, MD5/SHA-1/SHA-256, CVEs) — then exports a **STIX 2.1 bundle** or **MISP event JSON** (importable,
  keyless) or files the indicators to a case. Case exports also gained **STIX** and **MISP** buttons.
  **Email Triage** parses a pasted or uploaded **`.eml`**: authentication results (**SPF/DKIM/DMARC**), the
  **Received** hop chain and best-guess **originating IP**, **From / Reply-To / Return-Path / display-name spoofing**
  flags, executable/macro attachment detection (name/type/size + hashes), and extracted IOCs — rolled up into a
  risk level. Add the findings to a case.
- **Playbooks** — guided workflows that chain the individual tools into one run and file the result to a case.
  **Domain / phishing assessment** runs Enrich → Page analysis → Reputation → Abuse routing on a single domain,
  rolls the signals into an overall risk verdict, and auto-opens a tracked takedown when high-risk. **Brand-abuse
  discovery** runs Domain Match + DNSTwist for a brand and files the candidate lookalikes to a case. Each step is
  isolated (one failing never aborts the run), and every run ends with recommended next actions.
- **VIP Investigation** — a protective-intelligence exposure scorecard for a person (executive-protection / DRP).
  Enter a VIP (name/aliases, emails, known handles, company, country) and Osiris scores four dimensions
  **High / Medium / Low** — online-presence volume (cross-platform handle resolution), service-account
  discoverability (breach exposure via HIBP + resolution), geo-location risk, and impersonations
  (investigator-confirmed) — plus an overall exposure score and investigator pivots (presence/handle discovery,
  impersonation hunt, family/relatives, business/associates, geo/location). It measures *risk levels* and hands
  you pivots — it does not harvest or store sensitive personal content. Save a scorecard to a case.
- **Custom Platforms** — add/list/remove user platforms (persisted to `custom_platforms.json`).
- **Settings** — User-Agent, request timeout, rate limit, HTTP(S) proxy, Tor, and TLS verification.

The web UI now covers the full CLI surface except a few flags that are inherently CLI/host-specific
(`--browser`/`--list-browsers`, `--save-dir`/`--output`, `--json`, `--no-banner`, `--config`).

### Run it (production, one command)

From the repo root (with the venv created and `pip install -e .` done):

```bash
./run.sh            # builds the frontend if needed, then starts both servers
./run.sh --build    # force a fresh production build first
```

Then open http://localhost:3000. Ctrl+C stops both servers. Ports can be overridden with
`OSIRIS_BACKEND_PORT` / `OSIRIS_FRONTEND_PORT`.

### Run it (development, two terminals)

```bash
# Terminal 1 — backend API (from repo root, with the venv active)
uvicorn osiris.api:app --reload --port 8000

# Terminal 2 — frontend
cd web && npm install && npm run dev
```

By default the frontend calls the API at `http://localhost:8000`; override with `NEXT_PUBLIC_API_BASE_URL`
(see `web/.env.local.example`).

### Backend configuration (optional)

Copy `.env.example` to `.env` (gitignored) and fill in what you need — `run.sh` loads it automatically:

- **Brand Abuse (regex) tool** requires the internal Panda API (VPN): `OSIRIS_PANDA_URL`, `OSIRIS_PANDA_LOGIN`,
  `OSIRIS_PANDA_KEY`. Without them the tool returns a clear "not configured" message.
- **Enrichment** API keys (optional, degrade gracefully): `ABUSEIPDB_API_KEY`, `SECURITYTRAILS_API_KEY`, `IPINFO_TOKEN`,
  `VIRUSTOTAL_API_KEY` (adds VirusTotal detections + reputation to Enrich and the risk score). urlscan.io reputation
  and IP-Pivot reverse-IP work without keys (rate-limited).
- **VIP investigation** (optional): `HAVEIBEENPWNED_API_KEY` adds breach-exposure to the service-discoverability
  score. `BRAVE_SEARCH_API_KEY` adds name-**mention volume** to the online-presence score (knowledge-panel, result
  density and news coverage → H/M/L), blended with account footprint so presence is High if strong on either axis.
  Without these keys those signals degrade gracefully (presence uses account footprint only; everything else works).
  The geo-risk tiers are overridable: copy `geo_risk.example.json` to `geo_risk.json` (gitignored) at the repo root,
  or point `OSIRIS_GEO_RISK_FILE` at a file — either `{"high": [...], "medium": [...], "low": [...]}` or a flat
  `{"country": "high"}` map (case-insensitive; file entries win over the built-in defaults). A VIP scorecard can be
  exported as a print-friendly **PDF report** or **JSON** from the dashboard.
- **Screenshots** (optional) — capture suspect/lookalike/clone pages headlessly. Install once:
  `pip install -r requirements-screenshots.txt && playwright install chromium`. Without it, the camera button
  shows a clear "install to enable" message and nothing else is affected.
- **Monitoring alerts** (optional) — when a monitor run (Run monitor button or `osiris --monitor`) finds new
  lookalikes, Osiris can push a notification. Telegram: set `OSIRIS_TELEGRAM_BOT_TOKEN` (from @BotFather) and
  `OSIRIS_TELEGRAM_CHAT_ID`. Generic webhook: set `OSIRIS_ALERT_WEBHOOK_URL` (Osiris POSTs `{"text", "data"}` —
  point it at an internal endpoint to keep alert data off external services). Both are off unless set; use the
  Monitor tab's **Send test** button to verify wiring. Note: alerts push finding data to the configured channel.

### Tests

```bash
pip install -r requirements-dev.txt
pytest
```

### Git hooks (secret sweep)

Install once after cloning — a `pre-commit` hook then scans staged changes on every commit and **blocks** any that
contain secrets, local secret files, internal group-ib hosts, Panda credential values, or private IPs:

```bash
./scripts/install-hooks.sh
```

Override a deliberate false positive with `git commit --no-verify`.

---

## ⚙️ Configuration & API Keys

Osiris supports environment-based configuration for production usage:

- `OSIRIS_USER_AGENT` — Default User-Agent used for HTTP requests.
- `OSIRIS_REQUEST_TIMEOUT` — Default HTTP timeout in seconds.
- `OSIRIS_RATE_LIMIT` — Max requests per second for link checks.
- `OSIRIS_CHECK_TIMEOUT` — Default timeout for link status checks.
- `OSIRIS_CHECK_RETRIES` — Default retry count for link status checks.
- `OSIRIS_MAX_LINKS` — Max links to return after filtering.
- `OSIRIS_HTTP_PROXY` — Proxy URL for HTTP requests.
- `OSIRIS_HTTPS_PROXY` — Proxy URL for HTTPS requests.
- `OSIRIS_VERIFY_TLS` — Set to `false` to disable TLS verification.
- `OSIRIS_ALLOW_PRIVATE_TARGETS` — SSRF guard. By default, server-side fetches (URL Analyze, Enrich, Abuse Router,
  screenshots) refuse hosts resolving to private/loopback/link-local (incl. cloud-metadata `169.254.169.254`)/
  reserved addresses and non-http(s) schemes. Set to `true` only to deliberately scan internal hosts on a trusted network.
- `ABUSEIPDB_API_KEY` — Enables AbuseIPDB lookups during enrichment.
- `SECURITYTRAILS_API_KEY` — Enables passive DNS history lookups.
- `URLSCAN_API_KEY` — Enables the URLScan live sandbox scanner and higher urlscan search limits.
- `IPINFO_TOKEN` — Improves abuse contact resolution in hosting info.

Example (PowerShell):

```
$env:OSIRIS_USER_AGENT = "Osiris/1.0 (internal-audit)"
$env:ABUSEIPDB_API_KEY = "<your_key>"
```

### Config File (JSON)

Osiris can also load settings from a JSON config file using `--config`.
It searches for these files by default: `osiris.config.json`, `osiris.json`, or `~/.osiris.json`.

Example:

```json
{
  "user_agent": "Osiris/1.0 (corp-audit)",
  "request_timeout": 12,
  "rate_limit_per_sec": 3,
  "http_proxy": "http://127.0.0.1:8080",
  "https_proxy": "http://127.0.0.1:8080",
  "verify_tls": true,
  "json_output": false
}
```

## 📁 File Structure

```
Osiris/
│
├── osiris                           # Root launcher (./osiris)
├── src/                             # Source root
│   └── osiris/                      # Main application package
│       ├── __init__.py              # Package initializer
│       ├── cli.py                   # Command-line argument parser
│       ├── clone_detector.py        # Cloned website detection logic
│       ├── dnstwist.py              # Domain variation and typosquatting detector
│       ├── domain_matcher.py        # Domain matching and validation utilities
│       ├── enrichment.py            # Domain enrichment: WHOIS, DNS, hosting info
│       ├── exporter.py              # Export logic (CSV, JSON, TXT)
│       ├── input_handler.py         # Handles user/platform input
│       ├── intro_text.py            # Introduction text logic
│       ├── link_opener.py           # Opens links in browser
│       ├── logger.py                # Logging of searches and history
│       ├── platform_functions.py    # Platform management functions
│       ├── run_phishing_dorks.py    # Google dorking for phishing detection
│       ├── search_links.py          # Core search and URL generation logic
│       ├── text_clone_search.py     # Clone detection via text comparison
│       ├── threat_scoring.py        # Threat intelligence scoring (if applicable)
│       ├── utils.py                 # Utility functions (printing, banner, etc.)
│       ├── variant_generator.py     # Generate domain variants for typosquatting
│       └── data/                    # Platform templates
│           ├── __init__.py          # Makes the folder a package
│           └── platforms.py         # Platform templates (search URLs by category)
│
├── exports/                         # Folder for storing exported results
├── logs/                            # Folder for logs
├── README.md                        # Project documentation
├── requirements.txt                 # Python dependencies
└── setup.py                         # Setup script for packaging
```

---

## 🛠️ Troubleshooting

- **Permission denied running `osiris`**: Run from the Osiris project root (the folder that contains `osiris`, `src/`, and `README.md`) and ensure it's executable with `chmod +x osiris`.
- **macOS: `./osiris` still permission denied**: Remove quarantine and ensure Unix line endings:
  - `xattr -dr com.apple.quarantine ./osiris`
  - `sed -i '' -e 's/\r$//' ./osiris`
- **macOS: `osiris` command not found after install**: Add the pip bin directory to your PATH:
  - `export PATH="$HOME/Library/Python/3.9/bin:$PATH"`
  - Add the line to `~/.zshrc` (zsh) or `~/.bash_profile` (bash), then restart the shell.
  - Verify resolution:
    - `which osiris`
    - `osiris --help`
- **`pip install` fails**: Try upgrading pip (`pip install --upgrade pip`) or check network/proxy settings.
- **Python version mismatch**: Make sure you run with `python3` if your system defaults to Python 2.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Please open an issue or pull request on GitHub:
https://github.com/ggg6r34t/osiris

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE).

---

## 👨‍💻 Author

Crafted with ❤️ by ggg6r34t
