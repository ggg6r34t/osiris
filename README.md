# 🔍 Osiris

Osiris is a powerful and modular OSINT command-line tool for investigating trademark violations, people, scams, phishing,
and more across categorized platforms. Export results, open links, log activity, and perform intelligent
searches with support for fuzzy matching and link status checking.

---

## 🚀 Features

- Modular and clean architecture (`cli`, `search`, `export`, `utils`, `config`, `setup`)
- Search types: `trademark violations`, `people`, `scams`, `phishing`, or `webpages`
- Categorized platforms: Social, Mobile Apps, Web, Instant Messengers, Advertising, Marketplaces
- Supports fuzzy matching, platform/category filtering, link previews
- Batch mode from targets file
- Threat scoring for result triage
- Open links in browser
- Export results to CSV, JSON, or TXT
- Check link HTTP status before exporting
- Logs search history and activity
- Colorized terminal output for clarity

---

## 🧩 Use Cases

- Identify potential trademark violations and detect lookalike or similar domains across various platforms.
- Discover phishing sites, malicious domains, and scams by searching web services and detection engines.
- Investigate scam operations across e-commerce platforms, social media, and other services.
- Gather information for research, investigations, or audits to track entities involved in illicit activities.
- Add your own search platforms via JSON templates for tailored OSINT research.

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
- `ABUSEIPDB_API_KEY` — Enables AbuseIPDB lookups during enrichment.
- `SECURITYTRAILS_API_KEY` — Enables passive DNS history lookups.
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
