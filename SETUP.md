# Osiris — Setup & Operator Guide

Everything you need to **provide** (API keys, config) and **do manually** to run Osiris and use all its
features. Everything here is optional and opt-in — Osiris runs with zero keys; keys just unlock extra signals.

---

## Status snapshot

- Personal repo: `github.com/ggg6r34t/osiris` (branch `main`). Commits are made **locally** — you run the push.
- Features: search-link generation, domain intel (WHOIS/DNS/SSL enrich, lookalikes, clone detection, phishing
  dorks, IP-pivot/reverse-IP, VT/urlscan reputation), screenshots, cases/history, monitoring + diff,
  Telegram/webhook alerting, and the **VIP Investigation** dashboard.
- Tests pass, TypeScript + lint clean, production build works.

---

## ⚠️ Keep `.env` in sync

`.env` (gitignored) may predate newer features. Whenever you pull new work, compare it against `.env.example`
and copy over any missing keys. Missing keys don't break anything — the related signal just degrades gracefully.

```bash
diff <(grep -o '^[A-Z_]*' .env.example | sort -u) <(grep -o '^[A-Z_]*' .env | sort -u)
```

---

## What you must PROVIDE (API keys — all optional)

Put these in `.env` (gitignored). Copy the template first if you haven't: `cp .env.example .env`.

| Key | Unlocks | Get it from | Cost |
|---|---|---|---|
| `OSIRIS_PANDA_URL` / `OSIRIS_PANDA_LOGIN` / `OSIRIS_PANDA_KEY` | Brand Abuse (regex) tool | Internal Panda API (VPN) | — |
| `BRAVE_SEARCH_API_KEY` | VIP **mention volume** (name search signals) | brave.com/search/api | Free tier |
| `HAVEIBEENPWNED_API_KEY` | VIP **breach exposure** (service discoverability) | haveibeenpwned.com/API/Key | Paid |
| `VIRUSTOTAL_API_KEY` | Enrich reputation + risk score | virustotal.com (free API) | Free |
| `ABUSEIPDB_API_KEY` | IP abuse score in Enrich | abuseipdb.com | Free tier |
| `SECURITYTRAILS_API_KEY` | Passive DNS in Enrich | securitytrails.com | Free tier |
| `IPINFO_TOKEN` | Geo/ASN detail in Enrich | ipinfo.io | Free tier |
| `OSIRIS_TELEGRAM_BOT_TOKEN` + `OSIRIS_TELEGRAM_CHAT_ID` | Monitor alerts → Telegram | @BotFather + @userinfobot | Free |
| `OSIRIS_ALERT_WEBHOOK_URL` | Monitor alerts → internal endpoint | Your own endpoint | — |

**Works with zero keys:** all search-link generation, WHOIS/DNS/SSL enrich, lookalikes (domain-match/dnstwist),
clone detection, phishing dorks, IP-pivot/reverse-IP, urlscan, screenshots, cases, history, monitoring diff, and
the **VIP scorecard** (mention-volume + breach signals just show as "not configured").

---

## What you must DO manually

### One-time setup
1. **Sync `.env`** with `.env.example`, then fill the keys you want (see table above).
2. **Telegram alerts** (optional): create a bot with **@BotFather** → get the token; DM **@userinfobot** → get
   your chat id. Put both in `.env`, then click **Send test** on the Monitor tab to verify.
3. **Geo tiers** (optional): `cp geo_risk.example.json geo_risk.json` and edit to override built-in country risk.
   Or point `OSIRIS_GEO_RISK_FILE` at any file. Forms accepted:
   `{"high": [...], "medium": [...], "low": [...]}` or a flat `{"country": "high"}` map.
4. **Screenshots** (optional): `pip install -r requirements-screenshots.txt && playwright install chromium`.
5. **Push to GitHub** — commits are local; you run the push:
   ```bash
   git push origin main
   ```

### Per VIP investigation (investigator-driven by design)
1. Provide inputs: **name + aliases** (the anchor), emails, any known handles, company, country.
2. **Discover handles:** use the *Presence & handle discovery* pivots → find real profiles → feed those handles
   back into the form and re-run (that's how presence + discoverability get scored).
3. **Impersonations:** work the *Impersonation hunt* pivots, count the confirmed fakes, enter the number, re-run.
4. **Geo:** treat the tier as a starting point — apply judgement and the location pivots.
5. **Family / business:** review those pivots and file findings to a case.
6. Export the **PDF** / **JSON** report, or **Add to case**.

> Note: handle resolution means "a handle exists on that platform," not identity. Mention volume is a Brave
> heuristic (no raw result count). The geo tier is a coarse, overridable default. Verify via the pivots.

### Operations
- **Run it (production):**
  ```bash
  ./run.sh            # builds frontend if needed, starts backend + frontend
  ./run.sh --build    # force a fresh production build first
  ```
- **Run it (dev, hot-reload):**
  ```bash
  # backend (from repo root, venv active, .env loaded)
  uvicorn osiris.api:app --port 8000 --reload
  # frontend
  cd web && npm run dev
  ```
- **Stop running servers:** `lsof -ti:3000,8000 | xargs kill`
- **Monitoring:** add watch targets on the Monitor tab and click **Run monitor**, or schedule the CLI for cron:
  ```bash
  osiris --monitor            # runs all watchlist targets, fires alerts on new lookalikes
  osiris --check-takedowns    # re-checks open takedowns, flags down/relisted, fires alerts on change
  ```
- **Takedowns:** run the **Abuse Router** on a domain → **Track takedown** → manage it in **Cases → Takedowns**
  (advance status, re-check liveness, view the timeline). Alerts on down/relisted use the same channels as monitoring.

---

## Local files (gitignored — never committed)

| File | What it is |
|---|---|
| `.env` | Secrets & keys (Panda creds, API keys, alert tokens) |
| `osiris.db` | Local SQLite: history, cases, watchlist, monitor snapshots |
| `geo_risk.json` | Your VIP geo-risk tier overrides |
| `custom_platforms.json` | Your custom search platforms |
| `exports/`, `logs/` | Exported results and run logs |
