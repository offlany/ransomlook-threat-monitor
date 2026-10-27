# RansomLook Threat Monitor

Python-based ransomware threat intelligence monitoring and alerting tools for RansomLook and Ransomwatch.

This repository contains the two monitoring scripts found in the original local project. They are kept as separate entry points because they use different public data sources and have different runtime requirements.

## License

The original source code and synthetic fixture included in this repository are licensed under the MIT License. See [LICENSE](LICENSE).

This license applies only to the repository's original code and documentation. RansomLook and Ransomwatch content, `.onion` pages, MISP and Telegram services, external data, service names, and Python dependencies remain subject to their own licenses, terms, and usage restrictions.

## Components

### `ransomlook_monitor.py`

- Fetches the RansomLook recent-posts page (`/recent?window=3`)
- Parses recent rows from the page HTML
- Matches Hungarian-related keywords in victim listing titles
- Deduplicates alerts in a local JSON state file
- Supports one-shot scans, dry runs, state priming, polling, and saved HTML input
- Sends matching alerts through the Telegram Bot API when configured

### `ransomwatch_onion_scanner.py`

- Downloads active locations from the public Ransomwatch `groups.json` feed
- Filters and normalizes `.onion` endpoints
- Requests endpoints through a local Tor SOCKS5 proxy
- Searches returned HTML for Hungarian-related indicators
- Stores scanned endpoints in a local SQLite database
- Can create an optional MISP event and send an optional Telegram alert

## Data sources and outputs

| Component | Source | Local state | External output |
| --- | --- | --- | --- |
| RansomLook monitor | RansomLook recent page | JSON fingerprints | Telegram message or stdout |
| Ransomwatch scanner | Ransomwatch `groups.json` and active `.onion` endpoints | SQLite scan history | MISP event, Telegram message, and logs |

The scripts use public or user-configured services. They do not ship with collected victim data, credentials, tokens, cookies, or local scan state.

## Requirements

- Python 3.11 or newer
- A virtual environment is recommended
- `ransomlook_monitor.py` uses only the Python standard library
- `ransomwatch_onion_scanner.py` requires the packages in `requirements.txt`
- The Ransomwatch scanner also requires a running Tor SOCKS5 proxy at `127.0.0.1:9050`
- MISP and Telegram are optional integrations

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## RansomLook monitor

Preview a synthetic HTML fixture without contacting an external service:

```bash
python ransomlook_monitor.py \
  --html-file examples/ransomlook_recent.html \
  --state-file ./local-state.json \
  --once \
  --dry-run
```

Run one live scan without sending Telegram messages:

```bash
python ransomlook_monitor.py --once --dry-run
```

For real alerts, set the following environment variables before running the script:

```bash
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."
python ransomlook_monitor.py --once
```

The default state file is stored outside the repository under the platform's user state directory. Use `--state-file` to choose another location. Keep any custom state path outside version control.

## Ransomwatch scanner

The scanner is intentionally opt-in because it accesses `.onion` sites through Tor:

```bash
python ransomwatch_onion_scanner.py
```

Optional integrations use these environment variables:

- `MISP_URL`, `MISP_KEY`, `MISP_VERIFYCERT`
- `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`
- `SCAN_STATE_DB`

The scanner skips MISP and Telegram when their credentials are not configured. It does not provide access to private systems or bypass authentication.

### Verification status

The portfolio validation covers Python compilation and the RansomLook monitor's saved-HTML dry-run, including a synthetic `.hu` match and state deduplication. The Ransomwatch/Tor scanner has **not** been run against live `.onion` endpoints in this validation because it requires the declared Python dependencies, a local Tor SOCKS5 service, and an explicitly authorized test environment. Static compilation must not be interpreted as live Tor integration verification.

## Limitations

- RansomLook HTML parsing depends on the current `recent-rows` table structure.
- Keyword matching is heuristic and may produce false positives or miss relevant listings.
- Public ransomware listings are unverified claims and must not be treated as confirmed incidents.
- Ransomwatch data, `.onion` availability, Tor connectivity, and remote HTML structure can change without notice.
- The scanner records a target as scanned even when the request fails during that run; review the logs before relying on later runs.
- This repository does not include a historical dataset or a production alerting service.

## Responsible use

Use these scripts only for defensive research, authorized monitoring, and environments where you have permission to make the requests. Respect applicable law, service terms, privacy requirements, and organizational policies. Do not use them to access, collect, or redistribute private information.

## Security review checklist

Before publishing a clone of this repository, verify that:

- no `.env` file, API key, token, cookie, or state database is tracked;
- no private HTML capture or victim dataset has been added;
- Telegram and MISP credentials are supplied only through the environment;
- custom state files remain outside version control.
