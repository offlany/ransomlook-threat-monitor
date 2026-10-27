#!/usr/bin/env python3
"""
HU-focused ransomware TI scraper (Ransomwatch + Tor + MISP + Telegram).

What it does:
1) Downloads groups.json from Ransomwatch
2) Extracts active .onion endpoints
3) Scrapes each onion via socks5h://127.0.0.1:9050 (Anonsurf/Tor)
4) Detects Hungarian indicators in HTML
5) Creates a MISP event (PyMISP) on matches
6) Sends Telegram alert only when a Hungarian hit is found
7) Stores scanned onion URLs in SQLite to avoid re-processing
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from html import unescape
from typing import Any, Iterable, Optional
from urllib.parse import urlparse

import requests

try:
    from pymisp import MISPEvent, PyMISP
except ImportError:
    MISPEvent = None  # type: ignore[assignment]
    PyMISP = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GROUPS_JSON_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"
TOR_PROXY = "socks5h://127.0.0.1:9050"
ONION_TIMEOUT_SECONDS = 20
DB_PATH = os.getenv("SCAN_STATE_DB", "hu_ransomwatch_scan_state.sqlite3")

# Configure MISP and Telegram through environment variables.
MISP_URL = os.getenv("MISP_URL", "")
MISP_KEY = os.getenv("MISP_KEY", "")
MISP_VERIFYCERT = os.getenv("MISP_VERIFYCERT", "true").lower() == "true"

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

HU_KEYWORDS = [
    ".hu",
    "hungary",
    "magyarorszag",
    "magyarország",
    "budapest",
    "debrecen",
    "szeged",
    "gyor",
    "győr",
    "miskolc",
    "pecs",
    "pécs",
    "kft",
    "zrt",
    "nyrt",
    "gov.hu",
    "fidesz",
    "tisza",
    "hungarian",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scanned_onions (
            onion_url TEXT PRIMARY KEY,
            group_name TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def already_scanned(conn: sqlite3.Connection, onion_url: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM scanned_onions WHERE onion_url = ? LIMIT 1",
        (onion_url,),
    ).fetchone()
    return row is not None


def mark_scanned(conn: sqlite3.Connection, onion_url: str, group_name: str) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO scanned_onions (onion_url, group_name, scanned_at)
        VALUES (?, ?, ?)
        """,
        (onion_url, group_name, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def misp_is_configured() -> bool:
    return bool(MISP_URL and MISP_KEY)


def telegram_is_configured() -> bool:
    return bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)


def normalize_onion_url(raw_value: str) -> Optional[str]:
    if not raw_value:
        return None

    raw = raw_value.strip()
    if not raw:
        return None

    if not raw.startswith(("http://", "https://")):
        raw = f"http://{raw}"

    parsed = urlparse(raw)
    host = parsed.hostname
    if not host or not host.endswith(".onion"):
        return None

    # Keep path/query if present because some leak sites use path endpoints.
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{host}{path}{query}"


def extract_active_onions(groups_data: list[dict[str, Any]]) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    for group in groups_data:
        group_name = str(group.get("name", "unknown-group"))
        locations = group.get("locations", [])
        if not isinstance(locations, list):
            continue

        for loc in locations:
            if not isinstance(loc, dict):
                continue

            # In current Ransomwatch schema, "enabled" indicates active endpoints.
            enabled = loc.get("enabled")
            available = loc.get("available")
            is_active = bool(enabled) if enabled is not None else bool(available)
            if not is_active:
                continue

            onion_url = normalize_onion_url(str(loc.get("slug") or loc.get("fqdn") or ""))
            if not onion_url:
                continue

            if onion_url in seen:
                continue

            seen.add(onion_url)
            targets.append({"group_name": group_name, "onion_url": onion_url})

    return targets


def fetch_groups_json() -> list[dict[str, Any]]:
    logging.info("Downloading groups.json from Ransomwatch...")
    response = requests.get(GROUPS_JSON_URL, timeout=ONION_TIMEOUT_SECONDS)
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, list):
        raise ValueError("Unexpected groups.json format: expected a list")
    return data


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = unescape(match.group(1))
    return " ".join(title.split()).strip()


def find_hungarian_matches(html: str) -> list[str]:
    lowered = html.casefold()
    return [kw for kw in HU_KEYWORDS if kw.casefold() in lowered]


def scrape_onion(session: requests.Session, onion_url: str) -> str:
    response = session.get(onion_url, timeout=ONION_TIMEOUT_SECONDS, allow_redirects=True)
    response.raise_for_status()
    return response.text


def create_misp_event(
    pymisp_client: PyMISP,
    group_name: str,
    onion_url: str,
    victim_display: str,
    matched_keywords: list[str],
) -> Optional[str]:
    if MISPEvent is None:
        logging.error("PyMISP is not installed; cannot create MISP event.")
        return None

    event = MISPEvent()
    event.info = f"Potential Hungarian Ransomware Victim: {victim_display}"
    event.distribution = 0
    event.threat_level_id = 2  # Medium
    event.analysis = 0  # Initial

    created = pymisp_client.add_event(event, pythonify=True)
    if not isinstance(created, MISPEvent):
        logging.error("MISP event creation failed for %s", onion_url)
        return None

    event_id = str(created.id)

    # Required attributes: onion link + ransomware group name.
    pymisp_client.add_attribute(
        event_id,
        {
            "type": "url",
            "value": onion_url,
            "category": "Network activity",
            "comment": "Onion leak-site URL",
            "to_ids": False,
        },
    )
    pymisp_client.add_attribute(
        event_id,
        {
            "type": "text",
            "value": group_name,
            "category": "External analysis",
            "comment": "Ransomware group name",
            "to_ids": False,
        },
    )
    pymisp_client.add_attribute(
        event_id,
        {
            "type": "text",
            "value": ", ".join(sorted(set(matched_keywords))),
            "category": "External analysis",
            "comment": "Matched HU keywords",
            "to_ids": False,
        },
    )

    logging.info("MISP event created: ID=%s for %s", event_id, onion_url)
    return event_id


def send_telegram_alert(group_name: str, onion_url: str, misp_event_id: str) -> None:
    message = (
        "🚨 HU Ransomware Alert\n\n"
        f"Group: {group_name}\n\n"
        f"Onion: {onion_url}\n\n"
        f"MISP Event ID: {misp_event_id}"
    )

    api_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    response = requests.post(api_url, data=payload, timeout=ONION_TIMEOUT_SECONDS)
    response.raise_for_status()
    logging.info("Telegram alert sent for %s", onion_url)


def build_tor_session() -> requests.Session:
    session = requests.Session()
    session.proxies = {"http": TOR_PROXY, "https": TOR_PROXY}
    return session


def scan_targets(
    conn: sqlite3.Connection,
    targets: Iterable[dict[str, str]],
    misp_client: Optional[PyMISP],
) -> int:
    hits = 0
    tor_session = build_tor_session()

    for target in targets:
        group_name = target["group_name"]
        onion_url = target["onion_url"]

        if already_scanned(conn, onion_url):
            logging.info("[SKIP] Already scanned: %s", onion_url)
            continue

        logging.info("[SCAN] Group=%s URL=%s", group_name, onion_url)

        try:
            html = scrape_onion(tor_session, onion_url)
            matches = find_hungarian_matches(html)

            if matches:
                hits += 1
                victim_display = extract_title(html) or onion_url
                logging.warning(
                    "[HIT] HU indicators found | Group=%s URL=%s Keywords=%s",
                    group_name,
                    onion_url,
                    ", ".join(matches),
                )

                misp_event_id = "N/A"
                if misp_client is not None:
                    event_id = create_misp_event(
                        pymisp_client=misp_client,
                        group_name=group_name,
                        onion_url=onion_url,
                        victim_display=victim_display,
                        matched_keywords=matches,
                    )
                    if event_id:
                        misp_event_id = event_id

                if telegram_is_configured():
                    try:
                        send_telegram_alert(group_name, onion_url, misp_event_id)
                    except Exception as exc:
                        logging.error("Telegram send failed for %s: %s", onion_url, exc)
                else:
                    logging.info("Telegram not configured; skipping alert send.")
            else:
                logging.info("[OK] No HU indicators: %s", onion_url)

        except Exception as exc:
            # Keep running even when an onion is offline/unreachable.
            logging.error("[ERROR] Failed %s (%s): %s", onion_url, group_name, exc)
        finally:
            mark_scanned(conn, onion_url, group_name)

    return hits


def main() -> int:
    setup_logging()
    logging.info("Starting HU ransomware monitor run...")

    try:
        conn = init_db(DB_PATH)
    except Exception as exc:
        logging.error("Cannot initialize SQLite DB (%s): %s", DB_PATH, exc)
        return 1

    misp_client: Optional[PyMISP] = None
    if PyMISP is None or MISPEvent is None:
        logging.warning("PyMISP not installed. Install with: pip install pymisp")
    elif misp_is_configured():
        try:
            # If your MISP is behind a self-signed certificate, set MISP_VERIFYCERT=false.
            misp_client = PyMISP(
                MISP_URL,
                MISP_KEY,
                ssl=MISP_VERIFYCERT,
                timeout=ONION_TIMEOUT_SECONDS,
            )
            logging.info("MISP client initialized.")
        except Exception as exc:
            logging.error("MISP initialization failed: %s", exc)
            misp_client = None
    else:
        logging.info("MISP not configured yet (MISP_URL / MISP_KEY placeholder still present).")

    try:
        groups_data = fetch_groups_json()
        targets = extract_active_onions(groups_data)
        logging.info("Active onion targets found: %d", len(targets))
    except Exception as exc:
        logging.error("Failed to prepare targets: %s", exc)
        return 1

    hits = scan_targets(conn=conn, targets=targets, misp_client=misp_client)
    logging.info("Run complete. HU hits detected: %d", hits)
    return 0


if __name__ == "__main__":
    sys.exit(main())
