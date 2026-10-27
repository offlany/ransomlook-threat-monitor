#!/usr/bin/env python3

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional
from urllib import error, parse, request


RECENT_URL = "https://www.ransomlook.io/recent?window=3"
DEFAULT_INTERVAL_SECONDS = 30 * 60
REQUEST_TIMEOUT_SECONDS = 30
MAX_SEEN_ITEMS = 5000
SEEN_RETENTION_SECONDS = 14 * 24 * 60 * 60
DEFAULT_STATE_DIR = Path(
    os.getenv("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))
) / "ransomlook_hu_monitor"
STATE_FILE = Path(
    os.getenv("RANSOMLOOK_STATE_FILE", str(DEFAULT_STATE_DIR / "state.json"))
)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

HU_KEYWORDS = [
    "hungary", "magyar", "budapest", " kft", " zrt", " nyrt", ".hu ",
    "miniszterium", "allamkincstar", "nav.gov", "mnb.hu", "kozbeszerzes",
    "onkormanyzat", "rendorseg", "katasztrofavedelem", "neak", "mvm", "mav zrt",
    "posta", "volanbusz", "bkk", "kozut", "vizmuvek",
    "otp bank", "mbh bank", "richter gedeon", "4ig", "magyar telekom",
    "unicredit hungary", "citibank hungary", "magnet bank", "fundamenta",
    "allianz hungaria", "generali", "groupama", "alfa biztosito", "vig group",
    "union biztosito", "k&h bank", "raiffeisen", "cib bank", "erste bank",
    "semmelweis", "honvedkorhaz", "janos korhaz", "uzsoki", "gottsegen",
    "koranyi", "medicover", "budai egeszsegkozpont", "doktor24", "swiss clinic",
    "synlab", "affidea", "dunamedical", "maganrendelo", "klinika", "korhaz",
    "mol group", "audi hungaria", "mercedes-benz", "bosch", "suzuki hungary",
    "borsodchem", "wizz air", "waberer", "hell energy", "pick szeged",
    "zwack", "yettel", "telenor", "spar magyarorszag", "tesco-global",
    "opus global", "alteo", "masterplast", "videoton",
]

ERROR_DEFINITIONS = {
    "FETCH_TIMEOUT": (12, "RansomLook request timed out."),
    "FETCH_DNS_FAILURE": (13, "DNS lookup failed for RansomLook."),
    "FETCH_TLS_ERROR": (14, "TLS/SSL error while connecting to RansomLook."),
    "FETCH_CONNECTION_REFUSED": (15, "RansomLook connection was refused."),
    "FETCH_CONNECTION_RESET": (16, "RansomLook connection was reset."),
    "FETCH_HTTP_403": (17, "RansomLook returned HTTP 403. The request may be blocked."),
    "FETCH_HTTP_429": (18, "RansomLook returned HTTP 429. Too many requests."),
    "FETCH_HTTP_5XX": (19, "RansomLook returned a server-side 5xx error."),
    "FETCH_HTTP_ERROR": (20, "RansomLook returned an unexpected HTTP error."),
    "FETCH_NETWORK_ERROR": (21, "Generic network error while reaching RansomLook."),
    "PARSE_NO_POSTS": (22, "The page was fetched but no recent posts were parsed."),
    "HTML_FILE_READ_ERROR": (23, "Failed to read the local HTML file."),
    "TELEGRAM_CONFIG_MISSING": (30, "Telegram bot token or chat ID is missing."),
    "TELEGRAM_HTTP_400": (31, "Telegram returned HTTP 400. Chat ID or payload may be invalid."),
    "TELEGRAM_HTTP_401": (32, "Telegram returned HTTP 401. Bot token may be invalid."),
    "TELEGRAM_HTTP_403": (33, "Telegram returned HTTP 403. Bot may be blocked or forbidden."),
    "TELEGRAM_HTTP_429": (34, "Telegram returned HTTP 429. Rate limited."),
    "TELEGRAM_API_ERROR": (35, "Telegram API returned an application-level error."),
    "TELEGRAM_NETWORK_ERROR": (36, "Network error while reaching Telegram."),
    "STATE_WRITE_ERROR": (40, "Failed to write the state file."),
    "UNKNOWN_ERROR": (99, "Unexpected unclassified error."),
}


@dataclass
class RecentPost:
    published_at: str
    title: str
    group_name: str
    group_slug: str

    @property
    def fingerprint(self) -> str:
        return f"{self.published_at}|{self.group_slug}|{self.title}"


class RansomLookRecentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.posts: List[RecentPost] = []
        self._in_recent_rows = False
        self._in_row = False
        self._current_cell = 0
        self._current_post: Optional[Dict[str, str]] = None
        self._capture_field: Optional[str] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_dict = dict(attrs)

        if tag == "tbody" and attrs_dict.get("id") == "recent-rows":
            self._in_recent_rows = True
            return

        if not self._in_recent_rows:
            return

        if tag == "tr":
            self._in_row = True
            self._current_cell = 0
            self._current_post = {
                "published_at": "",
                "title": "",
                "group_name": "",
                "group_slug": unescape(attrs_dict.get("data-group", "")).strip(),
            }
            return

        if not self._in_row or self._current_post is None:
            return

        if tag == "td":
            self._current_cell += 1
            td_class = attrs_dict.get("class", "")
            if "recent-title" in td_class:
                self._capture_field = "title"
            return

        if tag == "time":
            published_at = attrs_dict.get("datetime", "").strip()
            if published_at:
                self._current_post["published_at"] = published_at
            return

        if (
            tag == "span"
            and self._current_cell == 3
            and "data-group-dot" not in attrs_dict
        ):
            self._capture_field = "group_name"

    def handle_endtag(self, tag: str) -> None:
        if tag == "tbody":
            self._in_recent_rows = False
            return

        if not self._in_row:
            return

        if tag in {"td", "span"}:
            self._capture_field = None
            return

        if tag == "tr" and self._current_post is not None:
            title = clean_text(self._current_post.get("title", ""))
            group_name = clean_text(self._current_post.get("group_name", ""))
            published_at = clean_text(self._current_post.get("published_at", ""))
            group_slug = clean_text(self._current_post.get("group_slug", ""))

            if title and published_at and group_slug:
                self.posts.append(
                    RecentPost(
                        published_at=published_at,
                        title=title,
                        group_name=group_name or group_slug,
                        group_slug=group_slug,
                    )
                )

            self._in_row = False
            self._current_cell = 0
            self._current_post = None
            self._capture_field = None

    def handle_data(self, data: str) -> None:
        if self._current_post is None or not self._capture_field:
            return
        self._current_post[self._capture_field] += data


class MonitorError(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.exit_code = ERROR_DEFINITIONS.get(code, ERROR_DEFINITIONS["UNKNOWN_ERROR"])[0]
        super().__init__(message)

    def __str__(self) -> str:
        return f"[{self.code}] {self.args[0]} (exit {self.exit_code})"


def clean_text(value: str) -> str:
    return " ".join(unescape(value).split())


def strip_accents(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def fold_text(value: str) -> str:
    return clean_text(strip_accents(value).lower())


def simplify_text(value: str) -> str:
    folded = fold_text(value)
    folded = re.sub(r"[^a-z0-9]+", " ", folded)
    return clean_text(folded)


def find_matching_keywords(text: str) -> List[str]:
    folded_text = fold_text(text)
    simplified_text = f" {simplify_text(text)} "
    matches: List[str] = []

    for keyword in HU_KEYWORDS:
        raw_keyword = keyword
        stripped_keyword = keyword.strip()
        folded_keyword = fold_text(stripped_keyword)
        simplified_keyword = simplify_text(stripped_keyword)

        if not stripped_keyword:
            continue

        is_match = False

        if stripped_keyword == ".hu":
            is_match = ".hu" in folded_text
        elif raw_keyword != stripped_keyword:
            is_match = f" {simplified_keyword} " in simplified_text
        else:
            if folded_keyword in folded_text:
                is_match = True
            elif simplified_keyword:
                is_match = f" {simplified_keyword} " in simplified_text

        if is_match:
            matches.append(stripped_keyword)

    return matches


def http_error_snippet(exc: error.HTTPError) -> str:
    try:
        snippet = exc.read(200).decode("utf-8", errors="replace").strip()
    except Exception:
        snippet = ""
    if not snippet:
        return ""
    snippet = " ".join(snippet.split())
    return f" Response snippet: {snippet[:160]}"


def raise_fetch_network_error(reason: object) -> None:
    if isinstance(reason, socket.timeout):
        raise MonitorError("FETCH_TIMEOUT", "RansomLook request timed out.")
    if isinstance(reason, socket.gaierror):
        raise MonitorError("FETCH_DNS_FAILURE", f"DNS lookup failed for RansomLook: {reason}")
    if isinstance(reason, ssl.SSLError):
        raise MonitorError("FETCH_TLS_ERROR", f"TLS/SSL error while connecting to RansomLook: {reason}")
    if isinstance(reason, ConnectionRefusedError):
        raise MonitorError("FETCH_CONNECTION_REFUSED", "RansomLook refused the connection.")
    if isinstance(reason, ConnectionResetError):
        raise MonitorError("FETCH_CONNECTION_RESET", "Connection to RansomLook was reset.")
    if isinstance(reason, OSError):
        if getattr(reason, "errno", None) == 104:
            raise MonitorError("FETCH_CONNECTION_RESET", "Connection to RansomLook was reset.")
        if getattr(reason, "errno", None) == 111:
            raise MonitorError("FETCH_CONNECTION_REFUSED", "RansomLook refused the connection.")
        raise MonitorError("FETCH_NETWORK_ERROR", f"Network error while reaching RansomLook: {reason}")
    raise MonitorError("FETCH_NETWORK_ERROR", f"Network error while reaching RansomLook: {reason}")


def raise_telegram_network_error(reason: object) -> None:
    if isinstance(reason, socket.timeout):
        raise MonitorError("TELEGRAM_NETWORK_ERROR", "Telegram request timed out.")
    if isinstance(reason, socket.gaierror):
        raise MonitorError("TELEGRAM_NETWORK_ERROR", f"DNS lookup failed for Telegram: {reason}")
    if isinstance(reason, ssl.SSLError):
        raise MonitorError("TELEGRAM_NETWORK_ERROR", f"TLS/SSL error while connecting to Telegram: {reason}")
    if isinstance(reason, OSError):
        raise MonitorError("TELEGRAM_NETWORK_ERROR", f"Network error while reaching Telegram: {reason}")
    raise MonitorError("TELEGRAM_NETWORK_ERROR", f"Network error while reaching Telegram: {reason}")


def print_error_codes() -> None:
    print("Possible error codes:")
    for code, (exit_code, description) in ERROR_DEFINITIONS.items():
        print(f"  {code:<24} exit {exit_code:<3} {description}")


def fetch_recent_html() -> str:
    http_request = request.Request(
        RECENT_URL,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0 Safari/537.36"
            )
        },
    )
    try:
        with request.urlopen(http_request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            content_type = response.headers.get_content_charset() or "utf-8"
            return response.read().decode(content_type, errors="replace")
    except error.HTTPError as exc:
        if exc.code == 403:
            raise MonitorError(
                "FETCH_HTTP_403",
                "RansomLook returned HTTP 403 Forbidden. The site may be blocking the request."
                + http_error_snippet(exc),
            ) from exc
        if exc.code == 429:
            raise MonitorError(
                "FETCH_HTTP_429",
                "RansomLook returned HTTP 429 Too Many Requests. Slow down the polling."
                + http_error_snippet(exc),
            ) from exc
        if 500 <= exc.code <= 599:
            raise MonitorError(
                "FETCH_HTTP_5XX",
                f"RansomLook returned HTTP {exc.code}. Server-side problem."
                + http_error_snippet(exc),
            ) from exc
        raise MonitorError(
            "FETCH_HTTP_ERROR",
            f"RansomLook returned HTTP {exc.code}.{http_error_snippet(exc)}",
        ) from exc
    except error.URLError as exc:
        raise_fetch_network_error(exc.reason)
    except socket.timeout as exc:
        raise MonitorError("FETCH_TIMEOUT", f"RansomLook request timed out: {exc}") from exc
    except ssl.SSLError as exc:
        raise MonitorError("FETCH_TLS_ERROR", f"TLS/SSL error while connecting to RansomLook: {exc}") from exc
    except ConnectionResetError as exc:
        raise MonitorError("FETCH_CONNECTION_RESET", f"Connection to RansomLook was reset: {exc}") from exc


def parse_recent_posts(html: str) -> List[RecentPost]:
    parser = RansomLookRecentParser()
    parser.feed(html)
    return parser.posts


def load_state(state_path: Path) -> Dict[str, float]:
    if not state_path.exists():
        return {}

    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

    seen = payload.get("seen", {})
    if not isinstance(seen, dict):
        return {}

    normalized_seen: Dict[str, float] = {}
    for key, value in seen.items():
        if isinstance(key, str) and isinstance(value, (int, float)):
            normalized_seen[key] = float(value)
    return normalized_seen


def save_state(state_path: Path, seen: Dict[str, float]) -> None:
    pruned_seen = prune_seen(seen)
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(
            json.dumps({"seen": pruned_seen}, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        raise MonitorError("STATE_WRITE_ERROR", f"Could not write state file {state_path}: {exc}") from exc


def prune_seen(seen: Dict[str, float]) -> Dict[str, float]:
    now = time.time()
    fresh_items = {
        fingerprint: timestamp
        for fingerprint, timestamp in seen.items()
        if now - timestamp <= SEEN_RETENTION_SECONDS
    }
    sorted_items = sorted(
        fresh_items.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:MAX_SEEN_ITEMS]
    return dict(sorted_items)


def extract_attacked_site(title: str) -> str:
    domain_match = re.search(
        r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
        fold_text(title),
    )
    if domain_match:
        return domain_match.group(0)
    return clean_text(title)


def build_telegram_message(post: RecentPost, matched_keywords: List[str]) -> str:
    attacked_site = extract_attacked_site(post.title)
    group_url = f"https://www.ransomlook.io/group/{parse.quote(post.group_slug, safe='')}"

    lines = [
        "Hungarian keyword hit on RansomLook",
        f"Attacked site: {attacked_site}",
        f"Victim listing: {post.title}",
        f"Ransom group: {post.group_name}",
        f"Published on RansomLook: {post.published_at}",
        f"Matched keywords: {', '.join(matched_keywords)}",
        f"Recent page: {RECENT_URL}",
        f"Group page: {group_url}",
    ]
    return "\n".join(lines)


def send_telegram_message(message: str) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise MonitorError(
            "TELEGRAM_CONFIG_MISSING",
            "Telegram is not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID.",
        )

    payload = parse.urlencode(
        {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")

    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    http_request = request.Request(
        telegram_url,
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8", errors="replace")
    except error.HTTPError as exc:
        if exc.code == 400:
            raise MonitorError(
                "TELEGRAM_HTTP_400",
                "Telegram returned HTTP 400. The chat ID or request payload may be invalid."
                + http_error_snippet(exc),
            ) from exc
        if exc.code == 401:
            raise MonitorError(
                "TELEGRAM_HTTP_401",
                "Telegram returned HTTP 401. The bot token may be invalid."
                + http_error_snippet(exc),
            ) from exc
        if exc.code == 403:
            raise MonitorError(
                "TELEGRAM_HTTP_403",
                "Telegram returned HTTP 403. The bot may be blocked from that chat."
                + http_error_snippet(exc),
            ) from exc
        if exc.code == 429:
            raise MonitorError(
                "TELEGRAM_HTTP_429",
                "Telegram returned HTTP 429 Too Many Requests. Rate limit hit."
                + http_error_snippet(exc),
            ) from exc
        raise MonitorError(
            "TELEGRAM_API_ERROR",
            f"Telegram returned HTTP {exc.code}.{http_error_snippet(exc)}",
        ) from exc
    except error.URLError as exc:
        raise_telegram_network_error(exc.reason)
    except socket.timeout as exc:
        raise MonitorError("TELEGRAM_NETWORK_ERROR", f"Telegram request timed out: {exc}") from exc
    except ssl.SSLError as exc:
        raise MonitorError("TELEGRAM_NETWORK_ERROR", f"TLS/SSL error while connecting to Telegram: {exc}") from exc

    try:
        parsed_body = json.loads(body)
    except json.JSONDecodeError as exc:
        raise MonitorError("TELEGRAM_API_ERROR", f"Telegram returned invalid JSON: {body[:160]}") from exc

    if not parsed_body.get("ok"):
        api_error_code = parsed_body.get("error_code")
        description = parsed_body.get("description", "Unknown Telegram API error.")
        if api_error_code == 400:
            raise MonitorError("TELEGRAM_HTTP_400", f"Telegram rejected the request: {description}")
        if api_error_code == 401:
            raise MonitorError("TELEGRAM_HTTP_401", f"Telegram rejected the bot token: {description}")
        if api_error_code == 403:
            raise MonitorError("TELEGRAM_HTTP_403", f"Telegram forbade the request: {description}")
        if api_error_code == 429:
            raise MonitorError("TELEGRAM_HTTP_429", f"Telegram rate limited the request: {description}")
        raise MonitorError("TELEGRAM_API_ERROR", f"Telegram API error: {description}")


def load_html_from_args(args: argparse.Namespace) -> str:
    if args.html_file:
        try:
            return Path(args.html_file).read_text(encoding="utf-8")
        except OSError as exc:
            raise MonitorError("HTML_FILE_READ_ERROR", f"Could not read HTML file {args.html_file}: {exc}") from exc
    return fetch_recent_html()


def run_cycle(
    seen: Dict[str, float],
    args: argparse.Namespace,
) -> int:
    html = load_html_from_args(args)
    posts = parse_recent_posts(html)

    if not posts:
        raise MonitorError(
            "PARSE_NO_POSTS",
            "The RansomLook page was fetched, but no recent posts were parsed. The HTML structure may have changed.",
        )

    sent_count = 0
    now = time.time()

    for post in posts:
        matched_keywords = find_matching_keywords(post.title)
        if not matched_keywords:
            continue

        if post.fingerprint in seen:
            continue

        message = build_telegram_message(post, matched_keywords)

        if args.prime_state:
            print(f"[PRIME] {post.title} | {post.group_name} | {', '.join(matched_keywords)}")
        elif args.dry_run:
            print("")
            print(message)
            print("-" * 80)
        else:
            send_telegram_message(message)
            print(f"[ALERT] {post.title} | {post.group_name} | {', '.join(matched_keywords)}")

        seen[post.fingerprint] = now
        sent_count += 1

    return sent_count


def log(message: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{timestamp}] {message}", flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor RansomLook recent posts for Hungarian keywords and send Telegram alerts."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print alerts instead of sending them to Telegram.",
    )
    parser.add_argument(
        "--prime-state",
        action="store_true",
        help="Mark currently matched posts as seen without sending Telegram messages.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"Polling interval in seconds. Default: {DEFAULT_INTERVAL_SECONDS}.",
    )
    parser.add_argument(
        "--state-file",
        default=str(STATE_FILE),
        help=f"Path to the dedupe state file. Default: {STATE_FILE}.",
    )
    parser.add_argument(
        "--html-file",
        help="Parse a saved HTML file instead of requesting the live RansomLook page.",
    )
    parser.add_argument(
        "--show-error-codes",
        action="store_true",
        help="Print all built-in error codes and exit codes, then exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.show_error_codes:
        print_error_codes()
        return 0

    state_path = Path(args.state_file)
    seen = load_state(state_path)

    while True:
        try:
            sent_count = run_cycle(seen, args)
            save_state(state_path, seen)
            if args.prime_state:
                action = "primed"
            elif args.dry_run:
                action = "previewed"
            else:
                action = "sent"
            log(f"Cycle complete: {sent_count} matching posts {action}.")
        except KeyboardInterrupt:
            log("Stopped by user.")
            return 0
        except MonitorError as exc:
            log(f"Cycle failed: {exc}")
            if args.once:
                return exc.exit_code
        except Exception as exc:
            unknown_error = MonitorError("UNKNOWN_ERROR", f"Unexpected error: {exc}")
            log(f"Cycle failed: {unknown_error}")
            if args.once:
                return unknown_error.exit_code

        if args.once:
            return 0

        time.sleep(max(args.interval_seconds, 60))


if __name__ == "__main__":
    sys.exit(main())
