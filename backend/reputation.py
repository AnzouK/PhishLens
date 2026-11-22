"""
URL reputation: several threat-intelligence sources are checked in
turn, so no single one decides alone.

    1. Local SQLite cache (24 h TTL)
    2. Google Safe Browsing v4 (10,000 lookups a day)
    3. PhishTank verified phishing feed (in memory)
    4. URLhaus (abuse.ch), malware URLs
    5. Spamhaus DBL (DNS), domain level

When the Safe Browsing daily quota runs out, tiers 2 to 4 run in
parallel and a URL flagged by any of them is flagged. The cache answers
most repeat lookups, so a normal day stays well under the 10,000 limit.

Every result is written back to the cache for 24 hours, so the same URL
is not looked up again across scans, restarts or users of a shared
backend.

Public API:
    ReputationEngine
        .startup()               : download the PhishTank feed, purge the cache
        .check_urls(urls) -> list: cascade lookup
        .stats()                 : quota and cache hit rate (GET /reputation/stats)
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import json
import logging
import os
import re
import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auth_headers import spamhaus_dbl
from link_alignment import link_host
from settings import VERSION

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

try:
    import httpx

    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    logger.warning("httpx not installed: reputation lookups disabled. pip install httpx>=0.27")


# Configuration (env-tunable)
GSB_API_KEY = os.environ.get("GSB_API_KEY", "").strip()
GSB_DAILY_LIMIT = int(os.environ.get("GSB_DAILY_LIMIT", "10000"))
GSB_SAFETY_BUFFER = int(os.environ.get("GSB_SAFETY_BUFFER", "500"))
GSB_MAX_PER_SCAN = int(os.environ.get("GSB_MAX_PER_SCAN", "30"))
# Per-user cache folder by default, not the shared /tmp.
CACHE_DB_PATH = os.environ.get(
    "REPUTATION_CACHE_DB",
    os.path.join(os.path.expanduser("~"), ".cache", "phishlens", "reputation.db"),
)
CACHE_TTL_SEC = int(os.environ.get("REPUTATION_CACHE_TTL", str(24 * 3600)))
PHISHTANK_API_KEY = os.environ.get("PHISHTANK_API_KEY", "").strip()  # optional
# Without an application key PhishTank allows only a few downloads a day:
# every 6 hours then, every hour with a key (the feed changes hourly).
PHISHTANK_REFRESH_S = int(
    os.environ.get("PHISHTANK_REFRESH_S") or (3600 if PHISHTANK_API_KEY else 6 * 3600)
)
# The last good feed, kept next to the cache so a restart does not
# download it again.
PHISHTANK_FEED_PATH = os.environ.get(
    "PHISHTANK_FEED_PATH", os.path.join(os.path.dirname(CACHE_DB_PATH), "phishtank.json.gz")
)
ENABLE_URLHAUS = os.environ.get("REPUTATION_ENABLE_URLHAUS", "1") != "0"
ENABLE_PHISHTANK = os.environ.get("REPUTATION_ENABLE_PHISHTANK", "1") != "0"
ENABLE_GSB = os.environ.get("REPUTATION_ENABLE_GSB", "1") != "0"
HTTP_TIMEOUT = float(os.environ.get("REPUTATION_HTTP_TIMEOUT", "3.0"))

USER_AGENT = f"PhishLens/{VERSION} (+https://github.com/AnzouK/PhishLens)"


# SQLite cache: persistent across restarts, thread-safe via lock.
class Cache:
    """Tiny SQLite cache with TTL. One row per URL. Expired rows are
    deleted at startup, then at most once an hour by a write, a stats()
    call or /health, so none is kept much past the TTL however long the
    instance runs, busy or idle.

    One threading lock covers every database call: the async methods run
    in worker threads (asyncio.to_thread), and /health and
    /reputation/stats call stats() and purge_if_due() from the threads
    of sync routes. Reentrant, as a write purges and a read can re-create
    the table while holding it."""

    PURGE_EVERY_SEC = 3600

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._last_purge = 0.0
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.path) as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS reputation_cache (
                    url        TEXT PRIMARY KEY,
                    verdict    TEXT NOT NULL,
                    stored_at  INTEGER NOT NULL
                )
            """)
            db.execute("""
                CREATE INDEX IF NOT EXISTS idx_stored_at
                    ON reputation_cache(stored_at)
            """)

    async def get(self, url: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self._get_sync, url)

    def _get_sync(self, url: str) -> dict[str, Any] | None:
        with self._lock:
            return self._get_locked(url)

    def _get_locked(self, url: str) -> dict[str, Any] | None:
        cutoff = int(time.time()) - CACHE_TTL_SEC
        try:
            with sqlite3.connect(self.path) as db:
                row = db.execute(
                    "SELECT verdict, stored_at FROM reputation_cache "
                    "WHERE url = ? AND stored_at > ?",
                    (url, cutoff),
                ).fetchone()
        except sqlite3.OperationalError as e:
            # The DB file was deleted or corrupted after startup, or the
            # volume was remounted: re-create the schema and count a miss.
            if "no such table" in str(e).lower():
                self._init_db()
                return None
            raise
        if not row:
            return None
        try:
            v = json.loads(row[0])
            v["cached"] = True
            v["cached_age_sec"] = int(time.time()) - row[1]
            return v
        except json.JSONDecodeError:
            return None

    async def put(self, url: str, verdict: dict[str, Any]):
        await asyncio.to_thread(self._put_sync, url, verdict)

    def _put_sync(self, url: str, verdict: dict[str, Any]):
        with self._lock:
            self._put_locked(url, verdict)

    def _put_locked(self, url: str, verdict: dict[str, Any]):
        # Drop the cached markers so a re-stored verdict does not keep them.
        v = {k: val for k, val in verdict.items() if k not in ("cached", "cached_age_sec")}
        try:
            with sqlite3.connect(self.path) as db:
                db.execute(
                    "INSERT OR REPLACE INTO reputation_cache(url, verdict, stored_at) "
                    "VALUES (?, ?, ?)",
                    (url, json.dumps(v), int(time.time())),
                )
        except sqlite3.OperationalError as e:
            if "no such table" in str(e).lower():
                # Re-create the schema and retry once. A second failure is a
                # real filesystem problem and is raised.
                self._init_db()
                with sqlite3.connect(self.path) as db:
                    db.execute(
                        "INSERT OR REPLACE INTO reputation_cache(url, verdict, stored_at) "
                        "VALUES (?, ?, ?)",
                        (url, json.dumps(v), int(time.time())),
                    )
            else:
                raise
        self.purge_if_due()

    def purge_if_due(self) -> None:
        with self._lock:
            if time.time() - self._last_purge >= self.PURGE_EVERY_SEC:
                self._purge_sync()

    async def purge_expired(self):
        await asyncio.to_thread(self._purge_sync)

    def _purge_sync(self):
        with self._lock:
            self._purge_locked()

    def _purge_locked(self):
        self._last_purge = time.time()
        cutoff = int(time.time()) - CACHE_TTL_SEC
        try:
            with sqlite3.connect(self.path) as db:
                db.execute("DELETE FROM reputation_cache WHERE stored_at <= ?", (cutoff,))
        except sqlite3.OperationalError as e:
            if "no such table" in str(e).lower():
                self._init_db()  # nothing to purge; later writes need the table
            else:
                raise

    def stats(self) -> dict[str, int]:
        with self._lock:
            self.purge_if_due()
            try:
                with sqlite3.connect(self.path) as db:
                    total = db.execute("SELECT COUNT(*) FROM reputation_cache").fetchone()[0]
            except sqlite3.OperationalError as e:
                if "no such table" in str(e).lower():
                    self._init_db()
                    return {"cache_entries": 0}
                raise
        return {"cache_entries": total}


# Google Safe Browsing v4: quota-tracked client.
class GsbQuota:
    """
    Simple daily counter, resets at 00:00 UTC.

    Kept in-process (not Redis) because a single instance handles all
    backend traffic (PhishLens Cloud runs at most one Cloud Run
    instance). The count starts again at zero when the instance
    restarts. With several replicas this would become a Redis INCR with
    EX=86400 behind the same interface.
    """

    def __init__(self, limit: int, buffer: int):
        self.limit = limit
        self.buffer = buffer
        self._counter = 0
        self._day = self._today()
        self._lock = asyncio.Lock()

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    async def try_consume(self, n: int = 1) -> bool:
        async with self._lock:
            today = self._today()
            if today != self._day:
                self._day = today
                self._counter = 0
            if self._counter + n > self.limit - self.buffer:
                return False
            self._counter += n
            return True

    def stats(self) -> dict[str, Any]:
        return {
            "day": self._day,
            "consumed": self._counter,
            "limit": self.limit,
            "safety_buffer": self.buffer,
            "remaining": max(0, self.limit - self.buffer - self._counter),
        }


class GoogleSafeBrowsing:
    """
    Google Safe Browsing Lookup API v4 client.
    https://developers.google.com/safe-browsing/v4/lookup-api
    """

    ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    THREAT_TYPES = [
        "MALWARE",
        "SOCIAL_ENGINEERING",  # this is the phishing bucket
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(self, api_key: str, quota: GsbQuota):
        self.api_key = api_key
        self.quota = quota
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def check_batch(self, urls: list[str]) -> dict[str, dict[str, Any]] | None:
        """
        Query GSB for a batch of URLs. Returns {url: verdict} for URLs that
        matched a threat; URLs not in the dict were checked and are clean.

        None when GSB did not answer (no key, quota exhausted, transport
        error): those URLs were not checked, and must not be cached as
        clean.
        """
        if not self.api_key:
            return None
        if not urls:
            return {}
        if not await self.quota.try_consume(len(urls)):
            return None

        payload = {
            "client": {"clientId": "phishlens", "clientVersion": VERSION},
            "threatInfo": {
                "threatTypes": self.THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        try:
            client = await self._get_client()
            # The key in a header, not in the URL: transport errors quote
            # the URL, and they are logged.
            r = await client.post(
                self.ENDPOINT, json=payload, headers={"X-Goog-Api-Key": self.api_key}
            )
            r.raise_for_status()
            body = r.json()
        except Exception as e:
            logger.warning(f"GSB request failed: {_safe_error(e)}")
            return None

        # GSB_DEBUG=1 logs every call and its match count, to diagnose a
        # phishing URL that is not flagged. Off by default.
        if os.environ.get("GSB_DEBUG", "0") != "0":
            n_matches = len(body.get("matches", []))
            logger.debug(f"[GSB] sent {len(urls)} URL(s), got {n_matches} match(es). URLs={urls}")
            if n_matches == 0:
                logger.debug(f"[GSB] full response body: {body}")

        results: dict[str, dict[str, Any]] = {}
        for match in body.get("matches", []):
            url = match.get("threat", {}).get("url", "")
            if not url:
                continue
            results.setdefault(
                url,
                {
                    "source": "google_safe_browsing",
                    "threat_types": [],
                    "platforms": [],
                },
            )
            results[url]["threat_types"].append(match.get("threatType", "UNKNOWN"))
            results[url]["platforms"].append(match.get("platformType", "UNKNOWN"))
        return results


# PhishTank: verified phishing feed, in-memory set.
# Hosts where one domain serves many unrelated owners, told apart by the
# path (storage buckets, link shorteners, form and file-sharing services,
# email click trackers, big platforms). A PhishTank entry on such a host
# says nothing about the other links of that host, so only the exact URL
# is matched there. Subdomain-based hosting (name.web.app, name.github.io)
# is not listed: its full host name already belongs to one owner.
SHARED_PATH_HOSTS = frozenset(
    {
        # cloud storage and static hosting by path
        "storage.googleapis.com",
        "firebasestorage.googleapis.com",
        "storage.cloud.google.com",
        "amazonaws.com",
        "blob.core.windows.net",
        "r2.dev",
        "ipfs.io",
        "dweb.link",
        "cloudflare-ipfs.com",
        "raw.githubusercontent.com",
        "gist.github.com",
        # link shorteners and redirectors
        "bit.ly",
        "bitly.com",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "rb.gy",
        "t.ly",
        "lnkd.in",
        "c.gle",
        "linktr.ee",
        "s.id",
        "tiny.cc",
        "qrco.de",
        # documents, forms and file sharing
        "google.com",
        "sites.google.com",
        "docs.google.com",
        "drive.google.com",
        "forms.gle",
        "microsoft.com",
        "office.com",
        "sharepoint.com",
        "onedrive.live.com",
        "1drv.ms",
        "live.com",
        "dropbox.com",
        "dropboxusercontent.com",
        "wetransfer.com",
        "we.tl",
        "box.com",
        "mega.nz",
        "mediafire.com",
        "docsend.com",
        "canva.com",
        "notion.so",
        "jotform.com",
        "typeform.com",
        "forms.office.com",
        "airtable.com",
        # big platforms
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "medium.com",
        "youtube.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "apple.com",
        "icloud.com",
        "adobe.com",
        "wordpress.com",
        # email click trackers and sending platforms
        "mandrillapp.com",
        "sendgrid.net",
        "mailchi.mp",
        "list-manage.com",
        "sendibm1.com",
        "hubspotlinks.com",
        "mailgun.org",
        "sparkpostmail.com",
        "exacttarget.com",
    }
)


def is_shared_path_host(netloc: str) -> bool:
    host = netloc.lower().split("@")[-1].split(":")[0].removeprefix("www.")
    return any(host == h or host.endswith("." + h) for h in SHARED_PATH_HOSTS)


class PhishTank:
    """
    PhishTank's public feed of verified phishing URLs. The full JSON dump
    is downloaded at startup and refreshed in the background; lookups are
    answered from an in-memory set.
    """

    # HTTPS: over plain HTTP anyone on the path could rewrite the list.
    FEED_URL = "https://data.phishtank.com/data/online-valid.json.gz"
    FEED_URL_AUTH = "https://data.phishtank.com/data/{key}/online-valid.json.gz"

    def __init__(self, api_key: str = "", feed_path: str = ""):
        self.api_key = api_key
        self.feed_path = feed_path
        self._urls: set[str] = set()
        self._domains: set[str] = set()
        self._last_refresh_ts: float = 0.0
        self._last_error: str = ""
        self._refresh_task: asyncio.Task | None = None

    def _feed_url(self) -> str:
        if self.api_key:
            return self.FEED_URL_AUTH.format(key=self.api_key)
        return self.FEED_URL

    @staticmethod
    def _parse(raw: bytes) -> list[dict[str, Any]]:
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        data = json.loads(raw)
        if not isinstance(data, list):
            raise ValueError("unexpected feed format")
        return data

    def load_saved(self) -> int:
        """Loads the last good feed saved on disk. Returns its entries."""
        if not self.feed_path or not os.path.exists(self.feed_path):
            return 0
        try:
            with open(self.feed_path, "rb") as fh:
                n = self._load(self._parse(fh.read()))
        except (OSError, ValueError) as e:
            logger.warning(f"PhishTank saved feed unreadable: {e}")
            return 0
        self._last_refresh_ts = os.path.getmtime(self.feed_path)
        return n

    def saved_age(self) -> float | None:
        if not self.feed_path or not os.path.exists(self.feed_path):
            return None
        return time.time() - os.path.getmtime(self.feed_path)

    def _save(self, raw: bytes) -> None:
        if not self.feed_path:
            return
        try:
            Path(self.feed_path).parent.mkdir(parents=True, exist_ok=True)
            tmp = self.feed_path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(raw if raw[:2] == b"\x1f\x8b" else gzip.compress(raw))
            os.replace(tmp, self.feed_path)
        except OSError as e:
            logger.warning(f"PhishTank feed not saved: {e}")

    async def refresh(self) -> int:
        """Download and load the feed. Returns the number of entries; on a
        failure the previous list stays and the reason is kept for /stats."""
        try:
            async with httpx.AsyncClient(
                timeout=60, headers={"User-Agent": USER_AGENT}, follow_redirects=True
            ) as c:
                r = await c.get(self._feed_url())
                if r.status_code != 200:
                    self._last_error = f"HTTP {r.status_code}"
                    logger.warning(
                        f"PhishTank refresh failed: HTTP {r.status_code}"
                        + ("" if self.api_key else " (no PHISHTANK_API_KEY: a few downloads a day)")
                    )
                    return 0
                data = self._parse(r.content)
        except Exception as e:
            self._last_error = type(e).__name__
            logger.warning(f"PhishTank refresh failed: {_safe_error(e)}")
            return 0
        n = self._load(data)
        self._last_refresh_ts = time.time()
        self._last_error = ""
        self._save(r.content)
        return n

    def _load(self, data: list[dict[str, Any]]) -> int:
        urls, domains = set(), set()
        for e in data:
            u = e.get("url", "")
            if not u:
                continue
            urls.add(u)
            host = link_host(u)
            if host and not is_shared_path_host(host):
                domains.add(host)

        self._urls = urls
        self._domains = domains
        return len(urls)

    async def start_refresh_loop(self, first_wait: float = 0.0):
        """Background task: refresh every PHISHTANK_REFRESH_S seconds."""
        await asyncio.sleep(first_wait)
        while True:
            try:
                n = await self.refresh()
                if n:
                    logger.info(f"PhishTank feed refreshed: {n} entries")
            except Exception as e:
                logger.warning(f"PhishTank loop error: {e}")
            await asyncio.sleep(PHISHTANK_REFRESH_S)

    def check(self, url: str) -> dict[str, Any] | None:
        """O(1) lookup: returns a verdict dict if listed, None otherwise."""
        if url in self._urls:
            return {"source": "phishtank", "match": "url", "threat_types": ["PHISHING"]}
        # The host as a browser reads it: "user@", a port or a final dot
        # around a listed domain no longer hide it (the netloc kept them).
        host = link_host(url)
        if host and host in self._domains and not is_shared_path_host(host):
            return {"source": "phishtank", "match": "domain", "threat_types": ["PHISHING"]}
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "phishtank_entries": len(self._urls),
            "phishtank_domains": len(self._domains),
            "phishtank_last_refresh_ts": self._last_refresh_ts,
            "phishtank_last_error": self._last_error or None,
        }


# URLhaus: abuse.ch malware URL feed.
class URLhaus:
    """
    URLhaus lookup API: free, no key required, generous rate limit.
    https://urlhaus.abuse.ch/api/
    """

    LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=HTTP_TIMEOUT, headers={"User-Agent": USER_AGENT}
            )
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def check(self, url: str) -> dict[str, Any] | None:
        try:
            client = await self._get_client()
            r = await client.post(self.LOOKUP_URL, data={"url": url})
            r.raise_for_status()
            body = r.json()
        except Exception:
            return None

        if body.get("query_status") != "ok":
            return None
        return {
            "source": "urlhaus",
            "threat_types": ["MALWARE"],
            "threat": body.get("threat"),
            "tags": body.get("tags", []),
            "date_added": body.get("date_added"),
            "urlhaus_reference": body.get("urlhaus_reference"),
        }


async def _spamhaus_dbl(host: str) -> dict[str, Any] | None:
    """A link's domain in the Spamhaus DBL, as a reputation source."""
    listing = await spamhaus_dbl(host)
    if not listing:
        return None
    return {
        "source": "spamhaus_dbl",
        "threat_types": [listing["threat_type"]],
        "dbl_code": listing["code"],
        "category": listing["category"],
    }


# Orchestrator
@dataclass
class UrlVerdict:
    url: str
    malicious: bool = False
    score: float = 0.0  # 0.0 clean → 1.0 malicious
    threat_types: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    tiers_run: list[str] = field(default_factory=list)
    cached: bool = False
    raw_matches: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "malicious": self.malicious,
            "score": self.score,
            "threat_types": sorted(set(self.threat_types)),
            "sources": self.sources,
            "tiers_run": self.tiers_run,
            "cached": self.cached,
            "raw_matches": self.raw_matches,
        }


class ReputationEngine:
    """
    Top-level cascade. Instantiate once at startup, call check_urls() per
    scan. Cache and quota state live for the process lifetime.
    """

    def __init__(self):
        self.cache = Cache(CACHE_DB_PATH)
        self.quota = GsbQuota(GSB_DAILY_LIMIT, GSB_SAFETY_BUFFER)
        self.gsb = (
            GoogleSafeBrowsing(GSB_API_KEY, self.quota) if (GSB_API_KEY and ENABLE_GSB) else None
        )
        self.phishtank = (
            PhishTank(PHISHTANK_API_KEY, PHISHTANK_FEED_PATH) if ENABLE_PHISHTANK else None
        )
        self.urlhaus = URLhaus() if ENABLE_URLHAUS else None
        self._hits = 0
        self._misses = 0

    async def startup(self):
        """Warm PhishTank + purge stale cache entries. Idempotent."""
        if self.phishtank and _HTTPX_AVAILABLE:
            # The saved feed first: a restart then costs no download.
            n = self.phishtank.load_saved()
            age = self.phishtank.saved_age()
            wait = 0.0
            if n:
                logger.info(f"PhishTank saved feed: {n} entries")
                wait = max(0.0, PHISHTANK_REFRESH_S - (age or 0))
            self.phishtank._refresh_task = asyncio.create_task(
                self.phishtank.start_refresh_loop(first_wait=wait)
            )
        await self.cache.purge_expired()

    async def shutdown(self):
        if self.phishtank and self.phishtank._refresh_task:
            self.phishtank._refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.phishtank._refresh_task
        if self.gsb:
            await self.gsb.close()
        if self.urlhaus:
            await self.urlhaus.close()

    def _normalize(self, url: str) -> str:
        url = url.strip()
        if not url:
            return ""
        # Add scheme if missing so GSB / URLhaus / urlparse behave consistently.
        if not re.match(r"^https?://", url, re.IGNORECASE):
            url = "http://" + url
        return url

    async def _from_cache(self, norm: list[str], verdicts: dict[str, UrlVerdict]) -> list[str]:
        """Fill `verdicts` from the cache; return the URLs it did not have."""
        uncached: list[str] = []
        for u in norm:
            cached = await self.cache.get(u)
            if cached is None:
                uncached.append(u)
                self._misses += 1
                continue
            self._hits += 1
            verdicts[u] = UrlVerdict(
                url=u,
                malicious=cached.get("malicious", False),
                score=cached.get("score", 0.0),
                threat_types=cached.get("threat_types", []),
                sources=cached.get("sources", []),
                tiers_run=cached.get("tiers_run", []),
                cached=True,
                raw_matches=cached.get("raw_matches", []),
            )
        return uncached

    async def _fallback(self, v: UrlVerdict) -> None:
        """PhishTank, URLhaus and the Spamhaus DBL for one URL Safe
        Browsing did not flag."""
        u = v.url
        pt_result = self.phishtank.check(u) if self.phishtank else None
        uh_result_task = self.urlhaus.check(u) if self.urlhaus else None
        host = link_host(u)
        sh_task = _spamhaus_dbl(host) if host else None

        uh_result = await uh_result_task if uh_result_task else None
        sh_result = await sh_task if sh_task else None

        for tier_name, r in (
            ("phishtank", pt_result),
            ("urlhaus", uh_result),
            ("spamhaus_dbl", sh_result),
        ):
            v.tiers_run.append(tier_name)
            if r:
                v.malicious = True
                v.threat_types.extend(r.get("threat_types", []))
                v.sources.append(r["source"])
                v.raw_matches.append(r)

        # Score: 1.0 from GSB, 0.4 per fallback source (capped at 1.0)
        if v.malicious:
            if "google_safe_browsing" in v.sources:
                v.score = 1.0
            else:
                n_fallback = sum(
                    1 for s in v.sources if s in ("phishtank", "urlhaus", "spamhaus_dbl")
                )
                v.score = min(1.0, 0.4 * n_fallback + 0.2)

    async def check_urls(self, urls: Iterable[str]) -> list[dict[str, Any]]:
        """Cascade lookup: returns one verdict dict per input URL."""
        if not _HTTPX_AVAILABLE:
            return [
                {
                    "url": u,
                    "malicious": False,
                    "score": 0.0,
                    "sources": [],
                    "threat_types": [],
                    "tiers_run": [],
                    "cached": False,
                    "raw_matches": [],
                    "note": "httpx not installed",
                }
                for u in urls
            ]

        norm = [self._normalize(u) for u in urls if u]
        norm = [u for u in norm if u]
        if not norm:
            return []

        verdicts: dict[str, UrlVerdict] = {u: UrlVerdict(url=u) for u in norm}

        uncached = await self._from_cache(norm, verdicts)
        if not uncached:
            return [verdicts[u].to_dict() for u in norm]

        # Google Safe Browsing, in one batch. At most GSB_MAX_PER_SCAN URLs per scan, the first ones in the
        # caller's rank order: the daily quota is shared by every user, and
        # one request with hundreds of links must not spend it.
        gsb_hits: dict[str, dict[str, Any]] = {}
        gsb_checked: set[str] = set()
        if self.gsb:
            batch = _gsb_batch(uncached, GSB_MAX_PER_SCAN)
            answer = await self.gsb.check_batch(batch)
            if answer is not None:
                gsb_hits, gsb_checked = answer, set(batch)

        # The other feeds check what Safe Browsing did not flag, or
        # everything when it is disabled or out of quota.
        need_fallback = _apply_gsb(verdicts, uncached, gsb_hits, gsb_checked)
        if need_fallback:
            await asyncio.gather(
                *(self._fallback(verdicts[u]) for u in need_fallback), return_exceptions=True
            )

        # A clean verdict is kept only when Safe Browsing (when configured)
        # checked the URL: otherwise exhausting the quota with junk links,
        # then sending a phishing link, would store it as clean for a day.
        for u in uncached:
            if verdicts[u].malicious or not self.gsb or u in gsb_checked:
                await self.cache.put(u, verdicts[u].to_dict())

        return [verdicts[u].to_dict() for u in norm]

    def stats(self) -> dict[str, Any]:
        total = self._hits + self._misses
        return {
            "cache": {
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": (self._hits / total) if total else 0.0,
                **self.cache.stats(),
            },
            "gsb": self.quota.stats() if self.gsb else {"enabled": False},
            "phishtank": self.phishtank.stats() if self.phishtank else {"enabled": False},
            "urlhaus": {"enabled": bool(self.urlhaus)},
        }


# Module-level singleton: the FastAPI app pulls this in lifespan.
_ENGINE: ReputationEngine | None = None


def get_engine() -> ReputationEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = ReputationEngine()
    return _ENGINE


async def startup():
    await get_engine().startup()


async def shutdown():
    global _ENGINE
    if _ENGINE:
        await _ENGINE.shutdown()
        _ENGINE = None


async def check_urls(urls: Iterable[str]) -> list[dict[str, Any]]:
    return await get_engine().check_urls(urls)


def fully_checked(verdicts: list[dict[str, Any]]) -> bool:
    """Every URL is flagged, or Safe Browsing (when configured) checked it."""
    if not (_ENGINE and _ENGINE.gsb):
        return True
    return all(v.get("malicious") or "gsb_clean" in (v.get("tiers_run") or []) for v in verdicts)


def stats() -> dict[str, Any]:
    return get_engine().stats() if _ENGINE else {"engine": "not_initialised"}


def purge_if_due() -> None:
    """Expired cache rows out, at most once an hour (Cache.purge_if_due)."""
    if _ENGINE:
        _ENGINE.cache.purge_if_due()


def _apply_gsb(
    verdicts: dict[str, UrlVerdict],
    uncached: list[str],
    gsb_hits: dict[str, dict[str, Any]],
    gsb_checked: set[str],
) -> list[str]:
    """Mark Safe Browsing matches; return the URLs left for the fallback
    sources."""
    need_fallback: list[str] = []
    for u in uncached:
        if u in gsb_hits:
            v = verdicts[u]
            v.malicious = True
            v.score = 1.0
            v.threat_types.extend(gsb_hits[u].get("threat_types", []))
            v.sources.append("google_safe_browsing")
            v.tiers_run.append("gsb")
            v.raw_matches.append(gsb_hits[u])
        else:
            if u in gsb_checked:
                verdicts[u].tiers_run.append("gsb_clean")
            need_fallback.append(u)
    return need_fallback


def _gsb_batch(urls: list[str], limit: int) -> list[str]:
    """The first `limit` URLs, in the order given: the caller ranks them
    (extension_backend.rank_links: visible links first, one per host
    first). Ranking them again here put hidden links on new hosts before
    a second visible one."""
    return list(urls)[:limit]


def _safe_error(e: Exception) -> str:
    """An error for the logs without the request URL, which can carry an
    API key (PhishTank's is in the feed's path)."""
    status = getattr(getattr(e, "response", None), "status_code", None)
    return f"{type(e).__name__}" + (f" (HTTP {status})" if status else "")
