"""
PhishLens — URL reputation cascade.
=====================================================================

Cascaded lookup against multiple threat-intel feeds so we never rely on
a single source of truth. Order:

    1. Local SQLite cache (24h TTL)                   — sub-millisecond
    2. Google Safe Browsing v4 (10,000 lookups/day)   — Google's flagship
    3. PhishTank verified phishing feed (in-memory)   — community-verified
    4. URLhaus (abuse.ch)                             — malware URLs
    5. Spamhaus DBL (DNS)                             — domain-level

When the GSB daily quota runs out, tiers 2-4 all run in parallel and
their verdicts are OR-fused. The cache absorbs the vast majority of
repeat lookups so a real-world day rarely hits the 10k limit anyway.

Every result is written back to the cache with a 24h TTL so the same
URL isn't re-queried across scans, restarts, or between users of a
shared backend.

Public API:
    ReputationEngine
        .startup()                — download PhishTank feed, warm cache
        .check_urls(urls) -> list — cascade lookup
        .stats()                  — quota + cache hit rate for debug/health
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import socket
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
    print("⚠ httpx not installed — reputation lookups disabled. "
          "pip install httpx>=0.27")


# ---------------------------------------------------------------------
# Configuration (env-tunable)
# ---------------------------------------------------------------------
GSB_API_KEY         = os.environ.get("GSB_API_KEY", "").strip()
GSB_DAILY_LIMIT     = int(os.environ.get("GSB_DAILY_LIMIT", "10000"))
GSB_SAFETY_BUFFER   = int(os.environ.get("GSB_SAFETY_BUFFER", "500"))
CACHE_DB_PATH       = os.environ.get("REPUTATION_CACHE_DB", "/tmp/phishlens_reputation.db")
CACHE_TTL_SEC       = int(os.environ.get("REPUTATION_CACHE_TTL", str(24 * 3600)))
PHISHTANK_REFRESH_S = int(os.environ.get("PHISHTANK_REFRESH_S", "3600"))
PHISHTANK_API_KEY   = os.environ.get("PHISHTANK_API_KEY", "").strip()  # optional
ENABLE_URLHAUS      = os.environ.get("REPUTATION_ENABLE_URLHAUS", "1") != "0"
ENABLE_PHISHTANK    = os.environ.get("REPUTATION_ENABLE_PHISHTANK", "1") != "0"
ENABLE_GSB          = os.environ.get("REPUTATION_ENABLE_GSB", "1") != "0"
HTTP_TIMEOUT        = float(os.environ.get("REPUTATION_HTTP_TIMEOUT", "3.0"))

USER_AGENT = "PhishLens/1.6 (+https://github.com/AnzouK/PhishLens)"


# =====================================================================
# SQLite cache — persistent across restarts, thread-safe via lock.
# =====================================================================
class Cache:
    """Tiny SQLite cache with TTL. One row per URL."""

    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
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
        async with self._lock:
            return await asyncio.to_thread(self._get_sync, url)

    def _get_sync(self, url: str) -> dict[str, Any] | None:
        cutoff = int(time.time()) - CACHE_TTL_SEC
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT verdict, stored_at FROM reputation_cache "
                "WHERE url = ? AND stored_at > ?",
                (url, cutoff),
            ).fetchone()
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
        async with self._lock:
            await asyncio.to_thread(self._put_sync, url, verdict)

    def _put_sync(self, url: str, verdict: dict[str, Any]):
        # Strip the cached flag before storing so we don't compound it.
        v = {k: val for k, val in verdict.items() if k not in ("cached", "cached_age_sec")}
        with sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT OR REPLACE INTO reputation_cache(url, verdict, stored_at) "
                "VALUES (?, ?, ?)",
                (url, json.dumps(v), int(time.time())),
            )

    async def purge_expired(self):
        async with self._lock:
            await asyncio.to_thread(self._purge_sync)

    def _purge_sync(self):
        cutoff = int(time.time()) - CACHE_TTL_SEC
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM reputation_cache WHERE stored_at <= ?", (cutoff,))

    def stats(self) -> dict[str, int]:
        with sqlite3.connect(self.path) as db:
            total = db.execute("SELECT COUNT(*) FROM reputation_cache").fetchone()[0]
        return {"cache_entries": total}


# =====================================================================
# Google Safe Browsing v4 — quota-tracked client.
# =====================================================================
class GsbQuota:
    """
    Simple daily counter, resets at 00:00 UTC.

    Kept in-process (not Redis) because a single Oracle Cloud VM handles
    all backend traffic. If we ever scale to N replicas, swap this for
    a Redis INCR with EX=86400 — same interface.
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
        "SOCIAL_ENGINEERING",   # this is the phishing bucket
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]

    def __init__(self, api_key: str, quota: GsbQuota):
        self.api_key = api_key
        self.quota = quota
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> "httpx.AsyncClient":
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                             headers={"User-Agent": USER_AGENT})
        return self._client

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def check_batch(self, urls: list[str]) -> dict[str, dict[str, Any]]:
        """
        Query GSB for a batch of URLs. Returns {url: verdict} for URLs that
        matched a threat; URLs not in the dict are assumed clean.

        On quota exhaustion or transport error, returns an empty dict —
        callers must treat that as "GSB unavailable, use fallbacks".
        """
        if not self.api_key or not urls:
            return {}
        if not await self.quota.try_consume(len(urls)):
            return {}

        payload = {
            "client": {"clientId": "phishlens", "clientVersion": "1.6.0"},
            "threatInfo": {
                "threatTypes": self.THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        try:
            client = await self._get_client()
            r = await client.post(f"{self.ENDPOINT}?key={self.api_key}",
                                  json=payload)
            r.raise_for_status()
            body = r.json()
        except Exception as e:
            print(f"⚠ GSB request failed: {e}")
            return {}

        # Temporary debug — log what Google actually returned so we can
        # diagnose "consumed=1 but zero matches" cases. Cheap enough to
        # leave on: one line per /analyse call, empty body most of the time.
        if os.environ.get("GSB_DEBUG", "1") != "0":
            n_matches = len(body.get("matches", []))
            print(f"[GSB] sent {len(urls)} URL(s), Google returned "
                  f"{n_matches} match(es). URLs={urls}. Body_keys={list(body.keys())}")
            if n_matches == 0 and urls:
                # Show first URL and full body — helps spot canonicalization
                # or key-restriction issues (e.g. HTTP referrer restrictions
                # on the API key can silently return {}).
                print(f"[GSB] first URL sent: {urls[0]!r}")
                print(f"[GSB] full response body: {body}")

        results: dict[str, dict[str, Any]] = {}
        for match in body.get("matches", []):
            url = match.get("threat", {}).get("url", "")
            if not url:
                continue
            results.setdefault(url, {
                "source": "google_safe_browsing",
                "threat_types": [],
                "platforms": [],
            })
            results[url]["threat_types"].append(match.get("threatType", "UNKNOWN"))
            results[url]["platforms"].append(match.get("platformType", "UNKNOWN"))
        return results


# =====================================================================
# PhishTank — verified phishing feed, in-memory set.
# =====================================================================
class PhishTank:
    """
    PhishTank's public feed of verified phishing URLs. We download the
    full JSON dump once at startup, refresh in the background every hour,
    and answer lookups from an in-memory set for zero-cost O(1) checks.
    """

    FEED_URL = "http://data.phishtank.com/data/online-valid.json"
    FEED_URL_AUTH = "http://data.phishtank.com/data/{key}/online-valid.json"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._urls: set[str] = set()
        self._domains: set[str] = set()
        self._last_refresh_ts: float = 0.0
        self._refresh_task: asyncio.Task | None = None

    def _feed_url(self) -> str:
        if self.api_key:
            return self.FEED_URL_AUTH.format(key=self.api_key)
        return self.FEED_URL

    async def refresh(self) -> int:
        """Download and load the feed. Returns the number of entries."""
        try:
            async with httpx.AsyncClient(timeout=30,
                                         headers={"User-Agent": USER_AGENT},
                                         follow_redirects=True) as c:
                r = await c.get(self._feed_url())
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            print(f"⚠ PhishTank refresh failed: {e}")
            return 0

        urls, domains = set(), set()
        for e in data:
            u = e.get("url", "")
            if not u:
                continue
            urls.add(u)
            try:
                netloc = urlparse(u).netloc.lower()
                if netloc:
                    domains.add(netloc)
            except Exception:
                pass

        self._urls = urls
        self._domains = domains
        self._last_refresh_ts = time.time()
        return len(urls)

    async def start_refresh_loop(self):
        """Background task — refresh every PHISHTANK_REFRESH_S seconds."""
        while True:
            try:
                n = await self.refresh()
                if n:
                    print(f"✓ PhishTank feed refreshed: {n} entries")
            except Exception as e:
                print(f"⚠ PhishTank loop error: {e}")
            await asyncio.sleep(PHISHTANK_REFRESH_S)

    def check(self, url: str) -> dict[str, Any] | None:
        """O(1) lookup — returns a verdict dict if listed, None otherwise."""
        if url in self._urls:
            return {"source": "phishtank", "match": "url", "threat_types": ["PHISHING"]}
        try:
            netloc = urlparse(url).netloc.lower()
        except Exception:
            return None
        if netloc and netloc in self._domains:
            return {"source": "phishtank", "match": "domain", "threat_types": ["PHISHING"]}
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "phishtank_entries": len(self._urls),
            "phishtank_domains": len(self._domains),
            "phishtank_last_refresh_ts": self._last_refresh_ts,
        }


# =====================================================================
# URLhaus — abuse.ch malware URL feed.
# =====================================================================
class URLhaus:
    """
    URLhaus lookup API — free, no key required, generous rate limit.
    https://urlhaus.abuse.ch/api/
    """
    LOOKUP_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self):
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> "httpx.AsyncClient":
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=HTTP_TIMEOUT,
                                             headers={"User-Agent": USER_AGENT})
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


# =====================================================================
# Spamhaus DBL — domain-level DNS lookup.
# =====================================================================
async def _spamhaus_dbl(domain: str) -> dict[str, Any] | None:
    """
    Query domain.dbl.spamhaus.org. If it resolves to a 127.0.1.x code,
    the domain is listed. NXDOMAIN = clean.

    IMPORTANT: 127.255.255.x codes are NOT listings — they are Spamhaus
    policy responses telling us the query was rejected (open/public
    resolver, anonymous query, rate limit). If we see one of those, we
    treat the check as "unavailable" and return None. Counting them as
    listings would false-positive on every domain we ever query.

    See https://www.spamhaus.org/faq/section/DNSBL%20Usage#365 for the
    full code table.
    """
    # Real listings — dbl.spamhaus.org threat classifications.
    _CODES = {
        "127.0.1.2":   ("SPAM",               "spam"),
        "127.0.1.4":   ("SOCIAL_ENGINEERING", "phish"),
        "127.0.1.5":   ("MALWARE",            "malware"),
        "127.0.1.6":   ("BOTNET_CC",          "botnet_cc"),
        "127.0.1.102": ("SPAM",               "abused_legit_spam"),
        "127.0.1.103": ("SUSPICIOUS",         "abused_legit_redirector"),
        "127.0.1.104": ("SOCIAL_ENGINEERING", "abused_legit_phish"),
        "127.0.1.105": ("MALWARE",            "abused_legit_malware"),
        "127.0.1.106": ("BOTNET_CC",          "abused_legit_botnet_cc"),
    }
    # Policy / error codes — the query was NOT answered. Treat as
    # "check unavailable", NOT as "domain malicious".
    _POLICY_ERROR_PREFIX = "127.255.255."

    if not domain or "." not in domain:
        return None
    query = f"{domain}.dbl.spamhaus.org"
    loop = asyncio.get_event_loop()
    try:
        resp = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, query),
            timeout=2.0,
        )
    except (socket.gaierror, socket.herror, asyncio.TimeoutError):
        return None
    except Exception:
        return None

    # Policy error — Spamhaus refused to answer (open resolver, rate
    # limit, anonymous query). NOT a listing. Return None so the caller
    # treats the tier as "no signal" rather than "malicious".
    if resp.startswith(_POLICY_ERROR_PREFIX):
        # Log once so we know DBL is effectively disabled on this host.
        if not _spamhaus_policy_logged["done"]:
            print(f"⚠ Spamhaus DBL policy response ({resp}) — the DNS resolver "
                  "used by this host is blocked by Spamhaus. DBL lookups will "
                  "be treated as unavailable. Use a private recursive resolver "
                  "or the Spamhaus DQS commercial feed to enable DBL.")
            _spamhaus_policy_logged["done"] = True
        return None

    # Real listing — 127.0.1.x range.
    if resp not in _CODES:
        # Unknown but 127.0.1.x-shaped response — probably a new threat
        # code we don't map yet. Still treat as SUSPICIOUS.
        if resp.startswith("127.0.1."):
            return {
                "source": "spamhaus_dbl",
                "threat_types": ["SUSPICIOUS"],
                "dbl_code": resp,
                "category": "listed_unknown_code",
            }
        # Anything else — not a documented DBL response, ignore.
        return None

    threat_type, category = _CODES[resp]
    return {
        "source": "spamhaus_dbl",
        "threat_types": [threat_type],
        "dbl_code": resp,
        "category": category,
    }


# Log the Spamhaus policy warning only once per process lifetime.
_spamhaus_policy_logged = {"done": False}


# =====================================================================
# Orchestrator
# =====================================================================
@dataclass
class UrlVerdict:
    url: str
    malicious: bool = False
    score: float = 0.0             # 0.0 clean → 1.0 malicious
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
        self.gsb = GoogleSafeBrowsing(GSB_API_KEY, self.quota) if (GSB_API_KEY and ENABLE_GSB) else None
        self.phishtank = PhishTank(PHISHTANK_API_KEY) if ENABLE_PHISHTANK else None
        self.urlhaus = URLhaus() if ENABLE_URLHAUS else None
        self._hits = 0
        self._misses = 0

    async def startup(self):
        """Warm PhishTank + purge stale cache entries. Idempotent."""
        if self.phishtank and _HTTPX_AVAILABLE:
            n = await self.phishtank.refresh()
            if n:
                print(f"✓ PhishTank initial load: {n} entries")
            # Fire-and-forget refresh loop
            self.phishtank._refresh_task = asyncio.create_task(
                self.phishtank.start_refresh_loop()
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

    async def check_urls(self, urls: Iterable[str]) -> list[dict[str, Any]]:
        """Cascade lookup — returns one verdict dict per input URL."""
        if not _HTTPX_AVAILABLE:
            return [{"url": u, "malicious": False, "score": 0.0,
                     "sources": [], "threat_types": [],
                     "tiers_run": [], "cached": False, "raw_matches": [],
                     "note": "httpx not installed"} for u in urls]

        norm = [self._normalize(u) for u in urls if u]
        norm = [u for u in norm if u]
        if not norm:
            return []

        verdicts: dict[str, UrlVerdict] = {u: UrlVerdict(url=u) for u in norm}

        # ---- 1. Cache lookup for every URL ----
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

        if not uncached:
            return [verdicts[u].to_dict() for u in norm]

        # ---- 2. Google Safe Browsing (batch) ----
        gsb_hits: dict[str, dict[str, Any]] = {}
        gsb_used = False
        if self.gsb:
            gsb_hits = await self.gsb.check_batch(uncached)
            gsb_used = True  # even if empty result — we consumed the quota

        # ---- 3. Fallback cascade for URLs GSB didn't flag ----
        # (also for the case where GSB is disabled / quota exhausted)
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
                if gsb_used:
                    verdicts[u].tiers_run.append("gsb_clean")
                need_fallback.append(u)

        # Run fallback tiers in parallel per URL
        async def _fallback_for(u: str):
            v = verdicts[u]
            pt_result = self.phishtank.check(u) if self.phishtank else None
            uh_result_task = self.urlhaus.check(u) if self.urlhaus else None
            netloc = urlparse(u).netloc
            sh_task = _spamhaus_dbl(netloc) if netloc else None

            uh_result = await uh_result_task if uh_result_task else None
            sh_result = await sh_task if sh_task else None

            for tier_name, r in (("phishtank", pt_result),
                                 ("urlhaus", uh_result),
                                 ("spamhaus_dbl", sh_result)):
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
                    n_fallback = sum(1 for s in v.sources
                                     if s in ("phishtank", "urlhaus", "spamhaus_dbl"))
                    v.score = min(1.0, 0.4 * n_fallback + 0.2)

        if need_fallback:
            await asyncio.gather(*(_fallback_for(u) for u in need_fallback),
                                 return_exceptions=True)

        # ---- 4. Persist to cache ----
        for u in uncached:
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


# =====================================================================
# Module-level singleton — the FastAPI app pulls this in lifespan.
# =====================================================================
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


def stats() -> dict[str, Any]:
    return get_engine().stats() if _ENGINE else {"engine": "not_initialised"}
