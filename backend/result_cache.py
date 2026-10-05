"""
In-memory cache for /analyse and /explain results (v1.15.2).

The same email is often checked more than once: auto-scan, then a manual
scan, then "Why this verdict?", or the same newsletter reaching several
users. A cache hit answers at once, keeps LIME explanations identical
between two clicks, and saves Google Safe Browsing quota.

- Keyed by a SHA-256 of the request: the email itself is never kept, only
  the verdict that was sent back (which holds the link verdicts already
  cached for 24 hours by the reputation module).
- Memory only: a restart or a redeploy empties it.
- Entries expire after ``RESULT_CACHE_TTL`` seconds (default 86400, 24 h;
  0 turns the cache off) and the oldest go first past
  ``RESULT_CACHE_MAX`` entries (default 2000).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import threading
import time
from collections import OrderedDict
from typing import Any

# client_context keys that do not change the verdict: two scans of the
# same email that differ only here share one cache entry.
_IGNORED_CONTEXT_KEYS = {"auto_scan"}


def make_key(namespace: str, payload: Any) -> str:
    """Stable hash of a JSON-able payload."""
    if isinstance(payload, dict) and isinstance(payload.get("client_context"), dict):
        payload = dict(payload)
        payload["client_context"] = {k: v for k, v in payload["client_context"].items()
                                     if k not in _IGNORED_CONTEXT_KEYS}
    blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return namespace + ":" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


class ResultCache:
    def __init__(self, ttl: float | None = None, max_entries: int | None = None):
        self.ttl = float(os.environ.get("RESULT_CACHE_TTL", "86400") if ttl is None else ttl)
        self.max_entries = int(os.environ.get("RESULT_CACHE_MAX", "2000") if max_entries is None else max_entries)
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    @property
    def enabled(self) -> bool:
        return self.ttl > 0 and self.max_entries > 0

    def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        with self._lock:
            item = self._data.get(key)
            if item is None or item[0] < time.monotonic():
                if item is not None:
                    del self._data[key]
                self.misses += 1
                return None
            self._data.move_to_end(key)
            self.hits += 1
            return copy.deepcopy(item[1])

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + self.ttl, copy.deepcopy(value))
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()
            self.hits = self.misses = 0

    def stats(self) -> dict:
        with self._lock:
            total = self.hits + self.misses
            return {
                "enabled": self.enabled,
                "entries": len(self._data),
                "ttl_hours": round(self.ttl / 3600, 2),
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else 0.0,
            }
