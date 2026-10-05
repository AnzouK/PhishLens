"""Unit tests for result_cache.py (v1.15.2)."""
from __future__ import annotations

import result_cache as rc


def test_make_key_is_stable_and_ignores_auto_scan():
    a = rc.make_key("analyse", {"raw_text": "x", "client_context": {"origin": "gmail", "auto_scan": True}})
    b = rc.make_key("analyse", {"client_context": {"auto_scan": False, "origin": "gmail"}, "raw_text": "x"})
    c = rc.make_key("analyse", {"raw_text": "y", "client_context": {"origin": "gmail"}})
    assert a == b != c
    assert rc.make_key("explain", {"raw_text": "x"}) != rc.make_key("analyse", {"raw_text": "x"})


def test_entries_expire(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(rc.time, "monotonic", lambda: now[0])
    cache = rc.ResultCache(ttl=60, max_entries=10)
    cache.set("k", {"verdict": "safe"})
    now[0] += 59
    assert cache.get("k") == {"verdict": "safe"}
    now[0] += 2
    assert cache.get("k") is None
    assert cache.stats()["entries"] == 0


def test_oldest_entry_goes_first():
    cache = rc.ResultCache(ttl=60, max_entries=2)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")            # a is now the most recent
    cache.set("c", 3)
    assert cache.get("b") is None and cache.get("a") == 1 and cache.get("c") == 3


def test_returns_copies():
    cache = rc.ResultCache(ttl=60, max_entries=5)
    value = {"agents": {"text": 0.9}}
    cache.set("k", value)
    value["agents"]["text"] = 0.1
    got = cache.get("k")
    got["agents"]["text"] = 0.5
    assert cache.get("k") == {"agents": {"text": 0.9}}


def test_disabled_cache_stores_nothing():
    cache = rc.ResultCache(ttl=0, max_entries=5)
    cache.set("k", 1)
    assert cache.get("k") is None and not cache.stats()["enabled"]
