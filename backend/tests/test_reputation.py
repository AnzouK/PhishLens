"""
Tests for the URL reputation cascade (reputation.py). Every external
tier (Google Safe Browsing, PhishTank, URLhaus, Spamhaus DBL) is
replaced by an in-process fake, so these run offline in milliseconds.
What we pin here: the SQLite cache, the GSB daily quota, URL
normalisation, and the scoring rules of the cascade.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import reputation as rep


# ---------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------
class FakePhishTank:
    def __init__(self, bad: set[str]):
        self.bad = bad
        self._refresh_task = None

    def check(self, url):
        if url in self.bad:
            return {"source": "phishtank", "threat_types": ["SOCIAL_ENGINEERING"]}
        return None

    def stats(self):
        return {"enabled": True, "entries": len(self.bad)}


class FakeUrlhaus:
    def __init__(self, bad: set[str]):
        self.bad = bad

    async def check(self, url):
        if url in self.bad:
            return {"source": "urlhaus", "threat_types": ["MALWARE"]}
        return None

    async def close(self):
        pass


class FakeGsb:
    def __init__(self, bad: set[str]):
        self.bad = bad
        self.calls = 0

    async def check_batch(self, urls):
        self.calls += 1
        return {u: {"threat_types": ["SOCIAL_ENGINEERING"]} for u in urls if u in self.bad}

    async def close(self):
        pass


def make_engine(tmp_path, gsb=None, phishtank=None, urlhaus=None):
    """Build a ReputationEngine without touching the network or env."""
    eng = rep.ReputationEngine.__new__(rep.ReputationEngine)
    eng.cache = rep.Cache(str(tmp_path / "cache.db"))
    eng.quota = rep.GsbQuota(limit=100, buffer=10)
    eng.gsb = gsb
    eng.phishtank = phishtank
    eng.urlhaus = urlhaus
    eng._hits = 0
    eng._misses = 0
    return eng


@pytest.fixture
def offline(monkeypatch):
    """Force the cascade on (even if httpx is missing locally) and stub
    the Spamhaus DNS lookup so nothing leaves the machine."""
    monkeypatch.setattr(rep, "_HTTPX_AVAILABLE", True)

    async def _no_dbl(_domain):
        return None
    monkeypatch.setattr(rep, "_spamhaus_dbl", _no_dbl)
    return monkeypatch


# ---------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------
class TestCache:
    def test_roundtrip_marks_cached(self, tmp_path):
        async def go():
            c = rep.Cache(str(tmp_path / "c.db"))
            assert await c.get("http://a.tld") is None
            await c.put("http://a.tld", {"malicious": True, "score": 1.0})
            return await c.get("http://a.tld")
        v = asyncio.run(go())
        assert v["malicious"] is True
        assert v["cached"] is True
        assert "cached_age_sec" in v

    def test_cached_flag_not_persisted(self, tmp_path):
        c = rep.Cache(str(tmp_path / "c.db"))
        c._put_sync("http://a.tld", {"score": 0.0, "cached": True, "cached_age_sec": 9})
        v = c._get_sync("http://a.tld")
        # the flags come from the read, not from what was stored
        assert v["cached_age_sec"] < 9

    def test_expired_entries_ignored(self, tmp_path, monkeypatch):
        c = rep.Cache(str(tmp_path / "c.db"))
        c._put_sync("http://old.tld", {"score": 0.0})
        monkeypatch.setattr(rep, "CACHE_TTL_SEC", -1)
        assert c._get_sync("http://old.tld") is None

    def test_self_heals_if_table_dropped(self, tmp_path):
        import sqlite3
        path = str(tmp_path / "c.db")
        c = rep.Cache(path)
        with sqlite3.connect(path) as db:
            db.execute("DROP TABLE reputation_cache")
        assert c._get_sync("http://x.tld") is None
        c._put_sync("http://x.tld", {"score": 0.0})
        assert c.stats()["cache_entries"] == 1


# ---------------------------------------------------------------------
# GSB quota
# ---------------------------------------------------------------------
class TestGsbQuota:
    def test_stops_at_limit_minus_buffer(self):
        async def go():
            q = rep.GsbQuota(limit=10, buffer=2)
            results = [await q.try_consume() for _ in range(10)]
            return q, results
        q, results = asyncio.run(go())
        assert results.count(True) == 8
        assert q.stats()["remaining"] == 0

    def test_resets_on_new_day(self):
        async def go():
            q = rep.GsbQuota(limit=3, buffer=0)
            for _ in range(3):
                await q.try_consume()
            assert await q.try_consume() is False
            q._day = "1999-01-01"          # simulate midnight UTC rollover
            return await q.try_consume()
        assert asyncio.run(go()) is True


# ---------------------------------------------------------------------
# Cascade
# ---------------------------------------------------------------------
class TestCascade:
    def test_normalize_adds_scheme(self, tmp_path):
        eng = make_engine(tmp_path)
        assert eng._normalize("  example.com/x ") == "http://example.com/x"
        assert eng._normalize("HTTPS://a.tld") == "HTTPS://a.tld"
        assert eng._normalize("   ") == ""

    def test_clean_url(self, tmp_path, offline):
        eng = make_engine(tmp_path, phishtank=FakePhishTank(set()),
                          urlhaus=FakeUrlhaus(set()))
        [v] = asyncio.run(eng.check_urls(["https://ok.tld/"]))
        assert v["malicious"] is False
        assert v["score"] == 0.0
        assert set(v["tiers_run"]) == {"phishtank", "urlhaus", "spamhaus_dbl"}

    def test_gsb_hit_scores_one(self, tmp_path, offline):
        bad = "http://evil.tld/login"
        eng = make_engine(tmp_path, gsb=FakeGsb({bad}))
        [v] = asyncio.run(eng.check_urls([bad]))
        assert v["malicious"] is True
        assert v["score"] == 1.0
        assert v["sources"] == ["google_safe_browsing"]

    def test_single_fallback_hit(self, tmp_path, offline):
        bad = "http://phish.tld/"
        eng = make_engine(tmp_path, phishtank=FakePhishTank({bad}),
                          urlhaus=FakeUrlhaus(set()))
        [v] = asyncio.run(eng.check_urls([bad]))
        assert v["malicious"] is True
        assert v["score"] == pytest.approx(0.6)       # 0.4 * 1 + 0.2
        assert "phishtank" in v["sources"]

    def test_two_fallback_hits_stack(self, tmp_path, offline):
        bad = "http://both.tld/"
        eng = make_engine(tmp_path, phishtank=FakePhishTank({bad}),
                          urlhaus=FakeUrlhaus({bad}))
        [v] = asyncio.run(eng.check_urls([bad]))
        assert v["score"] == pytest.approx(1.0)       # 0.4 * 2 + 0.2

    def test_second_lookup_served_from_cache(self, tmp_path, offline):
        bad = "http://evil.tld/"
        gsb = FakeGsb({bad})
        eng = make_engine(tmp_path, gsb=gsb)

        async def go():
            await eng.check_urls([bad])
            return await eng.check_urls([bad])
        [v] = asyncio.run(go())
        assert v["cached"] is True
        assert v["malicious"] is True
        assert gsb.calls == 1                       # quota not burned twice
        assert eng.stats()["cache"]["hits"] == 1

    def test_empty_input(self, tmp_path, offline):
        eng = make_engine(tmp_path)
        assert asyncio.run(eng.check_urls(["", "   "])) == []

    def test_no_httpx_returns_neutral(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rep, "_HTTPX_AVAILABLE", False)
        eng = make_engine(tmp_path)
        [v] = asyncio.run(eng.check_urls(["http://x.tld"]))
        assert v["malicious"] is False
        assert v["note"] == "httpx not installed"
