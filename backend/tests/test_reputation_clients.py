"""The network clients of the reputation cascade (Safe Browsing,
PhishTank, URLhaus), against in-process fake HTTP servers
(httpx.MockTransport): request shape and response parsing."""

from __future__ import annotations

import asyncio
import json

import pytest

httpx = pytest.importorskip("httpx")

import reputation as rep  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def client_for(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestSafeBrowsing:
    def make(self, handler, limit=100):
        gsb = rep.GoogleSafeBrowsing("KEY", rep.GsbQuota(limit, 0))
        gsb._client = client_for(handler)
        return gsb

    def test_matches_are_grouped_by_url(self):
        seen = {}

        def handler(request):
            seen["body"] = json.loads(request.content)
            seen["key"] = request.url.params["key"]
            return httpx.Response(
                200,
                json={
                    "matches": [
                        {
                            "threat": {"url": "http://bad.example/"},
                            "threatType": "SOCIAL_ENGINEERING",
                            "platformType": "ANY_PLATFORM",
                        },
                        {
                            "threat": {"url": "http://bad.example/"},
                            "threatType": "MALWARE",
                            "platformType": "WINDOWS",
                        },
                    ]
                },
            )

        out = run(self.make(handler).check_batch(["http://bad.example/", "https://good.example/"]))
        assert seen["key"] == "KEY"
        assert [e["url"] for e in seen["body"]["threatInfo"]["threatEntries"]] == [
            "http://bad.example/",
            "https://good.example/",
        ]
        assert out == {
            "http://bad.example/": {
                "source": "google_safe_browsing",
                "threat_types": ["SOCIAL_ENGINEERING", "MALWARE"],
                "platforms": ["ANY_PLATFORM", "WINDOWS"],
            }
        }

    def test_errors_and_exhausted_quota_mean_unavailable(self):
        assert (
            run(self.make(lambda r: httpx.Response(503)).check_batch(["http://x.example/"])) == {}
        )
        called = []
        gsb = self.make(lambda r: called.append(1) or httpx.Response(200, json={}), limit=1)
        assert run(gsb.check_batch(["http://a.example/", "http://b.example/"])) == {}
        assert not called

    def test_no_key_no_request(self):
        gsb = rep.GoogleSafeBrowsing("", rep.GsbQuota(10, 0))
        assert run(gsb.check_batch(["http://x.example/"])) == {}


class TestUrlhaus:
    def make(self, handler):
        u = rep.URLhaus()
        u._client = client_for(handler)
        return u

    def test_listed_url(self):
        def handler(request):
            assert request.content == b"url=http%3A%2F%2Fbad.example%2Fa"
            return httpx.Response(
                200, json={"query_status": "ok", "threat": "malware_download", "tags": ["exe"]}
            )

        out = run(self.make(handler).check("http://bad.example/a"))
        assert (
            out["source"] == "urlhaus"
            and out["threat"] == "malware_download"
            and out["tags"] == ["exe"]
        )

    def test_unknown_url_and_errors_are_clean(self):
        assert (
            run(
                self.make(lambda r: httpx.Response(200, json={"query_status": "no_results"})).check(
                    "http://x/"
                )
            )
            is None
        )
        assert run(self.make(lambda r: httpx.Response(500)).check("http://x/")) is None


class TestPhishTank:
    def test_feed_is_loaded_over_https_and_matches_url_and_domain(self, monkeypatch):
        requested = []

        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(200, json=[{"url": "http://evil.example/login"}, {"url": ""}])

        real = httpx.AsyncClient
        monkeypatch.setattr(
            rep.httpx,
            "AsyncClient",
            lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
        )
        pt = rep.PhishTank()
        assert run(pt.refresh()) == 1
        assert requested[0].startswith("https://")
        assert pt.check("http://evil.example/login")["match"] == "url"
        assert pt.check("http://evil.example/other")["match"] == "domain"
        assert pt.check("http://fine.example/") is None
        assert pt.stats()["phishtank_entries"] == 1

    def test_failed_download_keeps_the_previous_list(self, monkeypatch):
        real = httpx.AsyncClient
        monkeypatch.setattr(
            rep.httpx,
            "AsyncClient",
            lambda **kw: real(transport=httpx.MockTransport(lambda r: httpx.Response(500)), **kw),
        )
        pt = rep.PhishTank()
        pt._urls = {"http://old.example/"}
        assert run(pt.refresh()) == 0
        assert pt.check("http://old.example/") is not None
