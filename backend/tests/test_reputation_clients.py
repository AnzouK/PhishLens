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
            seen["key"] = request.headers.get("x-goog-api-key")
            seen["url"] = str(request.url)
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
        # never in the URL, which error messages quote
        assert "KEY" not in seen["url"]
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
            run(self.make(lambda r: httpx.Response(503)).check_batch(["http://x.example/"])) is None
        )
        called = []
        gsb = self.make(lambda r: called.append(1) or httpx.Response(200, json={}), limit=1)
        assert run(gsb.check_batch(["http://a.example/", "http://b.example/"])) is None
        assert not called

    def test_no_key_no_request(self):
        gsb = rep.GoogleSafeBrowsing("", rep.GsbQuota(10, 0))
        assert run(gsb.check_batch(["http://x.example/"])) is None


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

    def _patch(self, monkeypatch, handler):
        real = httpx.AsyncClient
        monkeypatch.setattr(
            rep.httpx,
            "AsyncClient",
            lambda **kw: real(transport=httpx.MockTransport(handler), **kw),
        )

    def test_gzip_feed_is_saved_and_loaded_after_a_restart(self, monkeypatch, tmp_path):
        import gzip

        body = gzip.compress(json.dumps([{"url": "http://evil.example/a"}]).encode())
        self._patch(monkeypatch, lambda r: httpx.Response(200, content=body))
        saved = tmp_path / "phishtank.json.gz"
        assert run(rep.PhishTank(feed_path=str(saved)).refresh()) == 1
        assert saved.exists()
        restarted = rep.PhishTank(feed_path=str(saved))
        assert restarted.load_saved() == 1
        assert restarted.check("http://evil.example/a")["match"] == "url"
        assert restarted.saved_age() < 60

    def test_a_refused_download_is_reported_in_the_stats(self, monkeypatch):
        self._patch(monkeypatch, lambda r: httpx.Response(404))
        pt = rep.PhishTank()
        assert run(pt.refresh()) == 0
        assert pt.stats()["phishtank_last_error"] == "HTTP 404"


class TestSharedHosts:
    def test_shared_hosts_match_only_the_exact_url(self):
        pt = rep.PhishTank()
        pt._urls = {"https://storage.googleapis.com/evil-bucket/login.html", "https://bit.ly/3evil"}
        pt._domains = {"storage.googleapis.com", "bit.ly", "evil-login.example"}
        assert pt.check("https://storage.googleapis.com/evil-bucket/login.html")["match"] == "url"
        assert pt.check("https://storage.googleapis.com/other-bucket/page.html") is None
        assert pt.check("https://bit.ly/45CzUKH") is None
        assert pt.check("https://evil-login.example/anything")["match"] == "domain"

    @pytest.mark.parametrize(
        ("netloc", "shared"),
        [
            ("storage.googleapis.com", True),
            ("www.bit.ly", True),
            ("ds26j.r.a.d.sendibm1.com", True),
            ("mybucket.s3.amazonaws.com", True),
            ("evil.web.app", False),
            ("kissandfly.ng", False),
            ("bit.ly.evil.example", False),
        ],
    )
    def test_shared_host_detection(self, netloc, shared):
        assert rep.is_shared_path_host(netloc) is shared
