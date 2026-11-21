"""Bypasses of the link rules: how a URL is read, known sites and their
redirects, threat-intelligence matching and the URL model."""

from __future__ import annotations

import pytest

import email_parsing as ep
import link_alignment as la
import reputation as rep
import structured_agents as sa


@pytest.mark.parametrize(
    "url",
    [
        "https://evil-login.tk?user=1",
        "https://evil.tk#login",
        "http://192.168.1.1?login",
        "http://3232235777/login",
        "http://0xC0A80101/login",
        "https://xn--pypal-4ve.com/login",
        "https://pаypal.com/login",
        "https://paypal.com:443@evil.example/",
    ],
)
def test_strong_link_signs_survive_url_tricks(url):
    assert sa.strong_link_sign([url])


def test_a_known_sites_redirect_is_not_a_known_link():
    for url in (
        "https://www.youtube.com/redirect?q=https://evil.example/login",
        "https://www.youtube.com/redirect?q=https%3A%2F%2Fevil.example",
        "https://www.youtube.com/redirect?q=https%253A%252F%252Fevil.example",
        "https://www.youtube.com/redirect?q=//evil.example/login",
        "https://www.youtube.com/redirect?q=%2f%2fevil.example",
    ):
        assert not la.well_known_link(url)
        counts = la.link_profile([url], "Bank <a@signed.example>")
        assert counts["well_known"] == 0 and counts["other"] == 1
        assert la.links_elsewhere_only(counts)
    assert la.well_known_link("https://www.youtube.com/watch?v=abc")


def test_ip_hosts():
    for host in ("192.168.1.1", "3232235777", "0xc0a80101", "::1", "10.1"):
        assert la.ip_host(host)
    for host in ("example.com", "1.example", ""):
        assert not la.ip_host(host)


@pytest.mark.parametrize(
    ("href", "url", "host"),
    [
        ("https://evil.tk\\@paypal.com/", "https://evil.tk/@paypal.com/", "evil.tk"),
        ("HTTPS:evil.tk/login", "https://evil.tk/login", "evil.tk"),
        ("https:\\\\evil.tk", "https://evil.tk", "evil.tk"),
        ("https://%65vil.tk/x", "https://evil.tk/x", "evil.tk"),
        ("https://evil。tk/", "https://evil.tk/", "evil.tk"),
        ("https://ＰＡＹＰＡＬ.com/", "https://paypal.com/", "paypal.com"),
        ("https://a.example/?q=1#f", "https://a.example/?q=1#f", "a.example"),
    ],
)
def test_links_are_read_as_browsers_read_them(href, url, host):
    assert ep.absolute_http(href) == url
    assert la.link_host(href) == host


def test_capitalised_and_www_addresses_are_links():
    assert ep.urls_in_text("see HTTPS://EVIL.tk/login, and www.evil.tk/x.") == [
        "https://evil.tk/login",
        "http://www.evil.tk/x",
    ]


@pytest.mark.parametrize(
    ("href", "host"),
    [
        ("https://evil.tk./login", "evil.tk"),
        ("https://storage.googleapis.com./b/x.html", "storage.googleapis.com"),
        ("http://192.168.1.1./login", "192.168.1.1"),
        ("https://u[@evil.tk/login", "evil.tk"),
        ("https://a.example:/x", "a.example"),
        ("http://[::1]:8080/x", "::1"),
    ],
)
def test_hosts_with_final_dot_brackets_empty_port(href, host):
    assert la.link_host(href) == host


def test_final_dots_and_brackets_keep_every_link_rule():
    assert sa.strong_link_sign(["https://evil.tk./login"])
    assert la.on_cloud_file_host("https://storage.googleapis.com./b/x.html")
    assert la.ip_host("192.168.1.1.")
    counts = la.link_profile(["https://u[@evil.tk/login"], "Bank <a@bank.example>")
    assert counts["other"] == 1


@pytest.mark.parametrize("href", ["https://evil.tk%40paypal.com/", "https://evil.tk＠paypal.com/"])
def test_host_decoding_to_at_sign_not_paypal(href):
    assert la.link_host(href) != "paypal.com"
    assert la.link_profile([href], "PayPal <service@paypal.com>")["aligned"] == 0


def test_phishtank_domains_are_matched_by_host():
    pt = rep.PhishTank()
    pt._load([{"url": "https://phish.example/login"}])
    for url in (
        "https://user@phish.example/x",
        "https://phish.example:8443/x",
        "https://phish.example./x",
    ):
        assert pt.check(url), url


@pytest.mark.parametrize(
    "url", ["https://evil.example/login#.css", "https://evil.example/login.css?id=1"]
)
def test_css_looking_link_counts_for_link_rule(url):
    counts = la.link_profile([url], "Bank <alerts@signed.example>")
    assert counts["other"] == 1
    assert la.links_elsewhere_only(counts)


def test_brackets_around_text_address_excluded():
    assert ep.urls_in_text("Verify at [https://evil.tk] or {https://e2.tk}.") == [
        "https://evil.tk",
        "https://e2.tk",
    ]
    assert la.link_host("https://evil.tk%3a80/") != "evil.tk"


@pytest.mark.parametrize(
    "href", ["https://℅@evil.tk#@paypal.com", "https://℅@evil.tk?x=@paypal.com"]
)
def test_unparsable_user_part_keeps_host(href):
    assert la.link_host(href) == "evil.tk"
    assert not la.well_known_link(href)
    assert sa.strong_link_sign([href])


def test_capitalised_address_counts_as_written():
    body = "Verify at HTTPS://Evil.Example/login now"
    urls = ep.urls_in_text(body)
    written = set(ep.urls_in_text(body))
    assert urls[0] in written


def test_invisible_char_in_host_read_as_browser_opens():
    assert ep.urls_in_text("go to https://evil​.tk/login") == ["https://evil.tk/login"]


def test_the_url_model_reads_the_links_as_read():
    seen = {}

    class Fx:
        def extract_url_features(self, text):
            seen["text"] = text
            return {}

    class Agent:
        def get_prediction_with_confidence(self, feats):
            return {"phishing_probability": 0.9}

    old = sa._FEATURE_EXTRACT, sa._URL_AGENT
    sa._FEATURE_EXTRACT, sa._URL_AGENT = Fx(), Agent()
    try:
        body = "See https://google.com and verify at HTTPS://192.168.1.1/login or www.evil.tk/x"
        sa.url_agent(ep.urls_in_text(body), body_text=body)
    finally:
        sa._FEATURE_EXTRACT, sa._URL_AGENT = old
    assert "https://192.168.1.1/login" in seen["text"]
    assert "http://www.evil.tk/x" in seen["text"]


@pytest.mark.parametrize(
    "url",
    [
        "https://www.youtube.com/redirect?q=+//evil.example/login",
        "https://www.youtube.com/redirect?q=%20//evil.example/login",
        "https://www.youtube.com/redirect?q=https:/evil.example/login",
        "https://www.youtube.com/redirect?q=https:evil.example/login",
        "https://www.youtube.com/redirect?q=https%253A%252F%252Fevil.example",
        "https://www.google.com/amp/s/evil.example/login",
    ],
)
def test_open_redirects_of_known_sites_in_any_form(url):
    assert not la.well_known_link(url)


def test_the_url_model_never_lowers_the_rules(monkeypatch):
    class Low:
        @staticmethod
        def get_prediction_with_confidence(_feats):
            return {"phishing_probability": 0.01}

    class Feats:
        @staticmethod
        def extract_url_features(_text):
            return {}

    monkeypatch.setattr(sa, "_URL_AGENT", Low)
    monkeypatch.setattr(sa, "_FEATURE_EXTRACT", Feats)
    url = "http://3232235777/login"
    assert sa.url_agent([url], body_text=f"Open {url}") >= sa.url_heuristic([url])


@pytest.mark.parametrize(
    "url",
    [
        "https://forms.office.com/r/abc",
        "https://onedrive.live.com/redir?resid=1",
        "https://contoso.sharepoint.com/:b:/g/x",
        "https://docs.google.com/forms/d/e/x/viewform",
        "https://www.youtube.com/redirect?q=www.evil.example/login",
    ],
)
def test_public_pages_on_known_sites_not_known(url):
    assert not la.well_known_link(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.youtube.com/watch?v=abc",
        "https://www.office.com/",
        "https://www.linkedin.com/in/x?trk=www",
    ],
)
def test_known_sites_stay_known(url):
    assert la.well_known_link(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.youtube.com/redirect?q=evil.tk/login",
        "https://l.facebook.com/l.php?u=x",
        "https://www.icloud.com/iclouddrive/0123#Invoice",
    ],
)
def test_redirect_and_share_paths_of_known_sites(url):
    assert not la.well_known_link(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.youtube.com/./redirect?q=evil.tk",
        "https://www.youtube.com/a/../redirect?q=evil.tk",
        "https://www.youtube.com/%2e/redirect?q=evil.tk",
        "https://www.icloud.com/./iclouddrive/0123",
    ],
)
def test_dot_segments_do_not_hide_a_redirect_path(url):
    assert not la.well_known_link(url)


def test_dot_segments_do_not_hide_a_shared_form():
    assert ep.detect_shared_links(["https://docs.google.com/./forms/d/e/x/viewform"])["count"] == 1


def test_empty_segments_do_not_absorb_dot_dot():
    assert la.browser_path("/a/%2f../redirect") == "/redirect"
    assert not la.well_known_link("https://www.youtube.com/a/%2f../redirect?q=evil.tk")
    assert ep.detect_shared_links(["https://docs.google.com//forms/d/e/x/viewform"])["count"] == 1
