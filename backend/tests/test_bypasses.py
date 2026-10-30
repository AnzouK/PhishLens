"""Each way found to make a phishing email look safer than it is, as the
attacker would write it, with what the checks must now conclude."""

from __future__ import annotations

import base64

import pytest

import auth_headers as ah
import email_parsing as ep
import link_alignment as la
import sender_trust as st
import structured_agents as sa
from extension_backend import _from_value

# ---------------------------------------------------------------------
# Authentication-Results
# ---------------------------------------------------------------------
QUOTED_LOCAL_PART = (
    'mx.google.com; spf=pass (google.com: domain of "dkim=pass header.i=@paypal.com "'
    "@attacker.example designates 192.0.2.1 as permitted sender) "
    'smtp.mailfrom="dkim=pass header.i=@paypal.com "@attacker.example; '
    "dkim=fail header.i=@paypal.com"
)


def verdict(ar: str, from_: str = "service@paypal.com", **extra) -> ah.AuthVerdict:
    return ah.parse_authentication_results({"from": from_, "authentication-results": ar, **extra})


def test_a_result_inside_a_quoted_address_or_a_comment_is_not_a_result():
    v = verdict(QUOTED_LOCAL_PART)
    assert v.dkim == "fail"
    assert v.spf_domain == "attacker.example"
    assert not v.cryptographically_verified


def test_a_result_must_start_its_clause():
    v = verdict(
        "mx.example; spf=pass smtp.mailfrom=x@attacker.example dkim=pass header.d=paypal.com"
    )
    assert v.dkim == "none"
    assert not v.cryptographically_verified


def test_microsoft_365_results_without_a_server_name_still_read():
    ar = (
        "spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=contoso.com; dkim=pass "
        "(signature was verified) header.d=contoso.com;dmarc=pass action=none "
        "header.from=contoso.com;compauth=pass reason=100"
    )
    v = verdict(ar, from_="a@contoso.com")
    assert (v.spf, v.dkim, v.dmarc) == ("pass", "pass", "pass")
    assert v.cryptographically_verified


def test_arc_results_alone_prove_nothing():
    v = ah.parse_authentication_results(
        {
            "from": "service@paypal.com",
            "arc-authentication-results": "i=1; mx.google.com; dkim=pass header.d=paypal.com",
        }
    )
    assert v.header_present and v.dkim == "pass"
    assert not v.cryptographically_verified and not v.aligned


def test_two_from_headers_keep_the_first_and_prove_nothing():
    headers = ep.header_dict(
        [
            ("From", "PayPal <service@paypal.com>"),
            ("From", "x@attacker.example"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert headers["from"] == "PayPal <service@paypal.com>"
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_the_message_cannot_name_the_duplicate_marker_itself():
    headers = ep.header_dict([("From", "a@b.example"), (ep.DUPLICATE_FROM, "0")])
    assert ep.DUPLICATE_FROM not in headers


def test_encoded_words_are_decoded_in_the_lenient_parser_too():
    assert ep.header_dict([("From", "=?utf-8?b?UGF5UGFs?= <a@evil.example>")])["from"] == (
        "PayPal <a@evil.example>"
    )


def test_gmail_values_that_are_not_host_names_are_dropped():
    ctx = {"origin": "gmail", "gmail_signed_by": "paypal.com; dmarc=pass header.from=paypal.com"}
    assert st.synthesize_auth_results(ctx, "a@paypal.com") == ""
    ctx = {"origin": "gmail", "gmail_signed_by": "paypal.com"}
    v = verdict(st.synthesize_auth_results(ctx, "a@paypal.com"), from_="a@paypal.com")
    assert v.cryptographically_verified and v.dmarc == "pass"


# ---------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "from_",
    [
        '"PayPal" <service@paypal.xyz>',
        '"PayPal" <service@paypal.duckdns.org>',
        '"E.Leclerc" <info@e.xyz>',
        '"Chrono​post" <x@evil.example>',
        '"Chrono­post" <x@evil.example>',
        '"Chronopost' + " " * 600 + '" <x@evil.example>',
        '"PаyPаl" <x@evil.example>',
        '"DНL" <x@evil.example>',
        '"PayPal\\" <x@evil.example>',
        "PayPal <x@evil.example> <service@paypal.com>",
    ],
)
def test_impersonation_variants_are_caught(from_):
    assert st.impersonated_brand(from_)


@pytest.mark.parametrize(
    "from_",
    [
        "PayPal <service@paypal.com>",
        "PayPal <service@mail.paypal.co.uk>",
        "PayPal <service@paypal.de>",
        "E.Leclerc <info@e.leclerc>",
        "BNP Paribas <x@mabanque.bnpparibas>",
        "Impots <x@dgfip.finances.gouv.fr>",
        "service@paypal.com",
    ],
)
def test_the_brands_own_addresses_are_not_impersonation(from_):
    assert st.impersonated_brand(from_) is None


def test_a_name_ending_in_a_backslash_keeps_its_quotes():
    value = _from_value("x@evil.example", "PayPal\\")
    assert st.impersonated_brand(value) == "paypal"
    assert st.sender_domain(value) == "evil.example"


# ---------------------------------------------------------------------
# Hidden text and links
# ---------------------------------------------------------------------
HIDDEN_FIRST = (
    '<div style="font-size:0;max-height:0;overflow:hidden;opacity:0">'
    + "minutes of the meeting " * 60
    + "</div><p>Verify your account now</p>"
    + '<div style="display:none">'
    + "".join(f'<a href="https://www.google.com/{i}">g</a>' for i in range(60))
    + "</div>"
    + '<a href = "https://evil.example/login">Verify</a>'
    + '<a href="&#104;ttps://evil2.example/">x</a>'
    + '<a href="//evil3.example/">y</a>'
)


def test_hidden_text_comes_after_the_visible_text():
    text = ep.html_to_text(HIDDEN_FIRST)
    assert text.startswith("Verify your account now")
    assert "minutes of the meeting" in text


@pytest.mark.parametrize(
    "style",
    [
        "display:none",
        "visibility:hidden",
        "opacity:0",
        "font-size:0px",
        "font-size:1px",
        "max-height:0;overflow:hidden",
        "DISPLAY: NONE !important",
    ],
)
def test_hiding_styles(style):
    assert ep.is_hidden_style(style)


@pytest.mark.parametrize("style", ["", "color:#333", "font-size:14px", "opacity:0.9", "height:0"])
def test_visible_styles(style):
    assert not ep.is_hidden_style(style)


def test_links_are_read_as_a_browser_reads_them_visible_first():
    links = ep.html_links(HIDDEN_FIRST)
    assert links[:3] == [
        "https://evil.example/login",
        "https://evil2.example/",
        "https://evil3.example/",
    ]
    assert "https://www.google.com/0" in links


def test_the_real_link_of_an_eml_is_found_behind_decoys():
    html = HIDDEN_FIRST
    raw = (
        b"From: a@b.example\r\nSubject: s\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
    ) + base64.encodebytes(html.encode())
    _body, urls, _headers = ep.parse_eml(raw)
    assert "https://evil.example/login" in urls


def test_words_after_a_data_uri_header_stay_words():
    text = "data:text/plain;base64,Urgent action required Verify your bank account now. Hi"
    assert "Verify your bank account" in ep.strip_markup_noise(text)
    assert not ep.looks_like_source(text)
    # a real inline image is still removed
    assert ep.strip_markup_noise("a data:image/png;base64," + "A" * 300 + " b") == "a b"


# ---------------------------------------------------------------------
# Link rules
# ---------------------------------------------------------------------
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


# ---------------------------------------------------------------------
# Server state
# ---------------------------------------------------------------------
def test_a_shorter_ttl_wins(monkeypatch):
    import result_cache

    now = [1000.0]
    monkeypatch.setattr(result_cache.time, "monotonic", lambda: now[0])
    cache = result_cache.ResultCache(ttl=86400, max_entries=10)
    cache.set("k", {"verdict": "safe"}, ttl=3600)
    now[0] += 3601
    assert cache.get("k") is None


def test_report_fields_other_than_the_text_are_identifiers():
    from pydantic import ValidationError

    from feedback import FeedbackRequest

    FeedbackRequest(kind="false_negative", text="a b c", source="gmail", version="2.0.11")
    with pytest.raises(ValidationError):
        FeedbackRequest(kind="false_negative", text="a b c", source="Call +234 800 000 0000")
