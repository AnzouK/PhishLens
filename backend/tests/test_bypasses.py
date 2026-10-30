"""Each way found to make a phishing email look safer than it is, as the
attacker would write it, with what the checks must now conclude."""

from __future__ import annotations

import base64
import json
from pathlib import Path

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
    headers = ep.header_dict([("From", "a@b.example"), (ep.FROM_UNPROVEN, "0")])
    assert ep.FROM_UNPROVEN not in headers


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
        '"PayPal" <service@paypal.tk>',
        '"PayPal" <service@paypal.co>',
        '"Chronopost" <colis@chronopost.ml>',
        '"Impots.gouv.fr" <avis@gouv.com>',
        '"FIRS" <x@gov.com>',
        '"' + "\u200b" * 300 + 'PayPal" <x@evil.example>',
        '"Info" <x@evil.example>, "PayPal" <x@evil.example>',
        '"Chronopost" <info@chronopost.us>',
        '"PayPal" <service@paypal.vc>',
        '"GTBank" <alerts@gtbank.in>',
        '"PayPal" <service@paypal.info>',
        '"PayPal" <service@paypal.com>, <scam@evil.example>',
        '"Amel\u0131" <x@evil.example>',
        '"PayPa\u0142" <x@evil.example>',
        '"\u1d18\u1d00\u028f\u1d18\u1d00\u029f" <x@evil.example>',
        "\u1d1c\u1d18\ua731 <x@evil.example>",
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
        "Amazon <x@amazon.co.jp>",
        "PayPal <service@paypal.fr>",
        "DHL <noreply@dhl.de>",
        "GTBank <alerts@gtbank.com>",
        "Airtel <x@airtel.com.ng>",
        "Societe Generale <x@particuliers.sg.fr>",
        "service@paypal.com",
    ],
)
def test_the_brands_own_addresses_are_not_impersonation(from_):
    assert st.impersonated_brand(from_) is None


def test_a_long_invisible_padding_is_removed_before_the_name_is_cut():
    value = _from_value("x@evil.example", "\u200b" * 300 + "PayPal")
    assert st.impersonated_brand(value) == "paypal"


def test_the_rules_sender_score_uses_the_same_impersonation_check():
    assert sa.metadata_agent({"from": "Chronopost <x@qdsodd.example>"}) == pytest.approx(0.5)


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
        "font-size:0.01em",
        "font-size:0%",
        "overflow-y:hidden;max-height:0",
        "position:absolute;left:-9999px",
        "text-indent:-9999px",
        "transform:scale(0)",
        "transform:scaleY(0)",
        "transform:scale(1, 0.0)",
        "font-size:0vw",
        "font-size:0ch",
        "color:transparent;line-height:0",
        "color:rgba(0,0,0,0)",
        "color:rgb(0 0 0 / 0)",
        "color:#ffffff00",
        "color:#fff;background-color:#fff",
        "clip-path:inset(100%)",
        "clip:rect(0px, 0px, 0px, 0px)",
    ],
)
def test_hiding_styles(style):
    assert ep.is_hidden_style(style)


@pytest.mark.parametrize(
    "style",
    [
        "",
        "color:#333",
        "font-size:14px",
        "font-size:1em",
        "font-size:1vw",
        "opacity:0.9",
        "height:0",
        "left:-20px",
        "transform:scale(1.2)",
        "clip-path:inset(10%)",
        "color:#fff;background-color:#0b57d0",
    ],
)
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


def test_addresses_in_hidden_text_do_not_push_the_real_link_out():
    html = (
        '<p>Verify your account</p><a href="https://evil.example/login">here</a>'
        '<div style="display:none">'
        + " ".join(f"https://x.example/{i}" for i in range(300))
        + "</div>"
    )
    raw = b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n" + html.encode()
    _body, urls, _headers = ep.parse_eml(raw)
    assert urls[0] == "https://evil.example/login"
    links = ep.rank_links(
        ["https://evil.example/login"], [f"https://x.example/{i}" for i in range(300)]
    )
    assert links[:2] == ["https://evil.example/login", "https://x.example/0"]
    assert len(links) == 100


def test_a_second_link_to_the_same_site_stays_before_addresses_in_the_text():
    links = ep.rank_links(
        ["https://docs.google.com/document/d/1", "https://docs.google.com/forms/d/e/phish"],
        [f"https://d{i}.example/" for i in range(150)],
    )
    assert links[:2] == [
        "https://docs.google.com/document/d/1",
        "https://docs.google.com/forms/d/e/phish",
    ]
    assert len(links) == 100


def test_closed_details_and_templates_count_as_hidden():
    text = ep.html_to_text(
        "<details><summary>More</summary><p>filler words</p></details>"
        "<template><p>template words</p></template><p>Verify your account</p>"
    )
    assert text.startswith("More Verify your account")
    assert "filler words" in text and "template words" in text


def test_the_page_links_come_before_addresses_written_in_the_text():
    from extension_backend import AnalyseRequest, _resolve_email

    text = "Hello " + " ".join(f"https://x.example/{i}" for i in range(80))
    req = AnalyseRequest(
        raw_text=text, client_context={"link_urls": ["https://evil.example/login"]}
    )
    _body, urls, _h, _raw = _resolve_email(req)
    assert urls[0] == "https://evil.example/login"


def test_the_real_link_of_an_eml_is_found_behind_decoys():
    html = HIDDEN_FIRST
    raw = (
        b"From: a@b.example\r\nSubject: s\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
    ) + base64.encodebytes(html.encode())
    _body, urls, _headers = ep.parse_eml(raw)
    assert "https://evil.example/login" in urls


@pytest.mark.parametrize(
    "text",
    [
        "data:text/plain;base64,Urgent action required Verify your bank account now. Hi",
        "data:text/plain;base64,\nUrgent\naction\nrequired\nVerify\nyour\nbank\naccount\nnow. Hi",
        "data:text/plain;base64,"
        + "A" * 40
        + "\nUrgent\naction\nrequired\nVerify\nyour\nbank\nnow. Hi",
    ],
)
def test_words_after_a_data_uri_header_stay_words(text):
    # Whether or not the text is then read as source, the words stay.
    left = ep.strip_markup_noise(text)
    assert "Verify" in left and len(left.split()) >= 5


def test_inline_images_are_still_removed():
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


# ---------------------------------------------------------------------
# Authentication-Results written by several checks of one server
# ---------------------------------------------------------------------
def test_only_the_topmost_result_header_is_read():
    # On Gmail, the sender's headers come right after Gmail's own
    # Authentication-Results: a second one, wherever it sits, could be the
    # sender's, so it is never joined (docs/threat-model.md, R11).
    headers = ep.header_dict(
        [
            ("Received", "from evil by mx.google.com"),
            ("Authentication-Results", "mx.google.com; spf=pass smtp.mailfrom=evil.example"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=bank.example"),
            ("Received", "from x by y"),
            ("From", "Bank <alerts@bank.example>"),
        ]
    )
    assert "bank.example" not in headers["authentication-results"]
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_a_from_with_several_addresses_proves_nothing():
    v = verdict(
        "mx.google.com; dkim=pass header.d=paypal.com",
        from_='"PayPal" <service@paypal.com>, <scam@evil.example>',
    )
    assert not v.cryptographically_verified


# ---------------------------------------------------------------------
# HTML attachments
# ---------------------------------------------------------------------
def test_an_html_attachment_reports_where_it_sends_first():
    import attachment_analysis as aa

    html = (
        "".join(f'<img src="https://cdn.example/{i}.png" hidden>' for i in range(300))
        + '<meta http-equiv="refresh" content="0; url=//evil.example/a">'
        + '<form action="https://evil.example/post"><input type="password"></form>'
    )
    out = aa.analyse_html(html.encode(), "invoice.html")
    urls = out["extracted_urls"]
    assert urls[0] == "https://evil.example/post"
    assert "https://evil.example/a" in urls


@pytest.mark.parametrize(
    "html",
    ['<img src=x onerror="go()">', '<a href=" javascript:go()">x</a>', "<body onfocus=go()>"],
)
def test_any_script_counts_as_javascript(html):
    import attachment_analysis as aa

    assert "contains_javascript" in aa.analyse_html(html.encode(), "a.html")["notable_features"]


def test_a_page_inside_an_iframe_srcdoc_is_read():
    import attachment_analysis as aa

    html = (
        '<iframe srcdoc="<form action=&quot;https://evil.example/login&quot;>'
        '<input type=password></form><script>go()</script>"></iframe>'
    )
    out = aa.analyse_html(html.encode(), "a.html")
    assert out["extracted_urls"] == ["https://evil.example/login"]
    assert {"contains_form", "contains_password_field", "contains_javascript"} <= set(
        out["notable_features"]
    )


# ---------------------------------------------------------------------
# Spamhaus
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("answer", "listed"),
    [("127.0.1.4", "phish"), ("127.0.1.99", "listed_unknown_code"), ("127.255.255.254", None)],
)
def test_spamhaus_answers(monkeypatch, answer, listed):
    import asyncio

    monkeypatch.setattr(ah.socket, "gethostbyname", lambda _q: answer)
    out = asyncio.run(ah.spamhaus_dbl("evil.example"))
    assert (out or {}).get("category") == listed


# ---------------------------------------------------------------------
# Shared with the extension: tests/fixtures/hidden_cases.json
# ---------------------------------------------------------------------
_HIDDEN_CASES = json.loads(
    (Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "hidden_cases.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", _HIDDEN_CASES, ids=[c["name"] for c in _HIDDEN_CASES])
def test_hidden_cases_shared_with_the_extension(case):
    assert ep.is_hidden_style(case["style"]) is case["hidden"]


# ---------------------------------------------------------------------
# Round 7
# ---------------------------------------------------------------------
def test_hidden_links_never_pass_a_second_visible_link_to_the_same_site():
    html = (
        '<a href="https://docs.google.com/document/d/1">Rules</a>'
        '<a href="https://docs.google.com/forms/d/e/phish">Verify</a>'
        '<div style="display:none">'
        + "".join(f'<a href="https://d{i}.example/">x</a>' for i in range(150))
        + "</div>"
    )
    raw = b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n" + html.encode()
    _body, urls, _h = ep.parse_eml(raw)
    assert urls[:2] == [
        "https://docs.google.com/document/d/1",
        "https://docs.google.com/forms/d/e/phish",
    ]
    # and a later ranking keeps that order (Safe Browsing gets the first 30)
    again = ep.rank_links([], urls, [])
    assert again[:2] == urls[:2]


def test_the_pages_hidden_links_come_after_its_visible_ones():
    from extension_backend import AnalyseRequest, _resolve_email

    req = AnalyseRequest(
        raw_text="Please verify your account today",
        client_context={
            "link_urls": ["https://docs.google.com/a", "https://docs.google.com/phish"],
            "hidden_link_urls": [f"https://d{i}.example/" for i in range(50)],
        },
    )
    _body, urls, _h, _raw = _resolve_email(req)
    assert urls[:2] == ["https://docs.google.com/a", "https://docs.google.com/phish"]


def test_words_after_an_unclosed_angle_bracket_stay_words():
    text = "Hi <a Urgent: your bank account is suspended, verify your password at our portal"
    assert ep.strip_markup_noise(text) == text
    assert not ep.looks_like_source(text)
    assert ep.strip_markup_noise('<div class="x"><p>Hello</p></div>') == "Hello"


def test_a_long_base64_run_does_not_make_the_server_drop_the_page_text():
    from extension_backend import AnalyseRequest, _resolve_email

    eml = (
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n<p>" + b"benign words " * 50 + b"</p>"
    )
    page = "Verify your bank account now please " + "A" * 3000
    req = AnalyseRequest(raw_email_b64=base64.b64encode(eml).decode(), raw_text=page)
    body, _u, _h, _raw = _resolve_email(req)
    assert body.startswith("Verify your bank account")


def test_html_source_shown_as_text_still_gives_way_to_the_original():
    source = (
        "<html><body>"
        + "".join(f'<div class="c{i}"><p>x</p></div>' for i in range(10))
        + "</body></html>"
    )
    assert ep.is_page_source(source)


def test_spaces_cannot_push_the_address_past_what_the_checks_read():
    headers = ep.header_dict([("From", '"PayPal' + " " * 3000 + '" <scam@evil.example>')])
    assert st.impersonated_brand(headers["from"]) == "paypal"
    headers = ep.header_dict(
        [
            ("From", '"PayPal" <service@paypal.com>' + " " * 3000 + ", <scam@evil.example>"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert not ah.parse_authentication_results(headers).cryptographically_verified
    long_from = ep.header_dict([("From", "x" * 9000 + "@a.example")])
    assert ep.FROM_UNPROVEN in long_from


def test_an_attached_email_proves_nothing_about_its_sender():
    from extension_backend import AnalyseRequest, _resolve_email

    eml = (
        b"From: GTBank <alerts@gtbank.com>\r\n"
        b"Authentication-Results: mx.google.com; dkim=pass header.i=@gtbank.com; "
        b"dmarc=pass header.from=gtbank.com\r\n\r\nYour account statement is ready."
    )
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        client_context={"headers_source": "attachment"},
    )
    _body, _u, headers, _raw = _resolve_email(req)
    assert "authentication-results" not in headers


def test_text_directly_inside_a_closed_details_is_hidden():
    text = ep.html_to_text(
        "<details><summary>Info</summary>benign words here</details><p>Verify your account</p>"
    )
    assert text.startswith("Info Verify your account")


@pytest.mark.parametrize(
    "html",
    [
        '<form><button formaction="https://evil.example/login">Sign in</button></form>',
        '<iframe src="data:text/html;base64,'
        + base64.b64encode(b'<form action="https://evil.example/login"></form>').decode()
        + '"></iframe>',
        '<meta http-equiv="refresh" content="0;url=data:text/html,'
        '%3Cform%20action%3D%22https%3A%2F%2Fevil.example%2Flogin%22%3E%3C%2Fform%3E">',
        '<object data="data:text/html,%3Ca%20href%3D%22https%3A%2F%2Fevil.example%2Flogin%22%3Ex%3C%2Fa%3E"></object>',
    ],
)
def test_html_attachments_reveal_targets_in_formaction_and_data_pages(html):
    import attachment_analysis as aa

    assert (
        "https://evil.example/login" in aa.analyse_html(html.encode(), "a.html")["extracted_urls"]
    )
