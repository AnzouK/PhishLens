"""Each way found to make a phishing email look safer than it is, as the
attacker would write it, with what the checks must now conclude."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

import auth_headers as ah
import email_parsing as ep
import hidden_content as hc
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
    assert hc.is_hidden_style(style)


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
    assert not hc.is_hidden_style(style)


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
    assert " ".join(text.split()).startswith("More Verify your account")
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
    parent = case.get("parentBackground")
    background = hc.parse_colour(parent) if parent else None
    assert hc.is_hidden_style(case["style"], background) is case["hidden"]


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


# ---------------------------------------------------------------------
# Round 8
# ---------------------------------------------------------------------
def test_an_unclosed_tag_before_a_link_with_a_query_keeps_the_text():
    text = (
        "Hi <a Urgent: your bank account is suspended, verify your password "
        "immediately at https://evil.example/login?id=1"
    )
    assert ep.strip_markup_noise(text) == text


@pytest.mark.parametrize(
    ("html", "left"),
    [
        ('<div class="x" hidden><p>Hello</p><br /><img src="a" /></div>', "Hello"),
        ("<table border=0 cellpadding='0'><tr><td>Hi</td></tr></table>", "Hi"),
        ('<img src="data:image/png;base64,AAAA', ""),
    ],
)
def test_real_markup_is_still_removed(html, left):
    assert ep.strip_markup_noise(html) == left


def test_a_few_tags_in_a_noisy_text_do_not_make_it_source():
    noisy = "benign words " * 20 + "&lt;a&gt; <a> <a> <a> <a> <a> " + "A" * 2000
    assert not ep.is_page_source(noisy)
    image_source = (
        '<div style="width: 100%"><img src="data:image/jpeg;base64,' + "QUJD" * 600 + '"></div>'
    )
    assert ep.is_page_source(image_source)


def test_a_style_sheet_rule_hides_text_in_the_parsed_message():
    text = ep.html_to_text(
        "<style>.h{display:none} @media (max-width:600px){.h{display:block}}</style>"
        '<div class="h">' + "minutes of the meeting " * 30 + "</div><p>Verify your account</p>"
    )
    assert text.startswith("Verify your account")


def test_white_text_on_a_white_parent_is_hidden_unless_a_sheet_paints_it():
    hidden = ep.html_to_text(
        '<div style="background-color:#ffffff"><span style="color:#fefefe">filler</span></div>'
        "<p>Verify</p>"
    )
    assert hidden.startswith("Verify")
    banner = ep.html_to_text(
        "<style>.top{background:#0b57d0}</style>"
        '<div class="top"><span style="color:#ffffff">Your order</span></div><p>Thanks</p>'
    )
    assert banner.startswith("Your order")


@pytest.mark.parametrize(
    "src",
    [
        "data:text/html,<form action='https://evil.example/login'><input type='password'></form>",
        "data:text/html;charset=utf-8;base64,"
        + base64.b64encode(b"<form action='https://evil.example/login'></form>").decode(),
        "data:application/xhtml+xml;base64,"
        + base64.b64encode(b"<form action='https://evil.example/login'></form>").decode(),
    ],
)
def test_data_pages_with_spaces_or_parameters_are_read(src):
    import attachment_analysis as aa

    out = aa.analyse_html(f'<iframe src="{src}"></iframe>'.encode(), "a.html")
    assert "https://evil.example/login" in out["extracted_urls"]
    assert "contains_form" in out["notable_features"]


@pytest.mark.parametrize("padding", [" " * 32_000, "​" * 9_000])
def test_padding_cannot_cut_the_second_address_of_a_from(padding):
    headers = ep.header_dict(
        [
            ("From", '"PayPal" <service@paypal.com>' + padding + ", <scam@evil.example>"),
            ("Authentication-Results", "mx.google.com; dkim=pass header.d=paypal.com"),
        ]
    )
    assert "scam@evil.example" in headers["from"]
    assert st.impersonated_brand(headers["from"]) == "paypal"
    assert not ah.parse_authentication_results(headers).cryptographically_verified


def test_the_messages_visible_links_come_before_the_pages_hidden_ones():
    from extension_backend import AnalyseRequest, _resolve_email

    eml = (
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="https://evil.example/login">Verify</a>'
    )
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        client_context={"hidden_link_urls": [f"https://d{i}.example/" for i in range(50)]},
    )
    _body, urls, _h, _raw = _resolve_email(req)
    assert urls[0] == "https://evil.example/login"


# ---------------------------------------------------------------------
# Round 9
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("html", "first"),
    [
        # legitimate: never hidden
        (
            '<style>.btn{background-color:#0b57d0}</style><a class="btn" style="color:#ffffff">Open</a><p>Hi</p>',
            "Open",
        ),
        (
            '<table><tr><td bgcolor="#0b57d0" style="color:#ffffff">Statement</td></tr></table><p>Hi</p>',
            "Statement",
        ),
        (
            '<style>body{background:#111}</style><body><p style="color:#fff">Dark</p><p>Hi</p></body>',
            "Dark",
        ),
        (
            '<div style="background-color:rgba(0,0,0,0.06);color:#000">Grey box</div><p>Hi</p>',
            "Grey box",
        ),
        # hiding: moved last
        (
            '<style>@charset "utf-8"; .h{display:none}</style><div class="h">filler</div><p>Hi</p>',
            "Hi",
        ),
        ('<style>.h{color:#ffffff}</style><div class="h">filler</div><p>Hi</p>', "Hi"),
        (
            '<style>.h{max-height:0} .h{overflow:hidden}</style><div class="h">filler</div><p>Hi</p>',
            "Hi",
        ),
        (
            '<style>@media screen{.h{display:none}}</style><div class="h">filler</div><p>Hi</p>',
            "Hi",
        ),
        ('<div style="background-color:rgba(0,0,0,0.06);color:#fff">filler</div><p>Hi</p>', "Hi"),
        (
            '<div style="color:#fff;background:#000"><span style="background:#fff">filler</span></div><p>Hi</p>',
            "Hi",
        ),
    ],
)
def test_style_cascade_and_backgrounds(html, first):
    assert ep.html_to_text(html).startswith(first)


def test_a_phone_rule_is_not_applied():
    text = ep.html_to_text(
        '<style>@media (max-width:600px){.m{display:none}}</style><div class="m">Desktop</div><p>Hi</p>'
    )
    assert text.startswith("Desktop")


@pytest.mark.parametrize(
    "text",
    [
        'Hi <a x="Urgent: your bank account is suspended, verify at https://evil.example/login?id=1',
        "Hi <a Urgent: your bank account is suspended. Verify your password at=https://evil.example/?id=1",
    ],
)
def test_sentences_that_look_like_attributes_stay_words(text):
    assert ep.strip_markup_noise(text) == text


def test_one_long_pseudo_tag_does_not_make_a_text_source():
    assert not ep.is_page_source("benign " * 5 + '<div a="' + "A" * 1990 + '">')


def test_a_link_the_browser_saw_hidden_stays_hidden():
    from extension_backend import AnalyseRequest, _resolve_email

    eml = (
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n"
        b'<a href="https://pixel.example/1"><img width=1 height=1></a>'
        b'<a href="https://evil.example/login">Verify</a>'
    )
    req = AnalyseRequest(
        raw_email_b64=base64.b64encode(eml).decode(),
        client_context={
            "link_urls": ["https://evil.example/login"],
            "hidden_link_urls": ["https://pixel.example/1"],
        },
    )
    _body, urls, _h, _raw = _resolve_email(req)
    assert urls == ["https://evil.example/login", "https://pixel.example/1"]


@pytest.mark.parametrize(
    ("value", "rgb"),
    [
        ("rgb(100%, 100%, 100%)", (255, 255, 255)),
        ("hsl(0, 0%, 100%)", (255, 255, 255)),
        ("hsla(240, 100%, 50%, 0.5)", (0, 0, 255)),
        ("rgb(0 0 0 / 0.5)", (0, 0, 0)),
        ("#0b57d0", (11, 87, 208)),
    ],
)
def test_colours_parse(value, rgb):
    assert hc.parse_colour(value)[:3] == rgb


# ---------------------------------------------------------------------
# Round 10
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("html", "first"),
    [
        # legitimate: a dark section whose children set a light colour
        (
            '<p>Hello,</p><div style="background:#111"><p style="color:#fff">Your statement</p>'
            '<a href="https://bank.example/login" style="color:#fff">Open</a></div><p>Footer</p>',
            "Hello, Your statement Open Footer",
        ),
        (
            '<style>.dark{background:#111}</style><div class="dark"><p style="color:#fff">Dark</p></div><p>Hi</p>',
            "Dark Hi",
        ),
        (
            '<a style="background: no-repeat center #0b57d0; color:#ffffff">One</a>'
            '<a style="background: rgb(11, 87, 208) no-repeat; color:#fff">Two</a>'
            '<a style="background: linear-gradient(#0b57d0,#003399); color:#fff">Three</a><p>Hi</p>',
            "One Two Three Hi",
        ),
        (
            '<div style="visibility:hidden">filler<p style="visibility:visible">Shown</p></div><p>Hi</p>',
            "Shown Hi",
        ),
        # hiding
        (
            '<div style="background:#111">filler<p style="color:#fff">Dark</p></div><p>Hi</p>',
            "Dark Hi",
        ),
        (
            '<style>.h{display:none !important}</style><div class="h" style="display:block">x</div><p>Hi</p>',
            "Hi",
        ),
        ('<div style="display:/*x*/none">x</div><p>Hi</p>', "Hi"),
        ('<font color="#ffffff">x</font><p>Hi</p>', "Hi"),
    ],
)
def test_text_level_and_box_level_hiding(html, first):
    text = ep.html_to_text(html)
    # Lines now follow the page's blocks: compare the words in order.
    assert " ".join(text.split()).startswith(first)


def test_links_that_show_nothing_count_as_hidden():
    visible, hidden = ep.html_link_groups(
        '<a href="https://d0.example/"><span style="opacity:0">Click</span></a>'
        '<a href="https://d1.example/"></a>'
        '<a href="https://d2.example/"><img width="1" height="1"></a>'
        '<a href="https://shop.example/"><img src="banner.png"></a>'
        '<a href="https://evil.example/">Verify</a>'
    )
    assert visible == ["https://shop.example/", "https://evil.example/"]
    assert hidden == ["https://d0.example/", "https://d1.example/", "https://d2.example/"]


def test_a_sentence_after_a_closed_quote_without_a_bracket_stays_words():
    text = (
        'Hi <a x="Urgent: your bank account is suspended, verify your password '
        'immediately at https://evil.example/login?id=1"'
    )
    assert ep.strip_markup_noise(text) == text


def test_a_short_text_with_two_tags_is_not_source():
    assert not ep.is_page_source('<p><div a="' + "A" * 1990 + '">')
    assert not ep.is_page_source("Hello " + "<b>x</b>" * 3)


# ---------------------------------------------------------------------
# Round 11
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "decoy",
    [
        '<a href="https://d0.example/" style="visibility:hidden"><svg width="10" height="10"></svg></a>',
        '<a href="https://d0.example/"><img src="x.png" width="10" height="10" style="visibility:hidden"></a>',
        '<a href="https://d0.example/"><img src="x.png" style="width:1px;height:1px"></a>',
        '<a href="https://d0.example/"><!-- x --></a>',
        '<a href="https://d0.example/"><style>.x{}</style></a>',
    ],
)
def test_links_showing_nothing_visible_are_hidden(decoy):
    visible, hidden = ep.html_link_groups(decoy + '<a href="https://evil.example/">Verify</a>')
    assert visible == ["https://evil.example/"]
    assert hidden == ["https://d0.example/"]


@pytest.mark.parametrize(
    ("html", "first"),
    [
        # hiding
        (
            '<div style="background:linear-gradient(#fff,#fff);color:transparent">filler</div><p>Hi</p>',
            "Hi",
        ),
        (
            '<div style="color:transparent"><span style="background:#000">filler</span></div><p>Hi</p>',
            "Hi",
        ),
        ('<p style="color:ivory">filler</p><p>Hi</p>', "Hi"),
        ('<div style="display: none ! important">filler</div><p>Hi</p>', "Hi"),
        ("<details><summary>One</summary><summary>filler</summary></details><p>Hi</p>", "One Hi"),
        # legitimate
        ('<a style="background-color:navy;color:#fff">Sign in</a><p>Hi</p>', "Sign in Hi"),
        ('<td bgcolor="0b57d0" style="color:#fff">Statement</td><p>Hi</p>', "Statement Hi"),
        (
            '<a style="background:#fff;background-color:#0b57d0;color:#fff">Open</a><p>Hi</p>',
            "Open Hi",
        ),
        (
            '<style>.b{background:#fff}</style><a class="b" style="background-color:#0b57d0;color:#fff">Go</a>',
            "Go",
        ),
        ('<a style="background-color:var(--brand);color:#fff">Brand</a><p>Hi</p>', "Brand Hi"),
    ],
)
def test_round_11_hiding_and_legitimate_styles(html, first):
    assert " ".join(ep.html_to_text(html).split()).startswith(first)


def test_a_quoted_sentence_is_not_an_attribute_even_with_a_closing_bracket():
    text = (
        'Hi <a x="Urgent: your bank account is suspended, verify your password '
        'immediately at https://evil.example/login?id=1">'
    )
    assert ep.strip_markup_noise(text) == text
    # a real style value stays markup
    assert (
        ep.strip_markup_noise(
            '<td style="width: 100%; max-width: 600px; margin: 0 auto; padding: 0 10px">x'
        )
        == "x"
    )


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


def test_addresses_written_in_capitals_or_with_www_are_links_too():
    assert ep.urls_in_text("see HTTPS://EVIL.tk/login, and www.evil.tk/x.") == [
        "https://evil.tk/login",
        "http://www.evil.tk/x",
    ]


@pytest.mark.parametrize(
    "name", ["invoice.exe ", "invoice.exe.", "invoice‮fdp.exe", "ｉｎｖ.ＥＸＥ"]
)
def test_file_names_windows_would_run(name):
    import archive_analysis as aa

    assert "executable_in_archive" in aa.classify_names([name])


def test_a_name_with_a_direction_override_is_a_fake_extension():
    import archive_analysis as aa

    assert "double_extension" in aa.classify_names(["invoice‮exe.pdf"])


def test_a_huge_style_sheet_does_not_stall_the_server():
    import time

    css = "".join(f".c{i} div span{{display:none}} " for i in range(2000))
    css += "div, " * 5000 + "p{display:none}"
    html = "<style>" + css + "</style>" + '<div class="c5"><span>x</span></div>' * 5000
    start = time.monotonic()
    ep.html_to_text(html)
    assert time.monotonic() - start < 10


def test_junk_rules_before_a_hiding_rule_do_not_spend_the_budget():
    css = "".join(f".c{i} div span{{color:#333}} " for i in range(3000)) + ".h{display:none}"
    html = (
        "<style>"
        + css
        + "</style>"
        + "<div><span>x</span></div>" * 300
        + '<div class="h">filler</div><p>Hi</p>'
    )
    assert ep.html_to_text(html).endswith("filler")


def test_words_written_by_a_style_sheet_are_read():
    text = ep.html_to_text(
        '<style>.x::before{content:"Your account is suspended. Verify now"}'
        '.absent::after{content:"never shown"}</style><p class="x">Hello</p>'
    )
    assert text == "Hello\nYour account is suspended. Verify now"


# ---------------------------------------------------------------------
# Round 12
# ---------------------------------------------------------------------
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
def test_hosts_with_a_final_dot_brackets_or_an_empty_port(href, host):
    assert la.link_host(href) == host


def test_final_dots_and_brackets_keep_every_link_rule():
    assert sa.strong_link_sign(["https://evil.tk./login"])
    assert la.on_cloud_file_host("https://storage.googleapis.com./b/x.html")
    assert la.ip_host("192.168.1.1.")
    counts = la.link_profile(["https://u[@evil.tk/login"], "Bank <a@bank.example>")
    assert counts["other"] == 1


@pytest.mark.parametrize("href", ["https://evil.tk%40paypal.com/", "https://evil.tk＠paypal.com/"])
def test_a_host_that_decodes_to_an_at_sign_is_not_read_as_paypal(href):
    assert la.link_host(href) != "paypal.com"
    assert la.link_profile([href], "PayPal <service@paypal.com>")["aligned"] == 0


def test_phishtank_domains_are_matched_by_host():
    import reputation as rep

    pt = rep.PhishTank()
    pt._load([{"url": "https://phish.example/login"}])
    for url in (
        "https://user@phish.example/x",
        "https://phish.example:8443/x",
        "https://phish.example./x",
    ):
        assert pt.check(url), url


def test_generated_text_skips_hidden_rules_and_hidden_elements():
    text = ep.html_to_text(
        "<style>.x::before{content:'hidden words';display:none}"
        ".y::before{content:'shown words'} .z::before{content:'buried words'}</style>"
        '<p class="x">a</p><p class="y">b</p><div style="display:none"><p class="z">c</p></div>'
    )
    assert " ".join(text.split()) == "a b shown words c"


def test_slow_selectors_are_bounded_by_the_clock():
    import time

    css = "".join(f"div div div:nth-child({i}){{display:none}} " for i in range(3000))
    html = (
        "<style>"
        + css
        + ".h{display:none}</style>"
        + "<div><div>v</div></div>" * 500
        + '<div class="h">filler</div><p>Hi</p>'
    )
    start = time.monotonic()
    text = ep.html_to_text(html)
    assert time.monotonic() - start < 5
    assert text.endswith("filler")


def test_selectors_naming_nothing_in_the_email_cost_nothing():
    css = "".join(f".nope{i} div{{display:none}} " for i in range(5000)) + ".h{display:none}"
    html = (
        "<style>" + css + "</style>" + "<div>v</div>" * 500 + '<div class="h">filler</div><p>Hi</p>'
    )
    assert ep.html_to_text(html).endswith("filler")


@pytest.mark.parametrize("name", ["invoice.pdf.exe.", "invoice.pdf.exe ", "invoice.pdf.ｅｘｅ"])
def test_a_fake_extension_with_a_final_dot_or_full_width_letters(name):
    import archive_analysis as aa

    assert "double_extension" in aa.classify_names([name])


# ---------------------------------------------------------------------
# Round 13
# ---------------------------------------------------------------------
@pytest.mark.parametrize(
    "url", ["https://evil.example/login#.css", "https://evil.example/login.css?id=1"]
)
def test_a_css_looking_link_still_counts_for_the_link_rule(url):
    counts = la.link_profile([url], "Bank <alerts@signed.example>")
    assert counts["other"] == 1
    assert la.links_elsewhere_only(counts)


def test_brackets_around_an_address_in_text_are_not_part_of_it():
    assert ep.urls_in_text("Verify at [https://evil.tk] or {https://e2.tk}.") == [
        "https://evil.tk",
        "https://e2.tk",
    ]
    assert la.link_host("https://evil.tk%3a80/") != "evil.tk"


def test_attachment_texts_find_addresses_like_emails():
    import attachment_analysis as aa
    import office_analysis as oa

    assert aa.extract_urls("see www.evil.tk/login and HTTP://192.168.1.1/x") == [
        "http://www.evil.tk/login",
        "http://192.168.1.1/x",
    ]
    found: list[str] = []
    oa._urls_from("open WWW.evil.tk/doc", found)
    assert found == ["http://www.evil.tk/doc"]


@pytest.mark.parametrize("value", ["PASSWORD", "Password", " password "])
def test_a_password_field_in_any_case(value):
    import attachment_analysis as aa

    html = f'<form action="https://attacker.example/post"><input type="{value}" name="p"></form>'
    assert (
        "contains_password_field"
        in aa.analyse_html(html.encode(), "invoice.html")["notable_features"]
    )


def test_an_area_counts_only_through_a_shown_image():
    visible, hidden = ep.html_link_groups(
        '<area href="https://d0.example/" style="display:contents">'
        '<map name="m"><area href="https://ok.example/" coords="0,0,10,10"></map>'
        '<img src="x.png" usemap="#m">'
        '<map name="n"><area href="https://hid.example/"></map>'
        '<img usemap="#n" style="display:none">'
        '<a href="https://evil.example/">Verify</a>'
    )
    assert visible == ["https://ok.example/", "https://evil.example/"]
    assert hidden == ["https://d0.example/", "https://hid.example/"]


def test_repeated_cheap_rules_do_not_hide_a_later_rule():
    html = (
        "<style>"
        + "i{display:none}" * 101
        + ".h{display:none}</style>"
        + "<i></i>" * 5000
        + '<div class="h">filler</div><p>Verify</p>'
    )
    assert ep.html_to_text(html).endswith("filler")


@pytest.mark.parametrize("css", ["._h div{display:none}", "div .-hide{display:none}"])
def test_selectors_with_underscore_or_dash_names(css):
    cls = "_h" if "_h" in css else "-hide"
    html = f'<style>{css}</style><div class="{cls}"><div>filler</div></div><div><span class="{cls}">x</span></div><p>Verify</p>'
    first = "x Verify" if cls == "_h" else "filler Verify"
    assert " ".join(ep.html_to_text(html).split()).startswith(first)


def test_generated_text_inherits_unreadability():
    text = ep.html_to_text(
        '<style>.x::before{content:"filler1"} .y::before{content:"filler2";color:#fff}'
        '.z::before{content:"shown"}</style>'
        '<div style="font-size:0"><p class="x"></p></div><p class="y"></p><p class="z">a</p>'
    )
    assert " ".join(text.split()) == "a shown"


def test_a_forward_without_newlines_in_its_html_is_detected():
    body = ep.html_to_text(
        "<p>FYI</p><div>---------- Forwarded message ---------<br>"
        "From: alerts@gtbank-secure.xyz<br>Verify your account</div>"
    )
    found = ep.detect_forwarded(body)
    assert found == {"detected": True, "original_sender": "alerts@gtbank-secure.xyz"}


def test_invisible_characters_do_not_cut_words_for_the_text_model():
    from text_model import without_invisible

    assert without_invisible("V​e​r​ify your acc­ount") == "Verify your account"
    assert without_invisible("मि‍त्र") == "मि‍त्र"


# ---------------------------------------------------------------------
# Round 14
# ---------------------------------------------------------------------
def _zip(*names: str) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, "MZ" if name.endswith(".exe") else "")
    return buf.getvalue()


@pytest.mark.parametrize("filename", ["docs.zip", "report.docx"])
def test_an_archive_dressed_as_a_word_file_still_shows_its_program(filename):
    import attachment_analysis as aa

    raw = _zip("[Content_Types].xml", "word/x", "invoice.pdf.exe")
    out = aa.analyse_attachment(base64.b64encode(raw).decode(), filename=filename)
    assert "executable_in_archive" in out["notable_features"]


def test_a_real_word_file_is_still_read_as_one():
    import attachment_analysis as aa

    raw = _zip("[Content_Types].xml", "word/document.xml", "word/media/image1.png")
    out = aa.analyse_attachment(base64.b64encode(raw).decode(), filename="report.docx")
    assert out["kind"] == "docx"
    assert out["notable_features"] == []


@pytest.mark.parametrize(
    "href", ["https://℅@evil.tk#@paypal.com", "https://℅@evil.tk?x=@paypal.com"]
)
def test_a_user_part_python_refuses_does_not_move_the_host(href):
    assert la.link_host(href) == "evil.tk"
    assert not la.well_known_link(href)
    assert sa.strong_link_sign([href])


def test_an_address_written_in_capitals_counts_as_written_in_the_text():
    body = "Verify at HTTPS://Evil.Example/login now"
    urls = ep.urls_in_text(body)
    written = set(ep.urls_in_text(body))
    assert urls[0] in written


@pytest.mark.parametrize(
    "text",
    [
        "V​‌e​‌r​‌i​‌f​‌y",
        "V͏e͏r͏i͏f͏y",
        "V️e️r️i️f️y",
    ],
)
def test_more_invisible_marks_do_not_cut_words(text):
    from unicode_text import without_invisible

    assert without_invisible(text) == "Verify"


def test_joiners_stay_inside_arabic_and_indic_words():
    from unicode_text import without_invisible

    persian = "می‌خواهم"
    assert without_invisible(persian) == persian
    assert without_invisible("П‌о") == "По"  # Cyrillic: no joiner needed


def test_a_display_name_padded_with_invisible_marks_keeps_the_brand():
    value = _from_value("x@evil.example", "͏" * 300 + "PayPal")
    assert st.impersonated_brand(value) == "paypal"


def test_an_address_with_an_invisible_character_reads_as_the_browser_opens_it():
    assert ep.urls_in_text("go to https://evil​.tk/login") == ["https://evil.tk/login"]


def test_hiding_rules_of_every_kind_survive_many_cheap_ones():
    for rule in (".h{visibility:hidden}", ".h{font-size:0}", ".h{color:transparent}"):
        html = (
            "<style>"
            + "i{display:none}" * 101
            + rule
            + "</style>"
            + "<i></i>" * 5000
            + '<div class="h">filler</div><p>Verify</p>'
        )
        assert ep.html_to_text(html).endswith("filler"), rule
