"""Bypasses that hide text or links in an email's HTML: styles, style
sheets, hidden elements and the order links are read in."""

from __future__ import annotations

import base64
import time

import pytest

import email_parsing as ep
import hidden_content as hc
from extension_backend import AnalyseRequest, _resolve_email
from tests.conftest import shared_cases

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


_HIDDEN_CASES = shared_cases("hidden_cases.json")["cases"]


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


def test_links_read_as_browser_visible_first():
    links = ep.html_links(HIDDEN_FIRST)
    assert links[:3] == [
        "https://evil.example/login",
        "https://evil2.example/",
        "https://evil3.example/",
    ]
    assert "https://www.google.com/0" in links


def test_hidden_text_addresses_keep_real_link():
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


def test_second_link_same_site_before_text_addresses():
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


def test_page_links_before_text_addresses():
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


@pytest.mark.parametrize("case", _HIDDEN_CASES, ids=[c["name"] for c in _HIDDEN_CASES])
def test_hidden_cases_shared_with_the_extension(case):
    parent = case.get("parentBackground")
    background = hc.parse_colour(parent) if parent else None
    assert hc.is_hidden_style(case["style"], background) is case["hidden"]


def test_hidden_links_stay_after_visible_same_site():
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


def test_page_hidden_links_after_visible():
    req = AnalyseRequest(
        raw_text="Please verify your account today",
        client_context={
            "link_urls": ["https://docs.google.com/a", "https://docs.google.com/phish"],
            "hidden_link_urls": [f"https://d{i}.example/" for i in range(50)],
        },
    )
    _body, urls, _h, _raw = _resolve_email(req)
    assert urls[:2] == ["https://docs.google.com/a", "https://docs.google.com/phish"]


def test_text_in_closed_details_hidden():
    text = ep.html_to_text(
        "<details><summary>Info</summary>benign words here</details><p>Verify your account</p>"
    )
    assert text.startswith("Info Verify your account")


def test_sheet_rule_hides_text_in_parsed_message():
    text = ep.html_to_text(
        "<style>.h{display:none} @media (max-width:600px){.h{display:block}}</style>"
        '<div class="h">' + "minutes of the meeting " * 30 + "</div><p>Verify your account</p>"
    )
    assert text.startswith("Verify your account")


def test_white_on_white_parent_hidden_unless_painted():
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


def test_message_visible_links_before_page_hidden():
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


def test_a_link_the_browser_saw_hidden_stays_hidden():
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
def test_more_hiding_and_legitimate_styles(html, first):
    assert " ".join(ep.html_to_text(html).split()).startswith(first)


def test_a_huge_style_sheet_does_not_stall_the_server():
    css = "".join(f".c{i} div span{{display:none}} " for i in range(2000))
    css += "div, " * 5000 + "p{display:none}"
    html = "<style>" + css + "</style>" + '<div class="c5"><span>x</span></div>' * 5000
    start = time.monotonic()
    ep.html_to_text(html)
    assert time.monotonic() - start < 10


def test_junk_rules_do_not_spend_hiding_budget():
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


def test_generated_text_skips_hidden_rules():
    text = ep.html_to_text(
        "<style>.x::before{content:'hidden words';display:none}"
        ".y::before{content:'shown words'} .z::before{content:'buried words'}</style>"
        '<p class="x">a</p><p class="y">b</p><div style="display:none"><p class="z">c</p></div>'
    )
    assert " ".join(text.split()) == "a b shown words c"


def test_slow_selectors_are_bounded_by_the_clock():
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


def test_selectors_matching_nothing_are_free():
    css = "".join(f".nope{i} div{{display:none}} " for i in range(5000)) + ".h{display:none}"
    html = (
        "<style>" + css + "</style>" + "<div>v</div>" * 500 + '<div class="h">filler</div><p>Hi</p>'
    )
    assert ep.html_to_text(html).endswith("filler")


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


def test_hiding_rules_survive_many_cheap_ones():
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


def test_a_link_around_a_drawn_shape_is_shown():
    visible, hidden = ep.html_link_groups(
        '<svg><a href="https://evil.tk/login"><rect width="100" height="30"/></a></svg>'
    )
    assert visible == ["https://evil.tk/login"]


@pytest.mark.parametrize(
    "padding",
    [
        '<img src="DATA:image/png;BASE64,' + "QUJD" * 300_000 + '">',
        '<img src="data:image/png;charset=utf-8;base64,' + "QUJD" * 300_000 + '">',
        "<!-- " + "x " * 600_000 + " -->",
        '<div title="' + "x" * 1_100_000 + '"></div>',
    ],
)
def test_padding_does_not_hide_links(padding):
    visible, hidden = ep.html_link_groups(padding + '<a href="https://evil.tk/login">Verify</a>')
    assert "https://evil.tk/login" in visible + hidden[:200]


def test_decoy_flood_does_not_hide_last_link():
    decoys = "".join(
        f'<a href="https://d{i}.example/" style="display:none">d</a>' for i in range(25_000)
    )
    visible, hidden = ep.html_link_groups(decoys + '<a href="https://evil.tk/x">Go</a>')
    assert "https://evil.tk/x" in ep.rank_links(visible, hidden, limit=200)


def test_long_comments_keep_text_and_links():
    assert (
        ep.html_to_text("<!-- " + "x " * 600_000 + " --><p>Verify your account</p>")
        == "Verify your account"
    )
    mso = "<!--[if mso]>" + "x" * 600 + '<a href="https://mso.example/btn">b</a><![endif]-->'
    visible, hidden = ep.html_link_groups(mso + '<a href="https://ok.example">ok</a>')
    assert visible == ["https://ok.example"] and hidden == ["https://mso.example/btn"]


def test_links_past_parsed_part_are_read():
    pad = '<div title="' + "x" * 1_100_000 + '"></div>'
    tail = '<link rel="stylesheet" href="https://fonts.example/a.css"><a href=" https://evil.tk/login ">Go</a>'
    visible, hidden = ep.html_link_groups(pad + tail)
    assert "https://evil.tk/login" in hidden
    assert "https://fonts.example/a.css" not in hidden


@pytest.mark.parametrize("pad", ["", "/* x */ " * 80])
def test_a_style_sheet_inside_comment_marks_applies(pad):
    html = (
        f'<style><!-- {pad}.h{{display:none}} --></style><div class="h">filler</div><p>Verify</p>'
    )
    assert ep.html_to_text(html).startswith("Verify")


def test_data_attribute_does_not_hide_next_link():
    pad = '<div title="' + "x" * 1_100_000 + '"></div>'
    visible, hidden = ep.html_link_groups(
        pad + '<a data-href="x" href="https://evil.tk/login">Go</a>'
    )
    assert "https://evil.tk/login" in hidden


def test_a_comment_in_a_second_style_sheet_stays():
    comment = "<!--" + "a" * 600 + "-->"
    two = f"<style>p{{color:red}}</style><p>hi</p><style>{comment} .x{{display:none}}</style>"
    assert comment in ep.without_inline_data(two)
    # A long comment after the sheets is still removed, its links kept.
    after = two + '<!--[if mso]><a href="https://evil.example/x">' + "b" * 600 + "<![endif]-->"
    out = ep.without_inline_data(after)
    assert comment in out and "b" * 600 not in out
    assert '<a href="https://evil.example/x"></a>' in out
    # "<style" inside a long comment opens no sheet.
    tricky = "<!--<style>" + "c" * 600 + "--><p>x</p>" + comment
    assert ep.without_inline_data(tricky) == "<p>x</p>"


def test_dotted_capital_i_does_not_shift_the_sheet_end():
    # "\u0130".lower() is two characters: a lowercased copy put the end
    # of the sheet inside the comment that follows it.
    html = "\u0130" * 2000 + "<style>p{}</style><!--" + "x" * 1_000_000 + "--><p>Hi</p>"
    out = ep.without_inline_data(html)
    assert "x" * 1000 not in out and out.endswith("<p>Hi</p>")
    assert (
        ep.without_inline_data("<STYLE>p{}</Style><!--" + "y" * 600 + "-->") == "<STYLE>p{}</Style>"
    )


@pytest.mark.parametrize("attr", ['title="<style>"', "title='<style>'", 'title="<!--"'])
def test_markup_inside_an_attribute_opens_nothing(attr):
    html = f"<div {attr}>Hi</div><!--" + "x" * 1_000_000 + "--><p>Verify</p>"
    assert ep.without_inline_data(html) == f"<div {attr}>Hi</div><p>Verify</p>"


def test_empty_comment_forms_hide_nothing():
    text = "Your account is locked " * 30
    for empty in ("<!-->", "<!--->"):
        html = f"{empty}<p>{text}</p><!-- x -->"
        assert ep.without_inline_data(html) == html


_BIG = "<!--" + "x" * 1_000_000 + "-->"


@pytest.mark.parametrize(
    "tag", ["title", "textarea", "script", "xmp", "iframe", "noembed", "noframes"]
)
def test_a_comment_opener_in_raw_text_hides_nothing(tag):
    # "<!--" inside these elements is text for browsers and html.parser:
    # the rest of the email, its text and links, must stay.
    body = "Your account is locked. " * 40
    html = f'<{tag}><!--</{tag}><p>{body}</p><a href="https://evil.tk/login">Go</a>'
    assert ep.without_inline_data(html) == html
    visible, _ = ep.html_link_groups(html)
    assert "https://evil.tk/login" in visible


@pytest.mark.parametrize("tag", ["script", "title", "TEXTAREA", "Xmp"])
def test_a_style_opener_in_raw_text_keeps_comment_removal(tag):
    html = f"<{tag}><style></{tag.lower()} >{_BIG}<p>Verify</p>"
    assert ep.without_inline_data(html) == f"<{tag}><style></{tag.lower()} ><p>Verify</p>"


def test_raw_text_close_needs_a_tag_end():
    # "</titlex>" does not close <title>: the comment stays inside it.
    html = "<title></titlex><!--" + "x" * 600 + "--></title><p>Verify</p>"
    assert ep.without_inline_data(html) == html


def test_long_s_does_not_open_a_sheet():
    # "ſ" matches "s" in a case-insensitive Unicode regex; a browser
    # reads "<ſtyle>" as an unknown tag.
    html = "<ſtyle>" + _BIG + "<p>Verify</p>"
    assert ep.without_inline_data(html) == "<ſtyle><p>Verify</p>"


def test_plaintext_makes_the_rest_text():
    html = "<plaintext><!--" + "x" * 600 + "--><p>Verify</p>"
    assert ep.without_inline_data(html) == html


def test_noscript_is_parsed_as_markup():
    # html.parser (scripting off) and Gmail read <noscript> content as markup.
    html = "<noscript>" + _BIG + "</noscript><p>Verify</p>"
    assert ep.without_inline_data(html) == "<noscript></noscript><p>Verify</p>"


def test_bang_comment_end_closes_a_comment():
    html = "<!--" + "x" * 1_000_000 + "--!><p>Verify</p>"
    assert ep.without_inline_data(html) == "<p>Verify</p>"
    assert ep.html_to_text(html) == "Verify"


@pytest.mark.parametrize("tag", ['<div a=b=">', '<div a=b= ">', "<div a=b='>", '<div a= b="c>"d>'])
def test_equals_inside_an_unquoted_value_opens_no_quote(tag):
    html = tag + _BIG + "<p>Verify</p>"
    assert ep.without_inline_data(html) == tag + "<p>Verify</p>"


def test_quoted_values_still_hide_markup():
    for tag in ['<div a = "x>">', "<div a='x>' b=\"y>\">", '<a href="x">', "</p a='>'>"]:
        assert ep.without_inline_data(tag + _BIG + "<p>V</p>") == tag + "<p>V</p>"
