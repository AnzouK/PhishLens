"""Bypasses aimed at the text the model reads: invisible characters, HTML
source shown as text, forwards, and the two readings of a text."""

from __future__ import annotations

import base64

import numpy as np
import pytest

import email_parsing as ep
import text_model as tm
from extension_backend import AnalyseRequest, _resolve_email
from tests.conftest import shared_cases
from unicode_text import collapse_invisible, without_invisible

_INVISIBLE_CASES = shared_cases("invisible_cases.json")["cases"]
_COLLAPSE_CASES = shared_cases("invisible_cases.json")["collapse"]


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


def test_words_after_unclosed_bracket_stay_words():
    text = "Hi <a Urgent: your bank account is suspended, verify your password at our portal"
    assert ep.strip_markup_noise(text) == text
    assert not ep.looks_like_source(text)
    assert ep.strip_markup_noise('<div class="x"><p>Hello</p></div>') == "Hello"


def test_long_base64_run_keeps_page_text():
    eml = (
        b"From: a@b.example\r\nContent-Type: text/html\r\n\r\n<p>" + b"benign words " * 50 + b"</p>"
    )
    page = "Verify your bank account now please " + "A" * 3000
    req = AnalyseRequest(raw_email_b64=base64.b64encode(eml).decode(), raw_text=page)
    body, _u, _h, _raw = _resolve_email(req)
    assert body.startswith("Verify your bank account")


def test_html_source_as_text_yields_to_original():
    source = (
        "<html><body>"
        + "".join(f'<div class="c{i}"><p>x</p></div>' for i in range(10))
        + "</body></html>"
    )
    assert ep.is_page_source(source)


def test_unclosed_tag_before_query_link_keeps_text():
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


def test_few_tags_in_noisy_text_not_source():
    noisy = "benign words " * 20 + "&lt;a&gt; <a> <a> <a> <a> <a> " + "A" * 2000
    assert not ep.is_page_source(noisy)
    image_source = (
        '<div style="width: 100%"><img src="data:image/jpeg;base64,' + "QUJD" * 600 + '"></div>'
    )
    assert ep.is_page_source(image_source)


@pytest.mark.parametrize(
    "text",
    [
        'Hi <a x="Urgent: your bank account is suspended, verify at https://evil.example/login?id=1',
        "Hi <a Urgent: your bank account is suspended. Verify your password at=https://evil.example/?id=1",
    ],
)
def test_sentences_that_look_like_attributes_stay_words(text):
    assert ep.strip_markup_noise(text) == text


def test_one_long_pseudo_tag_not_source():
    assert not ep.is_page_source("benign " * 5 + '<div a="' + "A" * 1990 + '">')


def test_sentence_after_closed_quote_stays_words():
    text = (
        'Hi <a x="Urgent: your bank account is suspended, verify your password '
        'immediately at https://evil.example/login?id=1"'
    )
    assert ep.strip_markup_noise(text) == text


def test_a_short_text_with_two_tags_is_not_source():
    assert not ep.is_page_source('<p><div a="' + "A" * 1990 + '">')
    assert not ep.is_page_source("Hello " + "<b>x</b>" * 3)


def test_quoted_sentence_with_bracket_not_attribute():
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


def test_forward_without_newlines_detected():
    body = ep.html_to_text(
        "<p>FYI</p><div>---------- Forwarded message ---------<br>"
        "From: alerts@gtbank-secure.xyz<br>Verify your account</div>"
    )
    found = ep.detect_forwarded(body)
    assert found == {"detected": True, "original_sender": "alerts@gtbank-secure.xyz"}


def test_invisible_chars_do_not_cut_words():
    assert without_invisible("V​e​r​ify your acc­ount") == "Verify your account"
    assert without_invisible("मि‍त्र") == "मि‍त्र"


@pytest.mark.parametrize(
    "text",
    [
        "V​‌e​‌r​‌i​‌f​‌y",
        "V͏e͏r͏i͏f͏y",
        "V️e️r️i️f️y",
    ],
)
def test_more_invisible_marks_do_not_cut_words(text):
    assert without_invisible(text) == "Verify"


def test_joiners_stay_inside_arabic_and_indic_words():
    persian = "می‌خواهم"
    assert without_invisible(persian) == persian
    assert without_invisible("П‌о") == "По"  # Cyrillic: no joiner needed


@pytest.mark.parametrize("case", _INVISIBLE_CASES, ids=[c["clean"] for c in _INVISIBLE_CASES])
def test_invisible_cases_shared_with_the_extension(case):
    assert without_invisible(case["text"]) == case["clean"]


@pytest.mark.parametrize("case", _COLLAPSE_CASES, ids=[str(i) for i in range(len(_COLLAPSE_CASES))])
def test_collapse_cases_shared_with_the_extension(case):
    assert collapse_invisible(case["text"]) == case["collapsed"]


def test_text_model_keeps_higher_reading(monkeypatch):
    def fake(texts, clean=True):
        # As shown scores low, as written (padding kept) scores high.
        p = 0.1 if clean else 0.95
        return np.array([[1 - p, p] for _ in texts])

    monkeypatch.setattr(tm, "predict_proba_batch", fake)
    assert tm.text_agent("Roofs ﻿﻿﻿ Metal") == pytest.approx(0.95)
    calls = []
    monkeypatch.setattr(
        tm,
        "predict_proba_batch",
        lambda t, clean=True: calls.append(clean) or np.array([[0.5, 0.5]]),
    )
    tm.text_agent("plain text")
    assert calls == [True]
