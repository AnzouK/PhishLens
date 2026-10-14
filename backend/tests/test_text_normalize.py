"""text_normalize.py must give exactly the text the v2 model was trained
on (normalize_text in the training code). These cases pin it."""

from __future__ import annotations

from text_normalize import normalize_text


def test_links_addresses_phones_and_placeholders_are_masked():
    t = normalize_text(
        "Pay at https://evil.example/x?a=1 or www.x.co, mail a.b@c.com, call +234 803 123 4567 <|URL|> [URL]"
    )
    assert t == "Pay at <URL> or <URL>, mail <EMAIL>, call <PHONE> <URL>"


def test_accents_kept_whitespace_collapsed():
    assert normalize_text("Votre   colis\n\nest prêt") == "Votre colis est prêt"


def test_long_junk_tokens_dropped_and_repeated_links_merged():
    assert normalize_text("a " + "x" * 200 + " b") == "a b"
    assert normalize_text("go https://a.example https://b.example now") == "go <URL> now"


def test_not_text_is_empty():
    assert normalize_text(None) == ""
