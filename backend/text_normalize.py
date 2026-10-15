"""
Text normalisation for the multilingual text agent (v2).

The v2 model was trained on normalised text: links, email addresses and
phone numbers replaced by tags (<URL>, <EMAIL>, <PHONE>), Unicode NFKC,
whitespace collapsed. The backend must feed it the same form, so this
module is a copy of normalize_text from the training code
(PhishLens-multilingual, common.py); tests/test_text_normalize.py pins
its output. Change both together, or not at all.
"""

from __future__ import annotations

import re
import unicodedata

MIN_CHARS, MAX_CHARS = 20, 20_000

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]*[^\s<>\"')\].,;:!?]", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_PHONE_RE = re.compile(r"(?<!\w)\+?\d(?:[ ().-]{0,2}\d){7,14}(?!\w)")
# Placeholders already present in some corpora (MeAJOR masks its data).
_PLACEHOLDERS = {
    "<|URL|>": "<URL>",
    "[URL]": "<URL>",
    "[EMAIL]": "<EMAIL>",
    "[PHONE]": "<PHONE>",
}


MAX_TOKEN = 120  # longer "words" are base64, hashes or tracking junk


def _token(tok: str) -> str:
    """Mask one whitespace-free token. Tokens are short (<= MAX_TOKEN), so
    the regexes stay linear: on a 100k-character blob without spaces the
    email pattern backtracks quadratically, which froze the first build."""
    low = tok.lower()
    if low.startswith(("http://", "https://", "www.")):
        return _URL_RE.sub("<URL>", tok[:4000])  # keeps trailing punctuation
    if len(tok) > MAX_TOKEN:
        return ""
    if "@" in tok:
        tok = _EMAIL_RE.sub("<EMAIL>", tok)
    if "http" in low or "www." in low:
        tok = _URL_RE.sub("<URL>", tok)
    return tok


def normalize_text(text: str) -> str:
    """Same masking for every corpus, so a model cannot learn a source from
    its formatting: links, email addresses and phone numbers become tags,
    unicode is normalised (NFKC) and whitespace collapsed. Linear time:
    the text is cut to MAX_CHARS * 2 first and masked token by token."""
    if not isinstance(text, str):
        return ""
    t = unicodedata.normalize("NFKC", text[: MAX_CHARS * 2])
    for k, v in _PLACEHOLDERS.items():
        t = t.replace(k, f" {v} ")
    t = " ".join(filter(None, (_token(x) for x in t.split())))
    t = _PHONE_RE.sub("<PHONE>", t)
    t = re.sub(r"(?:<URL>\s*){2,}", "<URL> ", t)
    return re.sub(r"\s+", " ", t).strip()
