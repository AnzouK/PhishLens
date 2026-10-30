"""
Characters that take no room on screen.

A word written "V" + zero-width space + "erify" shows as "Verify" but cuts
in pieces for the text model, and 200 invisible characters before a brand
name pushed the name past the part of a sender's name that is checked.
Every place that reads text an email controls removes them with
without_invisible (the extension has the same list: content_scripts/core.js,
INVISIBLE_RE).
"""

from __future__ import annotations

import unicodedata

# Invisible though not of the "format" category: the combining grapheme
# joiner, variation selectors, Hangul fillers.
_ALSO_INVISIBLE = frozenset("͏ᅟᅠㅤﾠ" + "".join(chr(c) for c in range(0xFE00, 0xFE10)))
_JOINERS = "‌‍"


def _shaped(c: str) -> bool:
    """A letter of the scripts whose shape the joiners change (Arabic,
    Persian, the Indic scripts)."""
    o = ord(c)
    return 0x0600 <= o <= 0x08FF or 0x0900 <= o <= 0x0DFF or 0xFB50 <= o <= 0xFEFF


def is_invisible(c: str) -> bool:
    return (
        unicodedata.category(c) == "Cf"
        or c in _ALSO_INVISIBLE
        or 0xE0100 <= ord(c) <= 0xE01EF  # variation selectors supplement
    )


def without_invisible(text: str) -> str:
    """The text without characters that take no room. The joiners
    (U+200C, U+200D) stay between two letters of a script they shape and
    go everywhere else."""
    if text.isascii():
        return text
    n = len(text)
    out = []
    for i, c in enumerate(text):
        if (
            not is_invisible(c)
            or c in _JOINERS
            and 0 < i < n - 1
            and _shaped(text[i - 1])
            and _shaped(text[i + 1])
        ):
            out.append(c)
    return "".join(out)
