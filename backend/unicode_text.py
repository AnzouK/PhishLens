"""
Characters that take no room on screen.

A word written "V" + zero-width space + "erify" shows as "Verify" but cuts
in pieces for the text model, and 200 invisible characters before a brand
name pushed the name past the part of a sender's name that is checked.
Every place that reads text an email controls removes them with
without_invisible (the extension has the same rule: content_scripts/core.js,
PL.withoutInvisible; shared cases in tests/fixtures/invisible_cases.json).

Invisible means what Unicode calls default ignorable (format characters,
variation selectors, fillers, tags), plus control characters other than
the tab, line feed, form feed and carriage return.
"""

from __future__ import annotations

import re
import sys
import unicodedata

# Default ignorable though not of the "format" category: the combining
# grapheme joiner, Hangul and halfwidth fillers, the Khmer inherent
# vowels, the Mongolian variation selectors, variation selectors.
_ALSO_INVISIBLE = frozenset("͏ᅟᅠ឴឵᠋᠌᠍᠏ㅤﾠ" + "".join(chr(c) for c in range(0xFE00, 0xFE10)))
_INVISIBLE_RANGES = (
    (0x0890, 0x0891),  # Arabic pound and piastre marks above (format)
    (0x13430, 0x1343F),  # Egyptian hieroglyph format controls
    (0xFFF0, 0xFFF8),  # reserved, default ignorable
    (0x1BCA0, 0x1BCA3),  # shorthand format controls
    (0x1D173, 0x1D17A),  # musical format controls
    (0xE0000, 0xE0FFF),  # tags and variation selectors supplement
)
# Control characters that are not white space on a page.
_CONTROLS = frozenset(
    chr(c) for c in [*range(0x00, 0x09), 0x0B, *range(0x0E, 0x20), *range(0x7F, 0xA0)]
)
_JOINERS = "‌‍"


def _ranges(codes: list[int]) -> str:
    out, start = [], None
    for k, o in enumerate(codes):
        if start is None:
            start = o
        if k + 1 == len(codes) or codes[k + 1] != o + 1:
            out.append(re.escape(chr(start)) + ("-" + re.escape(chr(o)) if o != start else ""))
            start = None
    return "".join(out)


def _invisible_codes() -> list[int]:
    codes = {o for o in range(sys.maxunicode + 1) if unicodedata.category(chr(o)) == "Cf"}
    codes |= {ord(c) for c in _ALSO_INVISIBLE | _CONTROLS}
    for lo, hi in _INVISIBLE_RANGES:
        codes.update(range(lo, hi + 1))
    return sorted(codes)


# Every invisible character, as one character class (built once: removing
# them is then linear and done in C, even over a whole attachment).
_INVISIBLE_CLASS = "[" + _ranges(_invisible_codes()) + "]"
_INVISIBLE_RE = re.compile(_INVISIBLE_CLASS)
_INVISIBLE_RUN_RE = re.compile(_INVISIBLE_CLASS + "+")


def is_invisible(c: str) -> bool:
    return bool(_INVISIBLE_RE.match(c))


def _shaped_block(c: str) -> bool:
    """Arabic and Persian (with their presentation forms), the Indic
    scripts: the scripts whose shape the joiners change."""
    o = ord(c)
    return (
        0x0600 <= o <= 0x08FF
        or 0x0900 <= o <= 0x0DFF
        or 0xFB50 <= o <= 0xFDFF
        or 0xFE70 <= o <= 0xFEFC
    )


def _shaped_letter(c: str) -> bool:
    return _shaped_block(c) and unicodedata.category(c)[0] == "L" and not is_invisible(c)


def _shaped_mark(c: str) -> bool:
    return _shaped_block(c) and unicodedata.category(c) in ("Mn", "Mc") and not is_invisible(c)


def _joins(text: str, i: int) -> bool:
    """The joiner at i sits where those scripts use one: after a letter of
    theirs (with its vowel signs or virama, "मि" + joiner, "क्" + joiner)
    and before another letter of theirs. Marks alone, invisible
    characters or Latin letters around it never count: "Pay" + mark +
    joiner + mark + "Pal" loses its joiner."""
    if i + 1 >= len(text) or not _shaped_letter(text[i + 1]):
        return False
    j = i - 1
    while j >= 0 and _shaped_mark(text[j]):
        j -= 1
    return j >= 0 and _shaped_letter(text[j])


def without_invisible(text: str) -> str:
    """The text without characters that take no room. The joiners
    (U+200C, U+200D) stay where Arabic, Persian and Indic writing uses
    them (_joins) and go everywhere else."""
    if not text:
        return ""

    def keep(m: re.Match) -> str:
        run = m.group()
        if len(run) != 1 or run not in _JOINERS:
            # A joiner next to another invisible character is never
            # between two letters.
            return ""
        return run if _joins(text, m.start()) else ""

    return _INVISIBLE_RUN_RE.sub(keep, text)
