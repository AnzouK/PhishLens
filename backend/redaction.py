"""
Second removal of personal data from reports users send (/feedback).

The extension already redacts the text before sending it
(extension/lib/redact.js) and shows the result to the person; these are
the same rules, applied again on the server, so a modified or outdated
client cannot store more than the current rules allow.
"""

from __future__ import annotations

import re

_GREETING = (
    r"(?:Hi|Hello|Hey|Dear|Bonjour|Bonsoir|Salut|Cher|Chère|Olá|Ola|Oi|Hola|Estimado|Estimada|"
    r"Hallo|Liebe|Lieber|Ciao|Caro|Cara|Gentile|Beste|Querida|Querido|Prezado|Prezada|Sannu|Barka)"
)
_TITLE = (
    r"(?:M\.|Mr\.?|Mrs\.?|Ms\.?|Mme\.?|Mlle\.?|Dr\.?|Madame|Monsieur|Mister|Miss|Sr\.|Sra\.|"
    r"Herr|Frau|Signor|Signora|Alhaji|Malam)"
)
_NAME = r"[A-ZÀ-Ý][^\W\d_'’-]*(?:['’-][^\W\d_]+)*"
_NOT_NAMES_TEXT = (
    "nous je we i you your we're we've it its this that the a le la les un une vous votre vos pour "
    "en merci thank thanks please suite if for today user users customer customers client cliente "
    "member membre team équipe there all everyone friend friends madame monsieur madam sir mate "
    "esteemed valued student bonjour hello hi obrigado todos tous and et y o e peer meet mr mrs ms "
    "dr m mme mlle sr sra herr frau"
)
_NOT_NAMES = set(_NOT_NAMES_TEXT.split())

_EMAIL = re.compile(r"[\w.%+-]+@[\w.-]+\.[^\W\d_]{2,}")
_URL = re.compile(
    r"\b(?:https?://|www\.)([^\s/?#<>\"']*[^\s/?#<>\"'.,;:!?)])(?:[/?#][^\s<>\"']*[^\s<>\"'.,;:!?)])?",
    re.I,
)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_PHONE = re.compile(r"(?<![\w])\+\d[\d ().-]{6,}\d")
_LONG_NUMBER = re.compile(r"(?<![^\W\d_])(?<!\d)\d(?:[ .-]?\d){5,}(?!\d)(?![^\W\d_])")
_HANDLE = re.compile(r"(?<![\w<])@[\w.]{2,}")
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060\ufeff]")
_LEADS = [
    re.compile(r"(\b" + lead + r")(" + _NAME + r"(?:\s+" + _NAME + r"){0,2})")
    for lead in (_TITLE + r"\s+", _GREETING + r",?\s+")
]


def _mask_names(words: str) -> str:
    return " ".join(w if w.lower().strip(".,!") in _NOT_NAMES else "<NAME>" for w in words.split())


def _username(token: str) -> bool:
    core = re.sub(r"^\W+|\W+$", "", token)
    if len(core) < 6 or core.startswith("<"):
        return False
    if "_" in core and re.search(r"[^\W\d_]", core):
        return True
    return bool(
        re.search(r"[a-zà-ÿ]", core) and re.search(r"\d", core) and re.search(r"[^\W\d_]{3}", core)
    )


def redact(text: str, terms: list[str] | None = None) -> str:
    t = _ZERO_WIDTH.sub("", str(text or ""))
    t = _EMAIL.sub("<EMAIL>", t)
    t = _URL.sub(lambda m: f"<URL:{m.group(1).lower().removeprefix('www.')}>", t)
    t = _IBAN.sub("<NUMBER>", t)
    t = _PHONE.sub("<PHONE>", t)
    t = _LONG_NUMBER.sub("<NUMBER>", t)
    t = _HANDLE.sub("<NAME>", t)
    for lead in _LEADS:
        t = lead.sub(lambda m: m.group(1) + _mask_names(m.group(2)), t)
    term_set = {x.lower() for x in (terms or []) if x}
    words = []
    for w in t.split(" "):
        if _username(w):
            w = re.sub(r"\w+", "<NAME>", w, count=1)
        elif term_set:
            w = re.sub(
                r"[^\W\d_]+", lambda m: "<NAME>" if m.group().lower() in term_set else m.group(), w
            )
        words.append(w)
    return re.sub(r"[ \t]{2,}", " ", " ".join(words)).strip()
