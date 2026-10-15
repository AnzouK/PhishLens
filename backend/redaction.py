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

_EMAIL_DOMAIN = re.compile(r"@[\w.-]+\.[^\W\d_]{2,}")
_URL = re.compile(
    r"\b(?:https?://|www\.)([^\s/?#<>\"']*[^\s/?#<>\"'.,;:!?)])(?:[/?#][^\s<>\"']*[^\s<>\"'.,;:!?)])?",
    re.I,
)
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_PHONE = re.compile(r"(?<![\w])\+\d[\d ().-]{6,}\d")
_LONG_NUMBER = re.compile(r"(?<![^\W\d_])(?<!\d)\d(?:[ .-]?\d){5,}(?!\d)(?![^\W\d_])")
_HANDLE = re.compile(r"(?<![\w<])@[\w.]{2,}")
_PLACEHOLDER = re.compile(r"<(?:NAME|EMAIL|NUMBER|PHONE|URL)")
_CORE = re.compile(r"\w(?:.*\w)?", re.S)
_ZERO_WIDTH = re.compile("[\u200b-\u200d\u2060\ufeff]")
_LEADS = [
    re.compile(r"(\b" + lead + r")(" + _NAME + r"(?:\s+" + _NAME + r"){0,2})")
    for lead in (_TITLE + r"\s+", _GREETING + r",?\s+")
]


def _local_part_char(ch: str) -> bool:
    return ch.isalnum() or ch in "._%+-_"


def _mask_emails(text: str) -> str:
    """Replaces name@domain.tld by <EMAIL>, walking back from each @domain."""
    out, last = [], 0
    for m in _EMAIL_DOMAIN.finditer(text):
        start = m.start()
        while start > last and _local_part_char(text[start - 1]):
            start -= 1
        if start == m.start():
            continue
        out += [text[last:start], "<EMAIL>"]
        last = m.end()
    out.append(text[last:])
    return "".join(out)


def _mask_names(words: str) -> str:
    return " ".join(w if w.lower().strip(".,!") in _NOT_NAMES else "<NAME>" for w in words.split())


def _username(token: str) -> bool:
    found = _CORE.search(token)
    core = found.group() if found else ""
    if len(core) < 6 or core.startswith("<"):
        return False
    if "_" in core and re.search(r"[^\W\d_]", core):
        return True
    return bool(
        re.search(r"[a-zà-ÿ]", core) and re.search(r"\d", core) and re.search(r"[^\W\d_]{3}", core)
    )


def redact(text: str, terms: list[str] | None = None) -> str:
    t = _ZERO_WIDTH.sub("", str(text or ""))
    t = _mask_emails(t)
    t = _URL.sub(lambda m: f"<URL:{m.group(1).lower().removeprefix('www.')}>", t)
    t = _IBAN.sub("<NUMBER>", t)
    t = _PHONE.sub("<PHONE>", t)
    t = _LONG_NUMBER.sub("<NUMBER>", t)
    t = _HANDLE.sub("<NAME>", t)
    for lead in _LEADS:
        t = lead.sub(lambda m: m.group(1) + _mask_names(m.group(2)), t)
    term_set = {x.lower() for x in (terms or []) if x}

    def word(m: re.Match) -> str:
        w = m.group()
        if _PLACEHOLDER.search(w):
            return w
        if _username(w):
            return re.sub(r"\w+", "<NAME>", w, count=1)
        if term_set:
            return re.sub(
                r"[^\W\d_]+", lambda x: "<NAME>" if x.group().lower() in term_set else x.group(), w
            )
        return w

    t = re.sub(r"\S+", word, t)
    return re.sub(r"[ \t]{2,}", " ", t).strip()
