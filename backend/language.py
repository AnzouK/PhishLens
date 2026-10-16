"""
Language of an email, for display ("Language detected: French") and for
the reports users choose to send.

Small and dependency-free: the writing system first (Cyrillic, Arabic,
Devanagari, Han, kana, Hangul, Thai...), then, for Latin script, the
share of common function words of each language. Good enough on a
paragraph; a short or mixed text gives "und" (undetermined) rather than a
guess.
"""

from __future__ import annotations

import re
import unicodedata

# Most frequent short words, chosen to be specific to one language.
_WORDS: dict[str, frozenset[str]] = {
    lang: frozenset(words.split())
    for lang, words in {
        "en": "the and you your for with this that have are was will our from not please "
        "account click here thank thanks dear has been which would there their",
        "fr": "le la les des une est vous votre pour avec dans sur pas que qui nous ce cette "
        "sont mais au aux merci bonjour cordialement été ou du",
        "pt": "o os as uma não você seu sua para com por está são mais muito obrigado olá "
        "também foi pelo pela isso aqui seus suas nosso",
        "es": "el los las una usted su sus para con por está son más muy gracias hola "
        "también fue del al este esta nuestro hemos puede",
        "de": "der die das und ist nicht sie ihr ihre mit für auf ein eine den dem zu "
        "von bitte danke wir sind wird werden haben auch",
        "it": "il lo gli una è non sono per con della del che questo questa grazie "
        "ciao anche più suo sua nostro abbiamo può alla",
        "nl": "de het een en van is niet u uw voor met op dat deze zijn wordt ons "
        "bedankt hallo ook naar wij kunt worden heeft",
        "pl": "nie się jest na to że do jak za od dla oraz jest pan pani dziękujemy "
        "twoje twój konto proszę może są",
        "tr": "ve bir bu için ile da de değil olarak hesabınız lütfen teşekkürler "
        "sizin daha çok gibi ancak",
        "id": "dan yang di untuk dengan ini itu tidak akan dari anda kami terima kasih "
        "akun silakan dapat atau pada",
        "vi": "và của là có không được cho các những bạn này với một tài khoản "
        "chúng tôi xin cảm ơn",
        "sw": "ya wa kwa za katika hii kama asante tafadhali akaunti yako sisi wewe kuwa "
        "kwamba lakini",
        "ha": "ba ne ce ga cikin wannan don kuma shi ita sannu nagode asusun ku mu su "
        "zuwa daga amma",
        "yo": "ati ti fun pe yii won awa jowo eyi wọn ẹ pẹlu lati",
        "ig": "nke bụ maka gị anyị dị ndị ihe nwere biko daalụ",
    }.items()
}

# Words that carry no meaning on their own: the common words above,
# minus those that can be a sign in an email (greetings, "account",
# "click", "please"...), plus a few very short ones. Used to keep the
# explanation readable (text_model.explain).
_KEEP = set(
    [
        "account",
        "click",
        "here",
        "please",
        "dear",
        "thank",
        "thanks",
        "merci",
        "bonjour",
        "cordialement",
        "obrigado",
        "olá",
        "gracias",
        "hola",
        "bitte",
        "danke",
        "grazie",
        "ciao",
        "bedankt",
        "hallo",
        "konto",
        "hesabınız",
        "lütfen",
        "akun",
        "akaunti",
        "tafadhali",
        "asusun",
    ]
)
_SHORT = [
    "a",
    "i",
    "to",
    "of",
    "in",
    "on",
    "it",
    "is",
    "be",
    "as",
    "at",
    "by",
    "or",
    "an",
    "me",
    "my",
    "so",
    "if",
    "do",
    "no",
    "we",
    "he",
    "she",
    "they",
    "them",
    "a",
    "à",
    "en",
    "et",
    "il",
    "je",
    "un",
    "y",
    "o",
    "e",
]
FUNCTION_WORDS = frozenset(
    w for words in _WORDS.values() for w in words if w not in _KEEP
) | frozenset(_SHORT)

# Unicode script of a character, from its name (stable across versions).
_SCRIPT_LANG = (
    ("HANGUL", "ko"),
    ("HIRAGANA", "ja"),
    ("KATAKANA", "ja"),
    ("CJK", "zh"),
    ("CYRILLIC", "ru"),
    ("ARABIC", "ar"),
    ("DEVANAGARI", "hi"),
    ("THAI", "th"),
    ("HEBREW", "he"),
    ("GREEK", "el"),
)
_UKRAINIAN = set("іїєґІЇЄҐ")
_TOKEN = re.compile(r"[^\W\d_]+", re.UNICODE)
_TAG = re.compile(r"<[A-Z]+>")
MIN_WORDS = 6


def _script_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        lang = next((code for key, code in _SCRIPT_LANG if name.startswith(key)), "latin")
        counts[lang] = counts.get(lang, 0) + 1
    return counts


def _without_addresses(text: str) -> str:
    """Drops the words that are links or email addresses."""
    return " ".join(
        w
        for w in text.split()
        if "@" not in w and "http://" not in w.lower() and "https://" not in w.lower()
    )


def detect_language(text: str) -> dict:
    """{"code": ISO 639-1 or "und", "confidence": 0..1}."""
    text = _TAG.sub(" ", _without_addresses(str(text or "")[:20_000]))
    scripts = _script_counts(text)
    letters = sum(scripts.values())
    if not letters:
        return {"code": "und", "confidence": 0.0}
    top, n = max(scripts.items(), key=lambda kv: kv[1])
    # One Han, kana or Hangul character is about one word.
    if letters < (8 if top in ("zh", "ja", "ko") else 20):
        return {"code": "und", "confidence": 0.0}
    if top != "latin" and n / letters >= 0.3:
        # Japanese mixes kana with Han characters: any kana means Japanese.
        if top == "zh" and scripts.get("ja"):
            top = "ja"
        if top == "ru" and any(ch in _UKRAINIAN for ch in text):
            top = "uk"
        return {"code": top, "confidence": round(min(1.0, n / letters), 2)}
    words = [w.lower() for w in _TOKEN.findall(text)]
    if len(words) < MIN_WORDS:
        return {"code": "und", "confidence": 0.0}
    hits = {lang: sum(w in vocab for w in words) for lang, vocab in _WORDS.items()}
    best = max(hits, key=hits.get)
    ranked = sorted(hits.values(), reverse=True)
    if ranked[0] < 3:
        return {"code": "und", "confidence": 0.0}
    # Confidence: how far ahead of the runner-up, and how dense the hits are.
    margin = (ranked[0] - ranked[1]) / ranked[0]
    density = min(1.0, ranked[0] / (0.15 * len(words)))
    return {"code": best, "confidence": round(0.5 * margin + 0.5 * density, 2)}
