"""
PhishLens: reading a raw .eml.

Gets the visible text, the links and the headers out of a message and
works out a few structural signals, such as forwarded mail and links to
file-sharing services.

Everything here runs in linear time and caps what it reads. Attackers
control the input, so there is no backtracking regex on it.
"""

from __future__ import annotations

import html as html_lib
import re
import warnings
from email import message_from_bytes, policy
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from hidden_content import generated_text, hidden_tags, shown_link, shown_maps, visible_text_first
from link_alignment import browser_path, browser_url, link_host
from settings import MAX_EMAIL_URLS, MAX_LINK_URLS, MAX_PAGE_TEXT_CHARS
from unicode_text import without_invisible

# A body that is only an address is still an email to read. Without this,
# BeautifulSoup logs a warning for each one.
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# URLs written out in text. Mail programs make "www." addresses clickable
# too, so we match those as well.
URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]}]+", re.IGNORECASE)


def urls_in_text(text: str) -> list[str]:
    # Trailing punctuation belongs to the sentence. Invisible characters go
    # first because a browser drops them from a host ("evil\u200b.tk"
    # opens evil.tk).
    out = []
    for u in URL_IN_TEXT_RE.findall(without_invisible(text or "")):
        u = u[:2048].rstrip(".,;:!?")
        out.append(browser_url(u if u[:4].lower() != "www." else "http://" + u))
    return out


_BLOCKS = ["p", "div", "tr", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "table", "pre"]


def html_to_text(html_src: str) -> str:
    """Return the text Gmail would show for an HTML body, hidden text last.

    We drop <style>, <script> and <head>. A plain tag strip used to keep
    the CSS ("25px", "roboto", "heading") and the text model read it as words.
    """
    soup = BeautifulSoup(without_inline_data(html_src)[:_MAX_PARSED], "html.parser")
    hidden = hidden_tags(soup)  # before the <style> sheets go
    generated = generated_text(soup, hidden)
    # <iframe>, <noembed> and <noframes> hold fallback content that
    # browsers and Gmail never show.
    for tag in soup(
        ["style", "script", "head", "noscript", "title", "iframe", "noembed", "noframes"]
    ):
        tag.decompose()
    # Insert newlines where the page breaks lines. detect_forwarded needs
    # the "---------- Forwarded message ---------" marker at the start of
    # a line, and some HTML has no newlines at all.
    for br in soup.find_all("br", limit=50_000):
        br.replace_with("\n")
    for block in soup.find_all(_BLOCKS, limit=50_000):
        block.insert_after("\n")
    text = visible_text_first(soup, hidden, generated)
    # Collapse whitespace per line without a regex to stay linear.
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def html_links(html_src: str, limit: int = 200) -> list[str]:
    """Return the http(s) link targets of an HTML document, visible ones first.

    We parse the HTML the way a browser does. The old regex on
    'href="https://' missed 'href = "...' and '&#104;ttps://'.
    """
    visible, hidden = html_link_groups(html_src)
    return rank_links(visible, hidden, limit=limit)


def html_link_groups(html_src: str) -> tuple[list[str], list[str]]:
    """Return visible and hidden link targets as two lists.

    Keeping them apart stops a hidden link from being ranked ahead of a
    visible one.
    """
    cleaned = without_inline_data(html_src)
    soup = BeautifulSoup(cleaned[:_MAX_PARSED], "html.parser")
    hidden_ids = {id(tag) for tag in hidden_tags(soup)}
    maps = shown_maps(soup, hidden_ids)
    visible, hidden, unknown = [], [], []
    shown, checked = set(), 0
    # We look at every link but only run the visibility check on 20,000.
    # Capping the links themselves would let copies of a decoy push the
    # real one out.
    for tag in soup.find_all(["a", "area"]):
        # SVG links use xlink:href.
        href = tag.get("href") or tag.get("xlink:href")
        url = absolute_http(href) if href else ""
        if not url or url in shown:
            continue
        checked += 1
        if checked > 20_000:
            unknown.append(url)
        elif shown_link(tag, hidden_ids, maps):
            shown.add(url)
            visible.append(url)
        else:
            hidden.append(url)
    # Links past the parsed part (behind padding or a huge comment) are
    # still read. We can't tell if they are visible, so they go first among
    # the hidden ones where a flood of hidden decoys can't push them out.
    # Padding usually comes before the lure, so we take the last 1,000 and
    # then the first 1,000. See R13 in docs/threat-model.md.
    tail = list(
        dict.fromkeys(
            u
            for u in (
                absolute_http(_attr_value(m)) for m in _LINK_ATTR_RE.finditer(cleaned, _MAX_PARSED)
            )
            if u and u not in shown
        )
    )
    unknown += tail[::-1] if len(tail) <= 2000 else tail[:-1001:-1] + tail[:1000]
    return visible, list(dict.fromkeys([*unknown, *hidden]))


def absolute_http(href: str) -> str:
    """Return the http(s) URL a browser would open for this href, or "".

    Browsers strip control characters and spaces, treat "//host/..." as
    https and accept odd forms like "HTTPS:evil.tk" or backslashes.
    link_alignment.browser_url does the normalising.
    """
    href = "".join(c for c in str(href)[:2048] if c > " " and c != "\x7f")
    if href.startswith(("//", "\\\\", "/\\", "\\/")):
        href = "https://" + href.lstrip("/\\")
    href = browser_url(href)
    return href if href[:8].lower().startswith(("http://", "https://")) else ""


# Gmail gives up on very large HTML and shows the source as text, inline
# images included. The text model reads that as phishing, so we strip it.
# We only match base64 in lines of 40 characters or more (a wrapped data
# URI uses 76). Allowing short lines also ate the words after
# "data:text/plain;base64,". A short last line is left as one stray word.
_DATA_URI_RE = re.compile(
    r"data:[\w/+.-]{1,100};base64,[A-Za-z0-9+/=]{40,8000000}(?:\r?\n[A-Za-z0-9+/=]{40,8000000})*"
)
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
# A tag, or a tag cut off at the end of a truncated page text. _markup
# decides whether it is real markup, because '<a Urgent: verify your
# account...' is a sentence.
_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]{0,20}(?P<inner>\s[^<>]{0,2000})?(?:/?>|\Z)")


_ATTR_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ATTR_NAME = _ATTR_START | frozenset("0123456789:.-")
# Page texts are cut at MAX_PAGE_TEXT_CHARS (PL.MAX_RAW_TEXT in
# content_scripts/core.js), so the last tag may have lost its closing quote.
_CUT_AT = MAX_PAGE_TEXT_CHARS - 100


def _attributes(inner: str, cut_off: bool = False) -> bool:
    """Return True if `inner` looks like HTML attributes with at least one value.

    'class="x" hidden' passes. 'Urgent: verify your account at
    https://x.example/?id=1' does not. Attribute names start with a letter
    and don't end in ":" or ".", which words in a sentence often do. We
    allow at most three bare names in a row. A quoted value must be closed
    unless the text was cut there or the value has no space. One pass, no regex.
    """
    i, n, pairs, bare = 0, len(inner), 0, 0
    while i < n:
        while i < n and inner[i].isspace():
            i += 1
        if i >= n:
            break
        if inner[i] == "/" and not inner[i + 1 :].strip():
            break  # '<img src="x" />'
        if inner[i] not in _ATTR_START:
            return False

        while i < n and inner[i] in _ATTR_NAME:
            i += 1
        if inner[i - 1] in ":." or (i < n and not inner[i].isspace() and inner[i] not in "=/"):
            return False
        while i < n and inner[i].isspace():
            i += 1
        if i < n and inner[i] == "=":
            i = _value_end(inner, i + 1, cut_off)
            if i < 0:
                return False
            pairs, bare = pairs + 1, 0
        else:
            bare += 1
            if bare > 3:
                return False
    return pairs > 0


def _value_end(inner: str, i: int, cut_off: bool) -> int:
    """Return the end of the attribute value at `i`, or -1 if it isn't one.

    A quoted sentence is not a value. Neither is a quote left open when the
    text wasn't cut there, unless the value has no spaces (a long data: URI
    has none, a sentence does).
    """
    n = len(inner)
    while i < n and inner[i].isspace():
        i += 1
    if i < n and inner[i] in "\"'":
        end = inner.find(inner[i], i + 1)
        if _sentence(inner[i + 1 : n if end < 0 else end]):
            return -1
        if end < 0 and not cut_off and any(c.isspace() for c in inner[i:].strip()):
            return -1
        return n if end < 0 else end + 1
    while i < n and not inner[i].isspace() and inner[i] not in "\"'=`":
        i += 1
    return i


def _sentence(value: str) -> bool:
    """Return True if a quoted value reads like prose.

    That means more than eight words and no ";" (styles have some), or a
    URL after a space. A real tag with a long alt text also ends up kept as
    words, which does no harm.
    """
    words = value.split()
    return (len(words) > 8 and ";" not in value) or any(
        w.lower().startswith(("http://", "https://")) for w in words[1:]
    )


def _markup(m: re.Match) -> str:
    """Drop the tag if it is real markup and keep anything else as words."""
    inner = m.group("inner") or ""
    cut_off = m.end() == len(m.string) and len(m.string) >= _CUT_AT
    if not m.group(0).endswith(">") and not cut_off and not _short_cut_tag(inner):
        return m.group(0)
    return " " if inner.strip() in ("", "/") or _attributes(inner, cut_off) else m.group(0)


def _short_cut_tag(inner: str) -> bool:
    """Return True if an unclosed tag at the end of the text is markup.

    A source page cut inside an <img> leaves a short tag with no URL. A
    sentence written after "<a x=" does not look like that.
    """
    return len(inner.split()) <= 12 and "http" not in inner.lower()


# Inline data URIs as browsers accept them: any case, parameters such as
# ";charset=utf-8" before base64, and white space inside.
_INLINE_DATA_RE = re.compile(
    r"data:[\w/+.-]{1,100}(?:;[\w.+-]{1,40}(?:=[\w.+\"-]{1,60})?){0,8};base64,[A-Za-z0-9+/=\s]{40,8000000}",
    re.IGNORECASE,
)
# How much of an HTML body we parse. Links past this point are still read
# with _LINK_ATTR_RE.
_MAX_PARSED = 1_000_000
# href of an <a> or <area> in raw HTML, quoted or not. Browsers drop
# spaces inside the quotes, so we allow them.
_LINK_ATTR_RE = re.compile(
    r"""<(?:a|area)\b[^<>]{0,2000}?(?<![\w.:-])(?:href|xlink:href)\s*=\s*"""
    r"""(?:"([^"]{1,2048})"|'([^']{1,2048})'|([^\s"'<>]{1,2048}))""",
    re.IGNORECASE,
)


def _attr_value(m: re.Match) -> str:
    return html_lib.unescape(m.group(1) or m.group(2) or m.group(3) or "").strip()


def without_inline_data(html_src: str) -> str:
    """Strip inline images and long comments from HTML before parsing.

    A newsletter with a 600 KB inline banner pushed every link past the
    parse limit and showed none. Links inside long comments, such as
    Outlook's "<!--[if mso]>" buttons, are kept as empty links so they are
    checked but never shown.
    """
    return _without_long_comments(_INLINE_DATA_RE.sub("", html_src[:10_000_000]))


# Start of markup as the HTML tokenizer sees it. "<!", "<?" or "</" not
# followed by an ASCII letter opens a bogus comment that runs to the next
# ">", as in html.parser. "</>" is an empty one and a trailing "</" is text.
_MARKUP_START_RE = re.compile(r"<(?:!--|[a-zA-Z]|/[a-zA-Z]|[!?/])")
# Raw text elements. Inside them "<!--" or "<style" opens nothing, both
# in browsers and in html.parser. <noscript> is left out because
# html.parser and mail readers run with scripting off and parse it as
# markup. <plaintext> turns the rest of the document into text.
_RAW_TEXT_OPEN_RE = re.compile(
    r"<(style|script|title|textarea|xmp|iframe|noembed|noframes|plaintext)(?=[\t\n\f\r />])",
    re.IGNORECASE | re.ASCII,
)
_RAW_TEXT_CLOSE_RE = {
    name: re.compile(rf"</{name}(?=[\t\n\f\r />])", re.IGNORECASE | re.ASCII)
    for name in ("style", "script", "title", "textarea", "xmp", "iframe", "noembed", "noframes")
}
# The rest of a tag after "<" or "</", read like the HTML tokenizer does.
# A value is only quoted if it starts with a quote, so in a=b=" the value
# is b=" and no quote opens. An unclosed quote runs to the end of the text.
_TAG_REST_RE = re.compile(
    r"""[^\t\n\f\r />]*"""
    r"""(?:[\t\n\f\r /]+"""
    r"""|[^\t\n\f\r />][^\t\n\f\r />=]*"""
    r"""(?:[\t\n\f\r ]*=[\t\n\f\r ]*(?:"[^"]*(?:"|\Z)|'[^']*(?:'|\Z)|[^\t\n\f\r >]*))?)*""",
)
# Comments end at "-->" or "--!>". "<!-->" and "<!--->" are complete,
# empty comments.
_COMMENT_END_RE = re.compile(r"--!?>")


def _tag_end(src: str, i: int) -> int:
    """Return the index just past the ">" that closes the tag at src[i].

    A ">" inside a quoted value doesn't count. Returns len(src) if the tag
    never closes.
    """
    m = _TAG_REST_RE.match(src, i + 2 if src.startswith("</", i) else i + 1)
    end = m.end()
    return end + 1 if end < len(src) and src[end] == ">" else len(src)


def _comment_end(src: str, start: int) -> int:
    """Return the index just past the comment at src[start], or len(src)."""
    if src.startswith(">", start + 4):
        return start + 5
    if src.startswith("->", start + 4):
        return start + 6
    m = _COMMENT_END_RE.search(src, start + 4)
    return len(src) if m is None else m.end()


def _without_long_comments(src: str) -> str:
    """Remove long comments, including bogus ones like "<!x", "<?x" or "</1".

    A comment the browser never shows can still push text and links past
    _MAX_PARSED, or make html.parser merge its surroundings into one tag.
    We walk the HTML in order like a browser. "<!--" inside a raw text
    element such as <style> is not a comment, so the sheet's rules still
    apply. "<style" or "<!--" inside an attribute value opens nothing.

    We search the original text and never a lowercased copy, because
    lowercasing can change the length.
    """
    out, pos, i, n = [], 0, 0, len(src)
    while True:
        m = _MARKUP_START_RE.search(src, i)
        if not m:
            break
        start = m.start()
        if m.group() in ("<!--", "<!", "<?", "</"):
            if m.group() == "<!--":
                end = _comment_end(src, start)
            else:
                end = src.find(">", start + 2)
                end = n if end < 0 else end + 1
            if end - start > 500:
                out.append(src[pos:start])
                for link in _LINK_ATTR_RE.finditer(src, start, end):
                    url = _attr_value(link)
                    if url:
                        out.append(f'<a href="{html_lib.escape(url)}"></a>')
                pos = end
            i = end
        else:
            i = _tag_end(src, start)
            raw = _RAW_TEXT_OPEN_RE.match(src, start)
            if raw:
                name = raw.group(1).lower()
                if name == "plaintext":
                    break
                close = _RAW_TEXT_CLOSE_RE[name].search(src, i)
                i = n if close is None else close.start()
    out.append(src[pos:])
    return "".join(out)


def strip_markup_noise(text: str) -> str:
    """Strip data URIs, long base64 runs and tags from a page text that is HTML source."""
    text = _DATA_URI_RE.sub(" ", text)
    text = _BASE64_RUN_RE.sub(" ", text)
    text = _TAG_RE.sub(_markup, text)
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def looks_like_source(text: str) -> bool:
    """Return True if most of a page text is markup or inline data."""
    if not text:
        return False
    return len(strip_markup_noise(text)) < 0.5 * len(text.strip())


def is_page_source(text: str) -> bool:
    """Return True if Gmail showed the HTML source instead of the email.

    Gmail does this for very large HTML. We require at least half the text
    to be tags and data URIs, since a long base64 run or a few tags are just
    noise. The caller then scores the parsed message instead, with its
    <style> rules applied by hidden_content.
    """
    text = text[:200_000]
    if not looks_like_source(text):
        return False
    if not text.lstrip().startswith("<"):
        return False  # a page's source starts with its markup
    tags = [len(m.group(0)) for m in _TAG_RE.finditer(text) if _markup(m) == " "]
    data = [len(m.group(0)) for m in _DATA_URI_RE.finditer(text)]
    # Need an inline image or at least ten tags. A few tags in prose are
    # not a page.
    return (bool(data) or len(tags) >= 10) and sum(tags) + sum(data) >= 0.5 * len(text.strip())


def _body_text(msg, raw_bytes: bytes) -> str:
    """Return the visible text of the email, from the rendered HTML part
    when there is one, from the plain text part otherwise."""
    if not msg.is_multipart():
        try:
            body = msg.get_content()
            return html_to_text(body) if msg.get_content_type() == "text/html" else body
        except Exception:
            return raw_bytes.decode("utf-8", errors="ignore")
    # Prefer the HTML part because that is what the reader sees. The
    # plain-text alternative spells out every URL, which pushes the text
    # model toward phishing.
    for kind, render in (("text/html", html_to_text), ("text/plain", str)):
        for part in msg.walk():
            if part.get_content_type() != kind or part.is_attachment():
                continue
            try:
                body = render(part.get_content())
            except Exception:
                continue
            if body.strip():
                return body
    return ""


def _link_targets(msg, body: str) -> list[str]:
    """Return the HTML part's link targets, then the URLs written in the text.

    An HTML email shows "Click here" and keeps the address in the href, so
    the hrefs come first.
    """
    visible: list[str] = []
    hidden: list[str] = []
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_type() != "text/html":
            continue
        try:
            shown, unseen = html_link_groups(part.get_content())
        except Exception:
            continue
        visible += shown
        hidden += unseen
    return rank_links(visible, hidden, urls_in_text(body))


def _raw_items(msg) -> list[tuple[str, str]]:
    """Return the headers as written rather than as the standard parser rebuilds them.

    The modern parser silently drops what it can't parse, so
    '"PayPal" <service@paypal.com> <scam@evil.example>' came back as
    '"PayPal" <service@paypal.com>'. Our checks need to see what mail
    programs see. 8-bit bytes are read as UTF-8 and header_dict decodes
    encoded words.
    """
    items = []
    for k, v in msg.raw_items():
        value = str(v)
        if any("\udc80" <= c <= "\udcff" for c in value):
            value = value.encode("ascii", "surrogateescape").decode("utf-8", "replace")
        items.append((k, value))
    return items


def parse_eml(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Return (body_text, urls_list, headers_dict).

    If the standard parser rejects a message we fall back to a lenient
    read. Otherwise a crafted email could avoid the scan by failing to parse.
    """
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.default)
        body = _body_text(msg, raw_bytes)
        return body.strip(), _link_targets(msg, body), header_dict(_raw_items(msg))
    except Exception:
        return _parse_lenient(raw_bytes)


def _decoded(part) -> str:
    data = part.get_payload(decode=True)
    if not isinstance(data, bytes):
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, errors="replace")
    except LookupError:  # unknown charset name
        return data.decode("utf-8", errors="replace")


def _parse_lenient(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Parse with the legacy compat32 policy, or return the raw text if that fails too."""
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.compat32)
        headers = header_dict((k, v) for k, v in msg.items() if isinstance(v, str))
        texts = {"text/html": "", "text/plain": ""}
        for part in msg.walk():
            kind = part.get_content_type()
            if kind in texts and not texts[kind] and not part.get_filename():
                texts[kind] = _decoded(part)
        html = html_to_text(texts["text/html"]) if texts["text/html"] else ""
        body = (html if html.strip() else texts["text/plain"]).strip()
        urls = rank_links(*html_link_groups(texts["text/html"]), urls_in_text(body))
        if body or urls:
            return body, urls, headers
    except Exception:
        headers = {}
    text = raw_bytes[:1_000_000].decode("utf-8", errors="replace")
    _head, _sep, rest = text.partition("\n\n")
    body = (rest or text).strip()
    return body, urls_in_text(body), headers


# Each relay adds these on top, so the topmost one comes from the
# receiving provider. Lower copies come from earlier hops (an internal
# Microsoft 365 relay writes "dkim=none") or from the sender, who can
# write anything. From:, Sender:, Reply-To: and Subject: should appear
# once. When a crafted message repeats them, mail programs show the
# first, so we read the first too.
_TOPMOST_WINS = frozenset(
    {
        "authentication-results",
        "arc-authentication-results",
        "from",
        "sender",
        "reply-to",
        "subject",
    }
)
# Marks a From: that proves nothing, because it repeats or is still longer
# than MAX_HEADER_CHARS after collapsing spaces. It mirrors
# auth_headers.FROM_UNPROVEN. Importing it would create a cycle.
FROM_UNPROVEN = "x-phishlens-from-unproven"
# The backend sets this when the scored text was cut and the forward
# marker only appears in the part left out. Like FROM_UNPROVEN, it is
# never read from the message itself.
FORWARDED_ELSEWHERE = "x-phishlens-forwarded"
# We collapse spaces before cutting at this length, so padding can't push
# the real address out of view.
MAX_HEADER_CHARS = 8000
_MAX_RAW_HEADER = 1_000_000


def header_dict(items) -> dict[str, str]:
    """Map lowercased header names to values with spaces collapsed.

    A repeated header keeps its last value, except those in _TOPMOST_WINS,
    which keep the first. A repeated or over-long From: is recorded under
    FROM_UNPROVEN.

    We only read the topmost Authentication-Results, even from servers that
    write one per check (Postfix with OpenDKIM and OpenDMARC). Position
    can't tell the receiver's header from one the sender wrote, since on
    Gmail the sender's copy sits right below Gmail's. Reading a second one
    would let the sender supply the result it wants. The worst case is a
    missed softer verdict on such mail, never a harsher one.
    """
    headers: dict[str, str] = {}
    for k, v in items:
        key = k.lower()
        if key in (FROM_UNPROVEN, FORWARDED_ELSEWHERE):
            continue
        if key in _TOPMOST_WINS and key in headers:
            if key == "from":
                headers[FROM_UNPROVEN] = "1"
            continue
        raw = str(v)
        # Clean before cutting. A From: padded with 32,000 spaces or
        # zero-width characters must not hide its second address. If it is
        # still too long to read whole, it proves nothing.
        decoded = _decoded_header(raw[:_MAX_RAW_HEADER], address=key in _ADDRESS_HEADERS)
        decoded = without_invisible(decoded)
        value = " ".join(decoded.split())
        if len(value) > MAX_HEADER_CHARS or len(raw) > _MAX_RAW_HEADER:
            value = value[:MAX_HEADER_CHARS]
            if key == "from":
                headers[FROM_UNPROVEN] = "1"
        headers[key] = value
    return headers


_ENCODED_WORD_RE = re.compile(r"=\?[^?\s]{1,40}\?[qQbB]\?[^?\s]{0,2000}\?=")
# A run of encoded words, with the white space between them.
_ENCODED_RUN_RE = re.compile(
    r"=\?[^?\s]{1,40}\?[qQbB]\?[^?\s]{0,2000}\?="
    r"(?:\s*=\?[^?\s]{1,40}\?[qQbB]\?[^?\s]{0,2000}\?=){0,50}"
)
_ADDRESS_HEADERS = frozenset({"from", "reply-to", "sender", "to", "cc", "return-path"})
# Characters with a meaning in an address header (RFC 5322 specials).
_SPECIALS = frozenset('()<>[]:;@\\,."')


def _quoted_at(text: str) -> list[bool]:
    """Return, per character, whether it sits inside a quoted string."""
    out, quoted, escaped = [], False, False
    for ch in text:
        out.append(quoted)
        if escaped:
            escaped = False
        elif ch == "\\" and quoted:
            escaped = True
        elif ch == '"':
            quoted = not quoted
    return out


def _decoded_header(value: str, address: bool = False) -> str:
    """Decode RFC 2047 encoded words the way mail programs display them.

    Each word is decoded wherever it stands, even inside quotes or next to
    "<". Lines are unfolded first and the space between two adjacent
    encoded words is dropped, so "=?..?UGF5?=" and "=?..?UGFs?=" on two
    lines give "PayPal". Words we can't decode stay as written.

    In address headers a decoded name must stay a name. Inside quotes we
    escape the decoded quotes and backslashes so '"=?..?a"<x@paypal>"b?="'
    can't break out. Before the address, a decoded name containing "<",
    "@" or "," gets quoted. Google Docs sends names like
    'André <andre@gmail.com> (via Docs)' this way. After the last address
    nothing is quoted, so an encoded address there is read as an address.
    """
    if "=?" not in value:
        return value
    from email.header import decode_header, make_header

    value = " ".join(value.split())
    quoted = _quoted_at(value) if address else []

    def word(m: re.Match) -> str:
        try:
            return str(make_header(decode_header(m.group(0))))
        except Exception:
            return m.group(0)

    def run(m: re.Match) -> str:
        text = _ENCODED_WORD_RE.sub(word, re.sub(r"(\?=)\s+(?==\?)", r"\1", m.group(0)))
        if not address:
            return text
        escaped = text.replace("\\", "\\\\").replace('"', '\\"')
        if quoted[m.start()]:
            return escaped
        if "@" in value[m.end() :] and _SPECIALS.intersection(text):
            return f'"{escaped}"'
        return text

    return _ENCODED_RUN_RE.sub(run, value)


# Forwarded emails. The From: of a forward is whoever forwarded it, so
# sender trust must not vouch for the forwarded content.
_FORWARD_MARKERS = re.compile(
    r"^[ \t]*(?:-{2,}[ \t]*(?:forwarded message|original message|message transf[ée]r[ée]|"
    r"message d'origine|mensaje reenviado|mensaje original)[ \t]*-{2,}"
    r"|begin forwarded message\s*:"
    r"|d[ée]but du message (?:r[ée]exp[ée]di[ée]|transf[ée]r[ée])\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
# Fwd:, TR:, WG: and friends, possibly after reply prefixes ("Re: Fwd:").
_FORWARD_SUBJECT = re.compile(
    r"^\s*(?:(?:re|res|aw|sv|antw|r)\s*:\s*){0,10}(?:fwd?|tr|wg|rv|enc)\s*:", re.IGNORECASE
)
_FORWARD_FROM_KEYS = ("from", "de", "von")


def _forwarded_sender(tail: str) -> str | None:
    """Return the first "From:" or "De :" line of the forwarded block.

    CodeQL flagged the regex versions as polynomial, so this is a plain
    loop over at most 40 lines of 300 characters.
    """
    for line in tail.splitlines()[:40]:
        key, sep, value = line[:300].partition(":")
        if sep and key.strip().lower() in _FORWARD_FROM_KEYS:
            _name, addr = parseaddr(value.strip())
            if "@" in addr and " " not in addr and "." in addr.rsplit("@", 1)[-1]:
                return addr.lower()
            return None
    return None


def detect_forwarded(body: str, subject: str | None = None) -> dict[str, Any]:
    """Return {"detected": bool, "original_sender": str | None}.

    A marker line in the body is enough. A Fwd: or TR: subject prefix also
    counts on its own, because clients that inline the forwarded text don't
    always add a marker.
    """
    body = body or ""
    m = _FORWARD_MARKERS.search(body)
    detected = bool(m) or bool(subject and _FORWARD_SUBJECT.match(subject))
    original = None
    if detected:
        tail = body[m.end() :] if m else body
        original = _forwarded_sender(tail[:5000])
    return {"detected": detected, "original_sender": original}


# File-sharing and form services. The domains are legitimate (Google,
# Microsoft, Dropbox), so the URL agent and threat intel rarely flag them,
# yet the shared file or form is often the lure. We show this to the user
# and leave the score alone.
_SHARE_SERVICES = [
    (re.compile(r"(?:^|\.)docs\.google\.com$"), r"^/forms/", "Google Forms"),
    (re.compile(r"(?:^|\.)forms\.gle$"), None, "Google Forms"),
    (re.compile(r"(?:^|\.)drive\.google\.com$"), None, "Google Drive"),
    (re.compile(r"(?:^|\.)docs\.google\.com$"), None, "Google Docs"),
    (
        re.compile(r"(?:^|\.)(?:firebasestorage|storage)\.googleapis\.com$"),
        None,
        "Google Cloud Storage",
    ),
    (re.compile(r"(?:^|\.)(?:1drv\.ms|onedrive\.live\.com)$"), None, "OneDrive"),
    (re.compile(r"(?:^|\.)sharepoint\.com$"), None, "SharePoint"),
    (re.compile(r"(?:^|\.)forms\.(?:office|microsoft)\.com$"), None, "Microsoft Forms"),
    (re.compile(r"(?:^|\.)(?:dropbox\.com|dropboxusercontent\.com|db\.tt)$"), None, "Dropbox"),
    (re.compile(r"(?:^|\.)(?:wetransfer\.com|we\.tl)$"), None, "WeTransfer"),
    (re.compile(r"(?:^|\.)box\.com$"), None, "Box"),
    (re.compile(r"(?:^|\.)mega\.nz$"), None, "MEGA"),
    (re.compile(r"(?:^|\.)mediafire\.com$"), None, "MediaFire"),
    (re.compile(r"(?:^|\.)docsend\.com$"), None, "DocSend"),
    (re.compile(r"(?:^|\.)icloud\.com$"), r"^/iclouddrive/", "iCloud Drive"),
]


def detect_shared_links(urls: list[str]) -> dict[str, Any]:
    """Return {"count": int, "services": [names], "urls": [first 10]}."""
    services: list[str] = []
    hits: list[str] = []
    for u in urls:
        try:
            parts = urlsplit(browser_url(u))
        except ValueError:
            continue
        host = link_host(u)
        for host_re, path_re, name in _SHARE_SERVICES:
            path = browser_path(parts.path)
            if host_re.search(host) and (path_re is None or re.match(path_re, path)):
                hits.append(u)
                if name not in services:
                    services.append(name)
                break
    return {"count": len(hits), "services": services, "urls": hits[:10]}


def client_links(extra: Any) -> list[str]:
    """Link targets sent by the client (client_context.link_urls).

    The client is untrusted. We keep only http(s) strings, cut each one at
    2048 characters (the host survives, and that is what the checks read),
    drop duplicates and stop at MAX_LINK_URLS.
    """
    if not isinstance(extra, list):
        return []
    out: list[str] = []
    for u in extra:
        if len(out) >= MAX_LINK_URLS:
            break
        if not isinstance(u, str):
            continue
        u = u[:20_000].strip()[:2048]
        u = browser_url(u)
        if re.match(r"https?://", u) and u not in out:
            out.append(u)
    return out


class Ranked(list):
    """Mark a list as already ranked so rank_links keeps its order.

    Ranking it again as one group would move its hidden links ahead of its
    second visible ones.
    """


def rank_links(*groups: list[str], limit: int = MAX_EMAIL_URLS) -> Ranked:
    """Return up to `limit` links, taking the groups in the order given.

    Link targets come before URLs written in the text, and a later group can
    never push out an earlier one. Within a group the first link of each
    host comes before any repeat, so a pile of links to one site can't
    crowd out the rest.
    """
    seen: set[str] = set()
    out: list[str] = []
    for group in groups:
        if isinstance(group, Ranked):
            fresh = [u for u in group if u not in seen]
            seen.update(fresh)
            out += fresh
            if len(out) >= limit:
                break
            continue
        hosts: set[str] = set()
        first, rest = [], []
        for u in group:
            if u in seen:
                continue
            seen.add(u)
            host = link_host(u)
            (rest if host in hosts else first).append(u)
            hosts.add(host)
        out += first + rest
        if len(out) >= limit:
            break
    return Ranked(out[:limit])
