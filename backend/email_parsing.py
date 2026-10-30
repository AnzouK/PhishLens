"""
Reading an email: the visible text, the links and the headers of a raw
.eml, plus the structural signals computed from them (forwarded emails,
links to file-sharing services).

Every parser here is linear on its input (no backtracking regex on
attacker-controlled text) and caps what it reads.
"""

from __future__ import annotations

import re
import warnings
from email import message_from_bytes, policy
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from hidden_content import generated_text, hidden_tags, shown_link, shown_maps, visible_text_first
from link_alignment import browser_url, link_host
from settings import MAX_EMAIL_URLS, MAX_LINK_URLS
from unicode_text import without_invisible

# An email that is only an address is still an email to read, not a
# mistake to warn about (each warning went to the server log).
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# http(s) URL written out in a text, in any case, or starting with
# "www." (mail programs make both clickable).
URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s\"'<>)\]}]+", re.IGNORECASE)


def urls_in_text(text: str) -> list[str]:
    # Punctuation that ends the sentence is not part of the address.
    # Invisible characters out first: a browser drops a zero-width space
    # from a host ("evil\u200b.tk" opens evil.tk), the match must too.
    out = []
    for u in URL_IN_TEXT_RE.findall(without_invisible(text or "")):
        u = u.rstrip(".,;:!?")
        out.append(browser_url(u if u[:4].lower() != "www." else "http://" + u))
    return out


_BLOCKS = ["p", "div", "tr", "li", "blockquote", "h1", "h2", "h3", "h4", "h5", "h6", "table", "pre"]


def html_to_text(html_src: str) -> str:
    """Visible text of an HTML email body, like the text Gmail shows, with
    the text of hidden elements after it (visible_text_first).

    <style>, <script> and <head> contents are dropped: a plain tag strip
    kept the CSS ("25px", "roboto", "heading"...) and the text model read
    it as words.
    """
    soup = BeautifulSoup(without_inline_data(html_src)[:1_000_000], "html.parser")
    hidden = hidden_tags(soup)  # before the <style> sheets go
    generated = generated_text(soup, hidden)
    for tag in soup(["style", "script", "head", "noscript", "title"]):
        tag.decompose()
    # Line breaks where the page breaks lines: a forward's marker line
    # ("---------- Forwarded message ---------") must start a line for
    # detect_forwarded, even when the HTML source has no newline at all.
    for br in soup.find_all("br", limit=50_000):
        br.replace_with("\n")
    for block in soup.find_all(_BLOCKS, limit=50_000):
        block.insert_after("\n")
    text = visible_text_first(soup, hidden, generated)
    # Collapse whitespace line by line (no regex: linear on any input).
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def html_links(html_src: str, limit: int = 200) -> list[str]:
    """http(s) targets of the links of an HTML document, as a browser reads
    them (entities decoded, spaces around "=" allowed, protocol-relative
    "//host" as https), visible links before hidden ones. A regex on
    'href="https://' missed 'href = "...' and '&#104;ttps://'."""
    visible, hidden = html_link_groups(html_src)
    return rank_links(visible, hidden, limit=limit)


def html_link_groups(html_src: str) -> tuple[list[str], list[str]]:
    """(visible, hidden) link targets of an HTML document, kept apart so
    that no hidden link can be ranked before a visible one."""
    soup = BeautifulSoup(without_inline_data(html_src)[:1_000_000], "html.parser")
    hidden_ids = {id(tag) for tag in hidden_tags(soup)}
    maps = shown_maps(soup, hidden_ids)
    visible, hidden = [], []
    for tag in soup.find_all(["a", "area"], href=True, limit=20_000):
        url = absolute_http(tag["href"])
        if url:
            (visible if shown_link(tag, hidden_ids, maps) else hidden).append(url)
    return visible, hidden


def absolute_http(href: str) -> str:
    """An http(s) URL from an href, as a browser reads it, or "": control
    characters and spaces removed, "//host/..." read as https, and the
    forms browsers accept ("HTTPS:evil.tk", backslashes, an encoded host)
    normalised (link_alignment.browser_url)."""
    href = "".join(c for c in str(href)[:2048] if c > " " and c != "\x7f")
    if href.startswith(("//", "\\\\", "/\\", "\\/")):
        href = "https://" + href.lstrip("/\\")
    href = browser_url(href)
    return href if href[:8].lower().startswith(("http://", "https://")) else ""


# Source code shown as text: when a mail page cannot render an email
# (Gmail gives up on very large HTML), its visible text is the HTML
# itself, inline images included. The text model reads that as phishing.
# Base64 only, in lines of 40 characters at least (a wrapped data URI
# has 76): with any whitespace, or short lines, allowed, the words after
# "data:text/plain;base64," were taken for inline data too. A short last
# line stays as text: one meaningless word.
_DATA_URI_RE = re.compile(
    r"data:[\w/+.-]{1,100};base64,[A-Za-z0-9+/=]{40,8000000}(?:\r?\n[A-Za-z0-9+/=]{40,8000000})*"
)
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
# A tag, or one cut off at the end of a truncated page text. Only a tag
# with nothing after its name or with attributes ("=") is markup (see
# _markup): '<a Urgent: verify your account...' is words.
_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]{0,20}(?P<inner>\s[^<>]{0,2000})?(?:/?>|\Z)")


_ATTR_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_ATTR_NAME = _ATTR_START | frozenset("0123456789:.-")
# Page texts are cut at 4,000 characters (content_scripts/core.js): a tag
# cut there may have lost its closing quote.
_CUT_AT = 3900


def _attributes(inner: str, cut_off: bool = False) -> bool:
    """True when `inner` reads as HTML attributes, with at least one value:
    'class="x" hidden' is; 'Urgent: verify your account at
    https://x.example/?id=1' is not. A name starts with a letter and does
    not end in ":" or "." (words of a sentence do), at most three names
    without a value follow each other, and a quoted value is closed unless
    the text was cut there (`cut_off`) or the value has no space. Linear:
    one pass, no regex."""
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
    """Where the attribute value starting at `i` ends, or -1 when it is
    not one: a quoted sentence (_sentence), or a quote left open in a text
    that was not cut there (a long data: URI has no spaces; a sentence
    written after "<a x=" does)."""
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
    """A quoted value that reads as prose: more than eight words and no
    ";" (a style has some), or an address after a space. Such a "tag" is
    a sentence written after "<a x=", kept as words; a real one with a
    long alt text is only kept as words too, which costs nothing."""
    words = value.split()
    return (len(words) > 8 and ";" not in value) or any(
        w.lower().startswith(("http://", "https://")) for w in words[1:]
    )


def _markup(m: re.Match) -> str:
    """The tag removed when it is markup: no attributes ("<p>", "</div>")
    or real ones; left as words otherwise."""
    inner = m.group("inner") or ""
    cut_off = m.end() == len(m.string) and len(m.string) >= _CUT_AT
    if not m.group(0).endswith(">") and not cut_off and not _short_cut_tag(inner):
        return m.group(0)
    return " " if inner.strip() in ("", "/") or _attributes(inner, cut_off) else m.group(0)


def _short_cut_tag(inner: str) -> bool:
    """A tag the text ends in without its ">": markup only when it is
    short and carries no address (a source page cut inside an <img>), not
    a sentence written after "<a x="."""
    return len(inner.split()) <= 12 and "http" not in inner.lower()


def without_inline_data(html_src: str) -> str:
    """HTML without its inline images (data: URIs). A large one before the
    links pushed them past the size the scan reads: a newsletter with a
    600 KB inline banner showed no link at all."""
    return _DATA_URI_RE.sub("", html_src[:10_000_000])


def strip_markup_noise(text: str) -> str:
    """Text without inline data (data: URIs, long base64 runs) and HTML
    tags, for a page text that is really the email's source."""
    text = _DATA_URI_RE.sub(" ", text)
    text = _BASE64_RUN_RE.sub(" ", text)
    text = _TAG_RE.sub(_markup, text)
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def looks_like_source(text: str) -> bool:
    """True when most of a page text is markup or inline data rather
    than words."""
    if not text:
        return False
    return len(strip_markup_noise(text)) < 0.5 * len(text.strip())


def is_page_source(text: str) -> bool:
    """True when a page text is the email's HTML source shown as text
    (Gmail gives up on very large HTML): half of it at least tags and
    data: URIs. A text with a long base64 run, or a few tags written in
    it, is a text with noise, not source. When it is source, the parsed
    message replaces it, read with its <style> rules (hidden_content)."""
    text = text[:200_000]
    if not looks_like_source(text):
        return False
    if not text.lstrip().startswith("<"):
        return False  # a page's source starts with its markup
    tags = [len(m.group(0)) for m in _TAG_RE.finditer(text) if _markup(m) == " "]
    data = [len(m.group(0)) for m in _DATA_URI_RE.finditer(text)]
    # An inline image, or ten tags at least: a few written in a text are
    # not a page.
    return (bool(data) or len(tags) >= 10) and sum(tags) + sum(data) >= 0.5 * len(text.strip())


def _body_text(msg, raw_bytes: bytes) -> str:
    """Visible text of the email: the rendered HTML part first, the plain
    text part otherwise."""
    if not msg.is_multipart():
        try:
            body = msg.get_content()
            return html_to_text(body) if msg.get_content_type() == "text/html" else body
        except Exception:
            return raw_bytes.decode("utf-8", errors="ignore")
    # The rendered HTML part first: it is the text the reader sees, with
    # links behind their labels. Plain-text alternatives spell every URL
    # out, which pushes the text model toward phishing.
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
    """The real targets of the HTML part's links (an HTML email shows
    "Click here", the address is in the href), then the URLs written in
    the text."""
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
    """The headers as written, not as the standard parser rebuilds them:
    it drops what it cannot parse ('"PayPal" <service@paypal.com>
    <scam@evil.example>' became '"PayPal" <service@paypal.com>'), and the
    checks must read what mail programs read. 8-bit bytes are read as
    UTF-8; encoded words are decoded by header_dict."""
    items = []
    for k, v in msg.raw_items():
        value = str(v)
        if any("\udc80" <= c <= "\udcff" for c in value):
            value = value.encode("ascii", "surrogateescape").decode("utf-8", "replace")
        items.append((k, value))
    return items


def parse_eml(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Return (body_text, urls_list, headers_dict).

    A message the standard parser rejects (a malformed header, a broken
    MIME structure) is read leniently instead of refused: a crafted
    email must not escape the scan by failing to parse."""
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
    """The legacy parser, which keeps headers as plain strings and never
    builds header objects; the raw bytes as text when even that fails."""
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


# Headers each relay adds on top of the message: the first (topmost) one
# is the receiving provider's. Lower ones come from earlier hops (an
# internal Microsoft 365 relay says "dkim=none") or from the sender, who
# can write anything there.
# A message has one From:, Sender:, Reply-To: and Subject:; when a crafted
# one repeats them, mail programs show the first, so the checks read it too.
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
# Set when the From: cannot prove a sender: repeated, or longer than
# MAX_HEADER_CHARS once its spaces are collapsed. Same name as
# auth_headers.FROM_UNPROVEN (not imported: no cycle).
FROM_UNPROVEN = "x-phishlens-from-unproven"
# Every header value is kept with its runs of spaces collapsed, cut here:
# 2,000 spaces in a From: used to push the real address past what the
# checks read.
MAX_HEADER_CHARS = 8000
_MAX_RAW_HEADER = 1_000_000


def header_dict(items) -> dict[str, str]:
    """Header name (lowercased) -> value. A repeated header keeps its last
    value, except the ones in _TOPMOST_WINS, which keep the first. A
    repeated From:, or one cut at MAX_HEADER_CHARS, is recorded under
    FROM_UNPROVEN. Values have their runs of spaces collapsed.

    Only the topmost Authentication-Results is read, even from a server
    that writes one per check (Postfix with OpenDKIM and OpenDMARC): the
    receiving server's headers and the sender's cannot be told apart by
    position (on Gmail, the sender's come right after Gmail's), so
    joining a second one would let a sender add the result it wants. The
    cost is a softer path missed on such mail, never a harder one."""
    headers: dict[str, str] = {}
    for k, v in items:
        key = k.lower()
        if key == FROM_UNPROVEN:
            continue
        if key in _TOPMOST_WINS and key in headers:
            if key == "from":
                headers[FROM_UNPROVEN] = "1"
            continue
        raw = str(v)
        # Invisible characters out and spaces collapsed before any cut: a
        # From: padded with 32,000 spaces or zero-width characters must not
        # lose its second address to it. A header too long to read whole
        # proves nothing.
        decoded = _decoded_header(raw[:_MAX_RAW_HEADER])
        decoded = without_invisible(decoded)
        value = " ".join(decoded.split())
        if len(value) > MAX_HEADER_CHARS or len(raw) > _MAX_RAW_HEADER:
            value = value[:MAX_HEADER_CHARS]
            if key == "from":
                headers[FROM_UNPROVEN] = "1"
        headers[key] = value
    return headers


_ENCODED_WORD_RE = re.compile(r"=\?[^?\s]{1,40}\?[qQbB]\?[^?\s]{0,2000}\?=")
_BETWEEN_WORDS_RE = re.compile(r"(\?=)[ \t]+(?==\?)")


def _decoded_header(value: str) -> str:
    """Encoded words ("=?utf-8?b?UGF5UGFs?=") decoded, as a mail program
    shows them: each one on its own, wherever it stands (inside quotes,
    next to "<" or another word), the space between two of them dropped
    (RFC 2047). An undecodable word stays as written."""
    if "=?" not in value:
        return value
    from email.header import decode_header, make_header

    def one(m: re.Match) -> str:
        try:
            return str(make_header(decode_header(m.group(0))))
        except Exception:
            return m.group(0)

    return _ENCODED_WORD_RE.sub(one, _BETWEEN_WORDS_RE.sub(r"\1", value))


# ---------------------------------------------------------------------
# Forwarded emails. The From: of a forward is the person who forwarded it,
# not the author of the content, so sender trust must not cover it.
# ---------------------------------------------------------------------
_FORWARD_MARKERS = re.compile(
    r"^[ \t]*(?:-{2,}[ \t]*(?:forwarded message|original message|message transf[ée]r[ée]|"
    r"message d'origine|mensaje reenviado|mensaje original)[ \t]*-{2,}"
    r"|begin forwarded message\s*:"
    r"|d[ée]but du message (?:r[ée]exp[ée]di[ée]|transf[ée]r[ée])\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
_FORWARD_SUBJECT = re.compile(r"^\s*(?:fwd?|tr|wg|rv|enc)\s*:", re.IGNORECASE)
_FORWARD_FROM_KEYS = ("from", "de", "von")


def _forwarded_sender(tail: str) -> str | None:
    """First "From:" / "De :" line of the forwarded block, parsed without a
    regex (CodeQL flagged the regex versions as polynomial on crafted
    input). Only the first 40 lines and 300 characters per line are read."""
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

    A forward marker in the body is required when there is one; the
    subject prefix (Fwd:, TR:, ...) alone also counts, since mail clients
    that inline the forwarded text do not always add a marker line.
    """
    body = body or ""
    m = _FORWARD_MARKERS.search(body)
    detected = bool(m) or bool(subject and _FORWARD_SUBJECT.match(subject))
    original = None
    if detected:
        tail = body[m.end() :] if m else body
        original = _forwarded_sender(tail[:5000])
    return {"detected": detected, "original_sender": original}


# ---------------------------------------------------------------------
# Links to file-sharing and form services. The domain is
# legitimate (Google, Microsoft, Dropbox), so the URL agent and threat
# intel rarely flag it, but the shared file or form is often the lure.
# Informational: surfaced to the user, not added to the score.
# ---------------------------------------------------------------------
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
            if host_re.search(host) and (path_re is None or re.match(path_re, parts.path or "/")):
                hits.append(u)
                if name not in services:
                    services.append(name)
                break
    return {"count": len(hits), "services": services, "urls": hits[:10]}


def client_links(extra: Any) -> list[str]:
    """Link targets sent by the client (client_context.link_urls).

    Untrusted input: only http(s) strings under 2048 characters are kept,
    at most MAX_LINK_URLS of them, duplicates dropped (order kept).
    """
    if not isinstance(extra, list):
        return []
    out: list[str] = []
    for u in extra:
        if len(out) >= MAX_LINK_URLS:
            break
        if not isinstance(u, str) or len(u) > 2048:
            continue
        u = u.strip()
        u = browser_url(u)
        if re.match(r"https?://", u) and u not in out:
            out.append(u)
    return out


class Ranked(list):
    """A list of links already in rank order (rank_links' output): a later
    rank_links keeps its order instead of ranking it again as one group,
    which would put its hidden links before its second visible ones."""


def rank_links(*groups: list[str], limit: int = MAX_EMAIL_URLS) -> Ranked:
    """The links of an email, at most `limit`, group by group in the order
    given (link targets before addresses written in the text): no link of
    a later group can push out one of an earlier group. Within a group,
    the first link of each host comes before any second one, so a pile of
    links to one site cannot push the others out either."""
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
