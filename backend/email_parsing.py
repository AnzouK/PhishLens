"""
Reading an email: the visible text, the links and the headers of a raw
.eml, plus the structural signals computed from them (forwarded emails,
links to file-sharing services).

Every parser here is linear on its input (no backtracking regex on
attacker-controlled text) and caps what it reads.
"""

from __future__ import annotations

import re
from email import message_from_bytes, policy
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlsplit

from settings import MAX_LINK_URLS

# http(s) URL written out in a text.
URL_IN_TEXT_RE = re.compile(r"https?://[^\s\"'<>)]+")


def urls_in_text(text: str) -> list[str]:
    return URL_IN_TEXT_RE.findall(text)


# Inline styles that hide an element from the reader: hidden text placed
# before the message filled the text model's window with words nobody
# sees. Such text is moved after the visible text rather than dropped: a
# <style> rule can show it again (on phones, say), and the reader may
# then see it.
_HIDING_STYLES = {
    "display": {"none"},
    "visibility": {"hidden", "collapse"},
    "mso-hide": {"all"},
}


def _number(value: str) -> float | None:
    num = value.strip().split(" ")[0].rstrip("%").rstrip("abcdefghijklmnopqrstuvwxyz")
    try:
        return float(num)
    except ValueError:
        return None


def is_hidden_style(style: str) -> bool:
    """True when an inline style hides its element: display:none,
    visibility:hidden, opacity near 0, a font smaller than 2 px, or no
    height or width with the overflow hidden."""
    decl: dict[str, str] = {}
    for item in (style or "")[:2000].lower().split(";"):
        key, sep, value = item.partition(":")
        if sep:
            decl[key.strip()] = value.replace("!important", "").strip()
    for key, hiding in _HIDING_STYLES.items():
        if decl.get(key) in hiding:
            return True
    opacity = _number(decl.get("opacity", "1"))
    if opacity is not None and opacity <= 0.05:
        return True
    size = decl.get("font-size", "")
    if (
        size
        and (n := _number(size)) is not None
        and (n == 0 or (n < 2 and size.endswith(("px", "pt"))))
    ):
        return True
    if decl.get("overflow") == "hidden":
        for key in ("max-height", "height", "max-width", "width"):
            n = _number(decl.get(key, "1"))
            if n is not None and n < 1:
                return True
    return False


def _hidden_tags(soup) -> list:
    """The outermost elements hidden by the hidden attribute or an inline
    style (the first 20,000 elements are examined)."""
    hidden, ids = [], set()
    for tag in soup.find_all(True, limit=20_000):
        hides = tag.has_attr("hidden") or is_hidden_style(tag.get("style", ""))
        if hides and not any(id(p) in ids for p in tag.parents):
            hidden.append(tag)
            ids.add(id(tag))
    return hidden


def visible_text_first(soup) -> str:
    """Text of a parsed HTML document: the visible text, then the text of
    hidden elements (see _HIDING_STYLES)."""
    hidden = [tag.extract() for tag in _hidden_tags(soup)]
    text = soup.get_text(separator=" ")
    tail = " ".join(tag.get_text(separator=" ") for tag in hidden)
    return f"{text}\n{tail}" if tail.strip() else text


def html_to_text(html_src: str) -> str:
    """Visible text of an HTML email body, like the text Gmail shows, with
    the text of hidden elements after it (visible_text_first).

    <style>, <script> and <head> contents are dropped: a plain tag strip
    kept the CSS ("25px", "roboto", "heading"...) and the text model read
    it as words. BeautifulSoup when installed (it is in requirements.txt),
    a linear find-based fallback otherwise.
    """
    html_src = without_inline_data(html_src)[:1_000_000]
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html_src, "html.parser")
        for tag in soup(["style", "script", "head", "noscript", "title"]):
            tag.decompose()
        text = visible_text_first(soup)
    except Exception:
        low = html_src.lower()
        out, i = [], 0
        while True:
            j = min(
                [k for k in (low.find("<style", i), low.find("<script", i)) if k >= 0], default=-1
            )
            if j < 0:
                out.append(html_src[i:])
                break
            out.append(html_src[i:j])
            end_tag = "</style>" if low.startswith("<style", j) else "</script>"
            k = low.find(end_tag, j)
            if k < 0:
                break
            i = k + len(end_tag)
        stripped, depth = [], 0
        for ch in "".join(out):
            if ch == "<":
                depth = 1
                stripped.append(" ")
            elif ch == ">" and depth:
                depth = 0
            elif not depth:
                stripped.append(ch)
        text = "".join(stripped)
        import html as _html

        text = _html.unescape(text)
    # Collapse whitespace line by line (no regex: linear on any input).
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


def html_links(html_src: str, limit: int = 200) -> list[str]:
    """http(s) targets of the links of an HTML document, as a browser reads
    them (entities decoded, spaces around "=" allowed, protocol-relative
    "//host" as https), visible links before hidden ones. A regex on
    'href="https://' missed 'href = "...' and '&#104;ttps://'."""
    html_src = without_inline_data(html_src)[:1_000_000]
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html_src, "html.parser")
    except Exception:
        return list(dict.fromkeys(m.group(1) for m in _HREF_RE.finditer(html_src)))[:limit]
    hidden = {id(t) for tag in _hidden_tags(soup) for t in (tag, *tag.find_all(True))}
    visible, later = [], []
    for tag in soup.find_all(["a", "area"], href=True, limit=20_000):
        url = _absolute_http(tag["href"])
        if url:
            (later if id(tag) in hidden else visible).append(url)
    return list(dict.fromkeys(visible + later))[:limit]


def _absolute_http(href: str) -> str:
    """An http(s) URL from an href, or "": control characters and spaces
    removed as browsers do, "//host/..." read as https."""
    href = "".join(c for c in str(href)[:2048] if c > " " and c != "\x7f")
    if href.startswith("//"):
        href = "https:" + href
    return href if href[:8].lower().startswith(("http://", "https://")) else ""


# href="https://..." in an HTML part. Bounded class, no nested
# quantifiers: linear on any input.
# Source code shown as text: when a mail page cannot render an email
# (Gmail gives up on very large HTML), its visible text is the HTML
# itself, inline images included. The text model reads that as phishing.
# Base64 characters and line breaks only: with any whitespace, the words
# after "data:text/plain;base64," were taken for inline data too.
_DATA_URI_RE = re.compile(r"data:[\w/+.-]{1,100};base64,[A-Za-z0-9+/=\r\n]{1,8000000}")
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{200,}")
# A tag, or one cut off at the end of a truncated page text.
_TAG_RE = re.compile(r"</?[a-zA-Z][a-zA-Z0-9]{0,20}(?:\s[^<>]{0,2000})?(?:/?>|\Z)")


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
    text = _TAG_RE.sub(" ", text)
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def looks_like_source(text: str) -> bool:
    """True when most of a page text is markup or inline data rather
    than words."""
    if not text:
        return False
    return len(strip_markup_noise(text)) < 0.5 * len(text.strip())


_HREF_RE = re.compile(r"""href=["'](https?://[^"'\s<>]{1,2048})""", re.IGNORECASE)


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
    """URLs written in the text, then the real targets of the HTML part's
    links (an HTML email shows "Click here", the address is in the href)."""
    urls = urls_in_text(body)
    for part in msg.walk() if msg.is_multipart() else [msg]:
        if part.get_content_type() != "text/html":
            continue
        try:
            html_src = part.get_content()
        except Exception:
            continue
        for url in html_links(html_src):
            if url not in urls:
                urls.append(url)
            if len(urls) >= 200:
                break
    return urls


def parse_eml(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Return (body_text, urls_list, headers_dict).

    A message the standard parser rejects (a malformed header, a broken
    MIME structure) is read leniently instead of refused: a crafted
    email must not escape the scan by failing to parse."""
    try:
        msg = message_from_bytes(raw_bytes, policy=policy.default)
        body = _body_text(msg, raw_bytes)
        return body.strip(), _link_targets(msg, body), header_dict(msg.items())
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
        urls = urls_in_text(body)
        for url in html_links(texts["text/html"]):
            if url not in urls and len(urls) < 200:
                urls.append(url)
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
# Same name as auth_headers.DUPLICATE_FROM (not imported: no cycle).
DUPLICATE_FROM = "x-phishlens-duplicate-from"


def header_dict(items) -> dict[str, str]:
    """Header name (lowercased) -> value. A repeated header keeps its last
    value, except the ones in _TOPMOST_WINS, which keep the first. A
    repeated From: is recorded under DUPLICATE_FROM."""
    headers: dict[str, str] = {}
    for k, v in items:
        key = k.lower()
        if key == DUPLICATE_FROM:
            continue
        if key in _TOPMOST_WINS and key in headers:
            if key == "from":
                headers[DUPLICATE_FROM] = "1"
            continue
        headers[key] = _decoded_header(str(v))
    return headers


def _decoded_header(value: str) -> str:
    """Encoded words ("=?utf-8?b?UGF5UGFs?=") decoded, as a mail program
    shows them. The standard parser already does it; the lenient one
    does not, and the name checks must read the same text either way."""
    if "=?" not in value:
        return value
    try:
        from email.header import decode_header, make_header

        return str(make_header(decode_header(value[:4000])))
    except Exception:
        return value


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
            parts = urlsplit(u)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        for host_re, path_re, name in _SHARE_SERVICES:
            if host_re.search(host) and (path_re is None or re.match(path_re, parts.path or "/")):
                hits.append(u)
                if name not in services:
                    services.append(name)
                break
    return {"count": len(hits), "services": services, "urls": hits[:10]}


def merge_link_urls(urls: list[str], extra: Any) -> list[str]:
    """Add client-supplied link targets to the URLs found in the text.

    Untrusted input: only http(s) strings under 2048 characters are kept,
    at most MAX_LINK_URLS of them, and duplicates are dropped (order kept).
    """
    out = list(dict.fromkeys(urls))
    if not isinstance(extra, list):
        return out
    seen = set(out)
    for u in extra:
        if len(out) >= MAX_LINK_URLS:
            break
        if not isinstance(u, str) or len(u) > 2048:
            continue
        u = u.strip()
        if not re.match(r"https?://", u, re.I) or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out
