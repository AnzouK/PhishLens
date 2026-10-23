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


def html_to_text(html_src: str) -> str:
    """Visible text of an HTML email body, like the text Gmail shows.

    <style>, <script> and <head> contents are dropped: a plain tag strip
    kept the CSS ("25px", "roboto", "heading"...) and the text model read
    it as words. BeautifulSoup when installed (it is in requirements.txt),
    a linear find-based fallback otherwise.
    """
    html_src = html_src[:1_000_000]
    try:
        from bs4 import BeautifulSoup  # type: ignore

        soup = BeautifulSoup(html_src, "html.parser")
        for tag in soup(["style", "script", "head", "noscript", "title"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
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


# href="https://..." in an HTML part. Bounded class, no nested
# quantifiers: linear on any input.
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
        for m in _HREF_RE.finditer(html_src[:500_000]):
            if m.group(1) not in urls:
                urls.append(m.group(1))
            if len(urls) >= 200:
                break
    return urls


def parse_eml(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Return (body_text, urls_list, headers_dict)."""
    msg = message_from_bytes(raw_bytes, policy=policy.default)
    body = _body_text(msg, raw_bytes)
    return body.strip(), _link_targets(msg, body), header_dict(msg.items())


# Headers each relay adds on top of the message: the first (topmost) one
# is the receiving provider's. Lower ones come from earlier hops (an
# internal Microsoft 365 relay says "dkim=none") or from the sender, who
# can write anything there.
_TOPMOST_WINS = frozenset({"authentication-results", "arc-authentication-results"})


def header_dict(items) -> dict[str, str]:
    """Header name (lowercased) -> value. A repeated header keeps its last
    value, except the authentication results, which keep the topmost."""
    headers: dict[str, str] = {}
    for k, v in items:
        key = k.lower()
        if key in _TOPMOST_WINS and key in headers:
            continue
        headers[key] = str(v)
    return headers


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
