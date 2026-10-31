"""
PhishLens: email attachment analysis.
=====================================================================
Extract text and URLs from email attachments and reuse the existing
text / URL / reputation pipeline on the extracted content.

Supported: PDF (with OCR for scanned pages and QR decoding),
HTML, SVG, web archives (.mht), plain text, images (OCR + QR), Word / Excel / PowerPoint in both
modern and legacy formats (text, links and macro-style flags; see
office_analysis.py). OCR and QR live in ocr.py. Also ZIP archives
(listed, risky entries flagged, supported files inside analysed one level
deep), RAR / 7z (the same way, when rarfile / py7zr are installed),
calendar invites (.ics), encrypted PDFs, and executable / script /
shortcut / disk-image files (flagged by type). See archive_analysis.py.

The dispatcher (analyse_attachment) returns a JSON-serialisable dict
whose shape mirrors /analyse as closely as possible so the extension
and landing widgets can share their rendering code.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import io
import logging
import re
import zipfile
from collections.abc import Callable
from email import message_from_bytes
from email import policy as email_policy
from typing import Any
from urllib.parse import unquote, urljoin

from bs4 import BeautifulSoup

import archive_analysis as archives
import ocr
import office_analysis as office
from email_parsing import _decoded_header, absolute_http, rank_links, urls_in_text
from hidden_content import generated_text, hidden_tags, shown_link, shown_maps, visible_text_first
from unicode_text import without_invisible

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

# ---------------------------------------------------------------------
# Limits: enforced BEFORE decoding to protect the process.
# ---------------------------------------------------------------------
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024  # 10 MB hard cap
MAX_EXTRACTED_TEXT = 20_000  # chars fed to the text agent
MAX_EXTRACTED_URLS = 200  # URLs sent to reputation cascade
PDF_PAGE_LIMIT = 50  # abort text extraction past this
# A PDF with fewer extracted characters than this per page (on average)
# is treated as scanned / image-only and sent to OCR.
SCANNED_CHARS_PER_PAGE = 50

# ---------------------------------------------------------------------
# Optional deps: graceful fallback (endpoint still responds, but
# returns a clear error) if the module isn't in the runtime image.
# ---------------------------------------------------------------------
try:
    import pdfplumber  # type: ignore

    _PDFPLUMBER_OK = True
except Exception as _e:
    _PDFPLUMBER_OK = False
    logger.warning(f"pdfplumber not available ({_e}); PDF attachments will be rejected.")


# ---------------------------------------------------------------------
# MIME sniffing: trust the extension of the filename first, fall back
# to content sniffing. Client sends its own mime_type as a hint but we
# don't trust it blindly.
# ---------------------------------------------------------------------
_MIME_BY_EXT = {
    ".pdf": "application/pdf",
    ".html": "text/html",
    ".htm": "text/html",
    ".xhtml": "application/xhtml+xml",
    ".shtml": "text/html",
    # A picture to the eye, a page to the browser: scripts, links and
    # forms (foreignObject) run when it is opened.
    ".svg": "image/svg+xml",
    ".svgz": "image/svg+xml",
    # Web archives and saved emails: MIME messages whose HTML parts open
    # as pages (in a browser, Word or a mail program).
    ".mht": "multipart/related",
    ".mhtml": "multipart/related",
    ".eml": "message/rfc822",
    ".txt": "text/plain",
    # Archives and calendar invites
    ".zip": "application/zip",
    ".rar": "application/vnd.rar",
    ".7z": "application/x-7z-compressed",
    ".ics": "text/calendar",
    # Office, modern (zip + xml)
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.ms-word.document.macroenabled.12",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.ms-excel.sheet.macroenabled.12",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".pptm": "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    ".dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ".dotm": "application/vnd.ms-word.template.macroenabled.12",
    ".xltx": "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    ".xltm": "application/vnd.ms-excel.template.macroenabled.12",
    ".xlsb": "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    ".potx": "application/vnd.openxmlformats-officedocument.presentationml.template",
    ".potm": "application/vnd.ms-powerpoint.template.macroenabled.12",
    ".ppsx": "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    ".ppsm": "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    # Office, legacy (OLE2)
    ".doc": "application/msword",
    ".xls": "application/vnd.ms-excel",
    ".ppt": "application/vnd.ms-powerpoint",
    # Images
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
}

IMAGE_MIMES = {m for m in _MIME_BY_EXT.values() if m.startswith("image/")} - {"image/svg+xml"}
MIME_PAGE_TYPES = {"multipart/related", "message/rfc822"}
# Read as pages: HTML, and SVG (a page with a picture's name).
PAGE_MIMES = {"text/html", "application/xhtml+xml", "image/svg+xml"}


def _magic_type(head: bytes) -> str | None:
    """The type a file's first bytes prove, whatever its name says."""
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head[:2] == b"PK":
        # ZIP-based: Office documents are resolved by the dispatcher,
        # which opens the archive to see what is inside.
        return "application/zip"
    if head.startswith(office.OLE2_MAGIC):
        return "application/x-ole-storage"
    if head.startswith(b"\x89PNG"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    return None


_HTML_MARKS = (b"<!doctype html", b"<html", b"<head", b"<form", b"<body", b"<script")


def sniff_type(filename: str, content_head: bytes, client_hint: str | None) -> str:
    """
    Return a canonical MIME type: the file's signature first (a PDF or an
    HTML login page renamed "invoice.txt" is still read as what it is),
    then the extension, then the client's hint.
    """
    ext = "." + archives._ext(filename) if archives._ext(filename) else ""
    magic = _magic_type(content_head[:16])
    by_ext = _MIME_BY_EXT.get(ext)
    office_container = ("application/zip", "application/x-ole-storage")
    if magic in office_container and by_ext in (office.OOXML_MIMES | office.LEGACY_MIMES):
        return by_ext  # an Office file is a ZIP or OLE2 container; its name says which
    if magic:
        return magic
    text_like = by_ext is None or by_ext.startswith("text/")
    if text_like and any(m in content_head[:1024].lower() for m in _HTML_MARKS):
        return "text/html"
    if (text_like or by_ext == "image/svg+xml") and b"<svg" in content_head[:1024].lower():
        return "image/svg+xml"
    if by_ext:
        return by_ext
    head = content_head[:16]
    if head.lstrip().lower().startswith(b"<!--"):
        return "text/html"
    if head.startswith(b"BM"):
        return "image/bmp"

    # Fall back to whatever the client claimed, sanitized.
    if client_hint and "/" in client_hint:
        return client_hint.lower().split(";", 1)[0].strip()
    return "application/octet-stream"


# ---------------------------------------------------------------------
# URL extraction: same regex the /analyse endpoint uses, plus we also
# pick up bare-domain "click here" style links (missing scheme).
# ---------------------------------------------------------------------
_URL_DEDUP_N = MAX_EXTRACTED_URLS


def extract_urls(text: str) -> list[str]:
    """The addresses written in an attachment's text, read like those of
    an email (email_parsing.urls_in_text: any case, "www.", as a browser
    reads them)."""
    seen, out = set(), []
    for u in urls_in_text(text[:2_000_000] if text else ""):
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if len(out) >= _URL_DEDUP_N:
            break
    return out


# =====================================================================
# PDF analysis
# =====================================================================
# Suspicious PDF markers: presence of any of these is worth surfacing
# to the user, they're the classic phishing / malware droppers.
_PDF_SUSPICIOUS_MARKERS = {
    b"/JavaScript": "contains_javascript",
    b"/JS": "contains_javascript",
    b"/AcroForm": "contains_form",
    b"/OpenAction": "auto_execute_on_open",
    b"/Launch": "launch_external_action",
    b"/EmbeddedFile": "embeds_another_file",
    b"/GoToR": "remote_link_action",
    b"/RichMedia": "flash_or_richmedia",
    b"/URI": "contains_link_annotation",
    b"/SubmitForm": "submits_form_to_url",
}


def _pdf_scan_markers(raw: bytes) -> list[str]:
    """
    Cheap pattern scan on the raw PDF bytes. Doesn't attempt to parse
    object streams; it just looks for the well-known feature tags.
    Zero cost, high signal for phishing PDFs.
    """
    flags = []
    for needle, label in _PDF_SUSPICIOUS_MARKERS.items():
        if needle in raw and label not in flags:
            flags.append(label)
    return flags


def _pdf_text_layer(raw: bytes) -> tuple[list[str], int, int]:
    """Text of the first pages: (chunks, pages read, page count)."""
    text_chunks: list[str] = []
    pages_read = 0
    with pdfplumber.open(io.BytesIO(raw)) as pdf:
        page_count = len(pdf.pages)
        for i, page in enumerate(pdf.pages):
            if i >= PDF_PAGE_LIMIT:
                break
            try:
                t = page.extract_text() or ""
                if t:
                    text_chunks.append(t)
                pages_read = i + 1
                if sum(len(c) for c in text_chunks) >= MAX_EXTRACTED_TEXT:
                    break
            except Exception:
                continue
    return text_chunks, pages_read, page_count


def _add_new(urls: list[str], more: list[str]) -> None:
    for u in more:
        if u not in urls:
            urls.append(u)


def _add_uri_annotations(raw: bytes, urls: list[str]) -> None:
    """Link annotations the text layer misses (a clickable button with no
    visible URL): grabs (/URI (https://...)).

    The inner class is length-capped (2048 bytes) to close a
    polynomial-ReDoS surface that CodeQL flagged: a crafted PDF with a
    very long /URI( body and no closing paren could push the regex engine
    into O(n^2) territory. 2 KB is more than any legit annotation holds.
    """
    for m in re.finditer(rb"/URI\s*\(([^)]{1,2048})\)", raw):
        try:
            u = absolute_http(m.group(1).decode("latin-1", errors="ignore").strip())
            if u and u not in urls:
                urls.append(u)
                if len(urls) >= MAX_EXTRACTED_URLS:
                    break
        except Exception:
            continue


def analyse_pdf(raw: bytes, filename: str) -> dict[str, Any]:
    """
    Extract text + URLs from a PDF, plus a list of qualitative feature
    flags. Returns a dict ready for the shared UI.
    """
    if not _PDFPLUMBER_OK:
        raise RuntimeError("PDF support is not available (pdfplumber missing).")

    markers = _pdf_scan_markers(raw)

    try:
        text_chunks, pages_read, page_count = _pdf_text_layer(raw)
    except Exception as e:
        if b"/Encrypt" in raw:
            # Password-protected PDF: nothing to read, which is the point
            # when the password travels in the email body.
            return {
                "kind": "pdf",
                "filename": filename,
                "size_bytes": len(raw),
                "page_count": 0,
                "pages_read": 0,
                "extracted_text": "",
                "extracted_text_chars": 0,
                "extracted_urls": [],
                "notable_features": markers + ["encrypted_document"],
            }
        raise RuntimeError(f"PDF parse failed: {e}") from e

    # Invisible characters out before the cut: 20,000 zero-width spaces
    # on the first page once left nothing else to read.
    text = without_invisible("\n".join(text_chunks))[:MAX_EXTRACTED_TEXT]

    # URLs: extracted text can miss link annotations (clickable button
    # with no visible URL text). We also parse /URI markers directly.
    urls = extract_urls(text)
    if len(urls) < MAX_EXTRACTED_URLS:
        _add_uri_annotations(raw, urls)

    # Scanned / image-only PDFs and QR codes. The first pages are
    # rendered once; QR decoding always runs on them, OCR only when the
    # PDF has (almost) no text layer.
    caps = ocr.capabilities()
    scanned = pages_read > 0 and len(text.strip()) < SCANNED_CHARS_PER_PAGE * pages_read
    ocr_used = False
    qr_found: list[str] = []
    if caps["pdf_render"] and (caps["qr"] or (scanned and caps["ocr"])):
        pages = ocr.render_pdf_pages(raw)
        scan = ocr.scan_images(pages, do_ocr=scanned and caps["ocr"])
        if scan["text"]:
            text = (text + "\n" + without_invisible(scan["text"])).strip()[:MAX_EXTRACTED_TEXT]
            ocr_used = True
        qr_found = scan["qr_urls"]
        _add_new(urls, extract_urls(scan["text"]) if scan["text"] else [])
        _add_new(urls, qr_found)
    if scanned:
        markers.append("image_only_pdf")
    if qr_found:
        markers.append("contains_qr_code")
    if ocr_used:
        markers.append("text_from_ocr")

    return {
        "kind": "pdf",
        "filename": filename,
        "size_bytes": len(raw),
        "page_count": page_count,
        "pages_read": pages_read,
        "extracted_text": text,
        "extracted_text_chars": len(text),
        "extracted_urls": urls[:MAX_EXTRACTED_URLS],
        "notable_features": markers,
        "qr_urls": qr_found,
        "ocr_used": ocr_used,
        "capabilities": caps,
    }


# =====================================================================
# Image analysis: OCR + QR
# =====================================================================
def analyse_image(raw: bytes, filename: str) -> dict[str, Any]:
    img = ocr.load_image(raw)
    caps = ocr.capabilities()
    scan = ocr.scan_images([img], do_ocr=caps["ocr"])
    text = without_invisible(scan["text"])[:MAX_EXTRACTED_TEXT]
    urls = extract_urls(text)
    for u in scan["qr_urls"]:
        if u not in urls:
            urls.append(u)
    flags = []
    if scan["qr_urls"]:
        flags.append("contains_qr_code")
    if text:
        flags.append("text_from_ocr")
    return {
        "kind": "image",
        "filename": filename,
        "size_bytes": len(raw),
        "width": img.size[0],
        "height": img.size[1],
        "extracted_text": text,
        "extracted_text_chars": len(text),
        "extracted_urls": urls[:MAX_EXTRACTED_URLS],
        "notable_features": flags,
        "qr_urls": scan["qr_urls"],
        "ocr_used": bool(text),
        "capabilities": caps,
    }


# =====================================================================
# HTML analysis
# =====================================================================
_PAGE_DATA_TYPES = ("data:text/html", "data:application/xhtml+xml", "data:image/svg+xml")


def _data_html(value: str) -> str | None:
    """The page in a "data:text/html[;charset=...][;base64],..." (or
    application/xhtml+xml) address, or None. Only a base64 payload loses
    its spaces: in a plain one they separate the tag from its attributes."""
    head, sep, payload = str(value).strip().partition(",")
    # Browsers drop tabs and line breaks anywhere in an address.
    params = ["".join(p.split()) for p in head.lower().split(";")]
    if not sep or params[0] not in _PAGE_DATA_TYPES:
        return None
    try:
        if "base64" in params[1:]:
            # Percent-decoded first, as browsers do ("%2B" is "+").
            raw = "".join(unquote(payload[:700_000]).split())
            return base64.b64decode(raw + "===")[:500_000].decode("utf-8", "replace")
        return unquote(payload[:500_000])
    except (ValueError, binascii.Error):
        return None


def _refresh_target(meta) -> str:
    """The address of a <meta http-equiv="refresh">: what follows the
    delay and ";" or ",", with or without "url=" ("0; url=https://x",
    "0; https://x", "0,URL = 'https://x'")."""
    content = str(meta.get("content") or "").strip()
    cut = min((i for i in (content.find(";"), content.find(",")) if i >= 0), default=-1)
    if cut < 0:
        return ""
    target = content[cut + 1 :].strip()
    if target[:3].lower() == "url":
        rest = target[3:].lstrip()
        if rest.startswith("="):
            target = rest[1:]
    return target.strip(" '\"")


# Where a page can carry another page: an attribute holding its HTML
# (srcdoc) or a data:text/html address.
_EMBEDDED_PAGES = (
    ("iframe", "srcdoc"),
    ("iframe", "src"),
    ("frame", "src"),
    ("object", "data"),
    ("embed", "src"),
)


def _inline_embedded(soup, depth: int = 3) -> None:
    """Pages an HTML attachment carries inside itself, parsed into it so
    their forms, scripts and links are read like the rest: an <iframe
    srcdoc="...">, a frame, object or embed whose address is
    data:text/html, and a meta refresh to one (three levels, 500 KB each)."""
    for _ in range(depth):
        found = False
        for name, attr in _EMBEDDED_PAGES:
            for tag in soup.find_all(name, attrs={attr: True}, limit=100):
                html = str(tag[attr]) if attr == "srcdoc" else _data_html(tag[attr])
                if html is None:
                    continue
                del tag[attr]
                tag.append(BeautifulSoup(html[:500_000], "html.parser"))
                found = True
        for meta in soup.find_all(
            "meta", attrs={"http-equiv": re.compile(r"^\s*refresh\s*$", re.I)}
        ):
            html = _data_html(_refresh_target(meta))
            if html is not None:
                meta["content"] = "0"
                meta.insert_after(BeautifulSoup(html[:500_000], "html.parser"))
                found = True
        if not found:
            return


def _script_url(value: str) -> bool:
    """javascript: or vbscript:, as browsers read an address (controls
    and spaces dropped, any case)."""
    v = "".join(c for c in str(value)[:200] if c > " ").lower()
    return v.startswith(("javascript:", "vbscript:"))


def _page_urls(soup, location: str = "") -> Callable[[str], str]:
    """How the page's addresses are read: absolute ones as browsers read
    them, relative ones against the page's <base href> (a form posting to
    "login.php" under <base href="https://evil.tk/"> goes to evil.tk), or
    against the address a web archive says the page came from
    (Content-Location). Without either, a relative address in a saved page
    points to a local file, not a site."""
    tag = soup.find("base", href=True)
    base = (absolute_http(tag["href"]) if tag else "") or absolute_http(location)

    def url(value: str) -> str:
        found = absolute_http(value)
        if found or not base or not str(value).strip():
            return found
        try:
            return absolute_http(urljoin(base, str(value).strip()))
        except ValueError:
            return ""

    return url


# HTML smuggling: a file built from data in the page and handed to the
# browser to save or open.
_SMUGGLING_RE = re.compile(
    r"msSaveOrOpenBlob|msSaveBlob|createObjectURL\s*\(|\.download\s*=|new\s+File\s*\(",
    re.IGNORECASE,
)
_JS_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})")
_NUMBER = r"(?:0[xX][0-9a-fA-F]{1,6}|0[oO][0-7]{1,8}|\d{1,7})"
_CHAR_CODES_RE = re.compile(rf"fromCharCode\s*\(\s*((?:{_NUMBER}\s*,\s*){{3,4000}}{_NUMBER})\s*\)")
# Two string literals joined with "+": "https://ev" + "il.tk".
_JOINED_RE = re.compile(r"""(["'`])\s*\+\s*(["'`])""")
_LITERAL_RE = re.compile(r"""["'`]([^"'`\n]{10,2048})["'`]""")
_BASE64_LITERAL_RE = re.compile(r"[\"'`]([A-Za-z0-9+/]{16,20000}={0,2})[\"'`]")


def _script_readings(code: str) -> list[str]:
    """A script as its addresses are written in it: escapes decoded
    ("\\x68\\x74\\x74\\x70s://"), character codes turned into text
    (String.fromCharCode(104, 116, ...)), percent-encoding undone
    (unescape("%68...")) and base64 literals decoded (atob("aHR0cHM6...")),
    each added after the code itself (string literals joined)."""
    out: list[str] = []

    def char(m: re.Match) -> str:
        try:
            return chr(int(m.group(1) or m.group(2) or m.group(3), 16))
        except (ValueError, OverflowError):
            return ""

    # Literals joined first ('"https://ev" + "il.tk"', also across
    # quote kinds), escapes decoded, then every other reading on that.
    code = _JOINED_RE.sub("", code)
    code = _JS_ESCAPE_RE.sub(char, code)
    out.append(code)
    for m in _CHAR_CODES_RE.finditer(code):
        codes = [int(n, 0) for n in re.findall(r"0[xXoO][0-9a-fA-F]+|\d+", m.group(1))]
        out.append("".join(chr(n) for n in codes if n < 0x110000))
    if "%" in code:
        out.append(unquote(code))
    # A string written backwards ("kt.live//:sptth".split("").reverse()).
    out += [lit[::-1] for lit in _LITERAL_RE.findall(code) if "//:" in lit]
    for m in _BASE64_LITERAL_RE.finditer(code):
        try:
            decoded = base64.b64decode(m.group(1) + "==", validate=False)[:20_000]
        except (ValueError, binascii.Error):
            continue
        out.append(decoded.decode("utf-8", "ignore"))
    return out


def _script_strings(code: str) -> str:
    return "\n".join(_script_readings(code))[:1_000_000]


# Markup a script writes into the page (document.write, innerHTML) once
# decoded: what is between its first tag and its last ">".
_WRITTEN_TAG_RE = re.compile(
    r"<(?:form|input|iframe|frame|meta|a|svg|button|img|object|embed)\b", re.I
)


def _js_strings(code: str) -> list[str]:
    """The string literals of a script ("...", '...', `...`, escapes
    allowed): where a page a script writes is, never the code around it
    ("if (x > 0)" is not markup). One pass, linear on any input; an
    unclosed literal ends at its line."""
    out: list[str] = []
    i, n = 0, len(code)
    while i < n:
        quote = code[i]
        if quote not in "\"'`":
            i += 1
            continue
        j = i + 1
        while j < n and code[j] != quote and (code[j] != "\n" or quote == "`"):
            j += 2 if code[j] == "\\" else 1
        if j < n and code[j] == quote:
            # Simple escapes as the script reads them (\" is ").
            out.append(re.sub(r"\\(.)", r"\1", code[i + 1 : j]))
        i = j + 1
    return out


def _inline_scripted(soup) -> None:
    """Pages a script writes, parsed into the page next to the script, so
    that their forms and password fields are read like the page's own:
    markup found in the script's string literals (joined, escapes decoded)
    and in what it decodes (atob, unescape, char codes), every one of
    them, 500 KB at most."""
    budget = 500_000
    for script in soup.find_all("script", limit=1000):
        readings = _script_readings(script.get_text()[:200_000])
        literals = _js_strings(readings[0]) if readings else []
        for piece in literals + readings[1:]:
            m = _WRITTEN_TAG_RE.search(piece)
            if not m or budget <= 0:
                continue
            start = piece.rfind("<", 0, m.start() + 1)
            end = piece.rfind(">")
            if end <= start:
                continue
            markup = piece[start : end + 1][:budget]
            budget -= len(markup)
            script.insert_after(BeautifulSoup(markup, "html.parser"))


def _page_flags(soup, has_script: bool, smuggles: bool) -> list[str]:
    flags = []
    if soup.find("form"):
        flags.append("contains_form")
    # Attribute values keep their case in the parser, browsers ignore it:
    # type="PASSWORD" is a password field.
    if soup.find("input", attrs={"type": re.compile(r"^\s*password\s*$", re.I)}):
        flags.append("contains_password_field")
    if has_script:
        flags.append("contains_javascript")
    if soup.find("iframe"):
        flags.append("contains_iframe")
    if soup.find("meta", attrs={"http-equiv": re.compile(r"^\s*refresh\s*$", re.I)}):
        flags.append("meta_refresh_redirect")
    if smuggles:
        # HTML smuggling: the page builds a file in the browser and saves
        # it, so no scanner ever sees the file itself.
        flags.append("embeds_another_file")
    return flags


def analyse_html(raw: bytes, filename: str, location: str = "") -> dict[str, Any]:
    """
    Extract visible text + href / action URLs from an HTML attachment.
    HTML phishing attachments typically render a login form styled as
    a well-known brand, with a <form action="attacker.tld">. We grab
    all such URLs regardless of visible text.
    """
    try:
        soup = BeautifulSoup(raw, "html.parser")
        # Script-written pages first: one can hold an <iframe srcdoc>.
        _inline_scripted(soup)
        _inline_embedded(soup)
    except Exception as e:
        raise RuntimeError(f"HTML parse failed: {e}") from e

    # URLs from the DOM even when they're not in the visible text, most
    # telling first: where the page sends its reader (form targets,
    # frames, a meta refresh, addresses written in a script such as
    # 'window.location = "https://..."'), then visible links, hidden
    # links, and images and style sheets last. Two hundred hidden images
    # once pushed the form's target past the limit.
    hidden_parts = hidden_tags(soup)  # before the <style> sheets go
    hidden = {id(tag) for tag in hidden_parts}
    maps = shown_maps(soup, hidden)
    url = _page_urls(soup, location)
    sends, visible, unseen, assets = [], [], [], []
    for tag in soup.find_all(["form", "iframe", "frame", "object", "embed"], limit=20_000):
        sends.append(url(tag.get("action") or tag.get("src") or tag.get("data") or ""))
    # A submit button can send the form elsewhere (formaction).
    for tag in soup.find_all(["button", "input"], formaction=True, limit=20_000):
        sends.append(url(tag["formaction"]))
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile(r"^\s*refresh\s*$", re.I)}):
        sends.append(url(_refresh_target(meta)))
    smuggles = False
    for script in soup.find_all("script", limit=1000):
        code = script.get_text()[:200_000]
        sends += urls_in_text(_script_strings(code))
        smuggles = smuggles or bool(_SMUGGLING_RE.search(code))
    for tag in soup.find_all(["a", "area"], limit=20_000):
        # SVG links use xlink:href.
        href = tag.get("href") or tag.get("xlink:href")
        if href:
            (visible if shown_link(tag, hidden, maps) else unseen).append(url(href))
    for tag in soup.find_all(["img", "link", "script"], limit=20_000):
        assets.append(url(tag.get("src") or tag.get("href") or ""))
    urls = rank_links(
        *([u for u in group if u] for group in (sends, visible, unseen, assets)),
        limit=MAX_EXTRACTED_URLS,
    )

    # Read before the scripts are removed: a script element, an event
    # handler attribute (onclick, onerror, onfocus...) or a script address
    # in any attribute (href, src, data, xlink:href, formaction...), as
    # browsers read it: controls and spaces dropped, any case.
    has_script = bool(soup.find("script")) or any(
        name.lower().startswith("on") or _script_url(value)
        for tag in soup.find_all(True, limit=20_000)
        for name, value in tag.attrs.items()
    )

    # Strip noisy tags before extracting the text; words the style sheets
    # write are kept, hidden text goes last.
    generated = generated_text(soup, hidden_parts)
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(without_invisible(visible_text_first(soup, hidden_parts, generated)).split())[
        :MAX_EXTRACTED_TEXT
    ]

    flags = _page_flags(soup, has_script, smuggles)

    return {
        "kind": "html",
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": text,
        "extracted_text_chars": len(text),
        "extracted_urls": urls,
        "notable_features": flags,
    }


_MAX_MIME_PAGES = 3
_MIME_PAGE_PARTS = ("text/html", "application/xhtml+xml", "image/svg+xml")


def analyse_mime_pages(raw: bytes, filename: str) -> dict[str, Any]:
    """A web archive (.mht) or a saved email (.eml) inside an archive: its
    HTML parts read as pages (forms, scripts, links), its plain text as
    text. Files attached to it are named, not opened."""
    msg = message_from_bytes(raw, policy=email_policy.compat32)
    pages: list[dict[str, Any]] = []
    plain: list[str] = []
    attached = False
    names: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        kind = part.get_content_type()
        # The name as a mail program shows it (encoded words decoded).
        fname = _decoded_header(str(part.get_filename() or ""))
        if fname:
            names.append(fname)
        data = part.get_payload(decode=True)
        if not isinstance(data, bytes):
            continue
        if fname and kind not in _MIME_PAGE_PARTS and kind != "text/plain":
            # A page's own pictures, styles and fonts are part of it; any
            # other file attached is not opened.
            if not kind.startswith(("image/", "font/")) and kind != "text/css":
                attached = True
        elif kind in _MIME_PAGE_PARTS and len(pages) < _MAX_MIME_PAGES:
            location = str(part.get("Content-Location") or "")
            pages.append(analyse_html(data[:MAX_ATTACHMENT_BYTES], filename, location))
        elif kind == "text/plain" and not plain:
            plain.append(data.decode(part.get_content_charset() or "utf-8", "replace"))
    out: dict[str, Any] = {
        "kind": "html",
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": "",
        "extracted_text_chars": 0,
        "extracted_urls": [],
        # Attached files are named: a program or a fake extension shows.
        "notable_features": archives.classify_names(names)
        + (["inner_files_not_extracted"] if attached else []),
    }
    for page in pages:
        out = _merge(out, page)
    if not pages and plain:
        text = without_invisible(plain[0])[:MAX_EXTRACTED_TEXT]
        out = _merge(out, {"extracted_text": text, "extracted_urls": extract_urls(text)})
    out["kind"] = "html"
    return out


# =====================================================================
# Dispatcher: the public entry point.
# =====================================================================
def analyse_attachment(
    content_b64: str, filename: str = "", mime_type: str | None = None
) -> dict[str, Any]:
    """
    Decode the base64 payload, dispatch by MIME, return a
    JSON-serialisable dict.

    Does NOT call the model agents itself: that's the /analyse_attachment
    endpoint's job (it wires the extracted text + URLs into text_agent /
    url_agent / reputation cascade the same way /analyse does for emails).

    Raises ValueError on unsupported types or oversized inputs.
    """
    if not content_b64:
        raise ValueError("Empty attachment.")

    try:
        raw = base64.b64decode(content_b64, validate=False)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}") from e

    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise ValueError(f"Attachment exceeds {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB limit.")
    if not raw:
        raise ValueError("Attachment is empty after decode.")

    return dispatch_raw(raw, filename or "", mime_type)


def _dangerous_type(raw: bytes, filename: str) -> dict[str, Any] | None:
    """Executables, scripts, shortcuts and disk images are flagged by
    type alone: there is nothing to read, and opening them is the attack."""
    name_flags = archives.classify_names([filename])
    ext = archives._ext(filename)
    if ext in archives.DISK_IMAGE_EXTS:
        flags = ["disk_image_attachment"]
    elif set(name_flags) & archives.DROPPER_FLAGS:
        flags = ["dangerous_file_type"]
        if "double_extension" in name_flags:
            flags.append("double_extension")
    else:
        return None
    return {
        "kind": "executable" if flags[0] == "dangerous_file_type" else "disk_image",
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": "",
        "extracted_text_chars": 0,
        "extracted_urls": [],
        "notable_features": flags,
    }


def _zip_names(raw: bytes) -> list[str] | None:
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            return [
                i.filename
                for i in zf.infolist()[: office.MAX_ZIP_ENTRIES]
                if not archives.is_dir(i.filename)
            ]
    except (zipfile.BadZipFile, ValueError):
        return None


# The pictures of an Office document are checked for QR codes, and read
# (OCR) when its text is shorter than this: a page that is one
# screenshot, or a few words around a QR code.
_FEW_WORDS = 25
_MAX_PICTURES = 3


def _merge(doc: dict[str, Any], other: dict[str, Any]) -> dict[str, Any]:
    """The Office reading of a package with what its other members say:
    flags, links and text added, the members listed like an archive's."""
    out = dict(doc)
    out["notable_features"] = list(
        dict.fromkeys([*doc.get("notable_features", []), *other.get("notable_features", [])])
    )
    out["extracted_urls"] = list(
        dict.fromkeys([*doc.get("extracted_urls", []), *other.get("extracted_urls", [])])
    )[:MAX_EXTRACTED_URLS]
    # Each reading keeps room in the cut: a long document cannot push the
    # login page next to it out of what is scored.
    extra = (other.get("extracted_text") or "")[: MAX_EXTRACTED_TEXT // 2]
    own = (doc.get("extracted_text") or "")[: MAX_EXTRACTED_TEXT - len(extra) - 1]
    out["extracted_text"] = "\n".join(t for t in (own, extra) if t)
    out["extracted_text_chars"] = len(out["extracted_text"])
    for key in ("inner_files", "entries", "_all_entries", "entry_count", "qr_urls", "ocr_used"):
        if other.get(key):
            out[key] = other[key]
    return out


def _pictures_of(raw: bytes, names: list[str], read_text: bool) -> dict[str, Any]:
    """QR codes of the largest pictures of a package, and their text (OCR)
    when `read_text`."""
    images = []
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        infos = [zf.getinfo(n) for n in office.media_parts(names)]
        infos = [i for i in infos if 0 < i.file_size <= archives.MAX_INNER_BYTES]
        infos.sort(key=lambda i: -i.file_size)
        for info in infos[:_MAX_PICTURES]:
            if info.file_size / max(info.compress_size, 1) > archives.MAX_RATIO:
                continue
            try:
                with zf.open(info) as fh:
                    images.append(ocr.load_image(fh.read(archives.MAX_INNER_BYTES)))
            except Exception:
                continue
    if not images:
        return {}
    caps = ocr.capabilities()
    scan = ocr.scan_images(images, do_ocr=read_text and caps["ocr"])
    text = without_invisible(scan["text"])[:MAX_EXTRACTED_TEXT]
    flags = (["contains_qr_code"] if scan["qr_urls"] else []) + (["text_from_ocr"] if text else [])
    return {
        "extracted_text": text,
        "extracted_urls": [*extract_urls(text), *scan["qr_urls"]],
        "notable_features": flags,
        "qr_urls": scan["qr_urls"],
        "ocr_used": bool(text),
    }


def _read_zip(raw: bytes, filename: str, depth: int) -> dict[str, Any]:
    """Any ZIP, whatever its name or announced type, read by what it holds.

    An Office package (content types and the main part of its kind) is
    always read as a document: its macros, fields and relationships are
    what Office acts on, whatever else the ZIP holds. Members Office does
    not use (a login page in word/, an .exe at the root, an embedded
    document) are read as archive members on top, and the two readings
    are merged: hiding one behind the other changes nothing. Any other
    ZIP is an archive."""
    names = _zip_names(raw)
    kind = office.detect_ooxml_kind(raw) if names is not None else None
    if kind is None:
        if names is None and archives._ext(filename) not in archives.ARCHIVE_EXTS:
            # Not a readable ZIP: the Office reader says so to the user.
            return office.analyse_ooxml(raw, filename)
        if depth:
            raise ValueError("Nested archive.")
        return archives.analyse_zip(
            raw, filename, inner=lambda data, name: dispatch_raw(data, name, None, depth + 1)
        )
    doc = office.analyse_ooxml(raw, filename)
    names = names or []
    if office.media_parts(names):
        short = len((doc.get("extracted_text") or "").split()) < _FEW_WORDS
        doc = _merge(doc, _pictures_of(raw, names, read_text=short))
    # What Office itself adds (a picture's SVG version, a chart's workbook)
    # is read but neither listed nor a reason for caution; anything else
    # is a foreign member, listed like an archive's.
    extra = [n for n in names if office.office_extra(n)]
    foreign = [n for n in names if not office.is_office_part(n) and not office.office_extra(n)]
    if not foreign and not extra and archives._ext(filename) not in archives.ARCHIVE_EXTS:
        return doc
    if depth:
        # Inside an archive: the members are named, not opened.
        flags = archives.classify_names(foreign)
        if foreign:
            flags.append("inner_files_not_extracted")
        return _merge(doc, {"notable_features": flags})
    members = archives.analyse_zip(
        raw,
        filename,
        inner=lambda data, name: dispatch_raw(data, name, None, depth + 1),
        skip=office.is_office_part,
        later=office.office_extra,
    )
    listed = set(foreign)
    # What Office added is reported only when it says something.
    members["inner_files"] = [
        f
        for f in members.get("inner_files") or []
        if f.get("filename") in listed or f.get("notable_features") or f.get("url_count")
    ]
    members["entries"] = [n for n in members.get("entries") or [] if n in listed]
    members["_all_entries"] = [n for n in members.get("_all_entries") or [] if n in listed]
    members["entry_count"] = len(members["_all_entries"])
    return _merge(doc, members)


def _read_page(raw: bytes, filename: str, mime: str) -> dict[str, Any]:
    """HTML, SVG (compressed or not), and MIME files made of pages."""
    if mime in MIME_PAGE_TYPES:
        return analyse_mime_pages(raw, filename)
    if raw[:2] == b"\x1f\x8b":  # .svgz
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
                raw = gz.read(MAX_ATTACHMENT_BYTES)
        except OSError as e:
            raise RuntimeError(f"SVG parse failed: {e}") from e
    return analyse_html(raw, filename)


def dispatch_raw(
    raw: bytes, filename: str, mime_type: str | None = None, depth: int = 0
) -> dict[str, Any]:
    """Analyse decoded bytes. depth > 0 inside an archive (nested
    archives are flagged, not opened)."""
    danger = _dangerous_type(raw, filename)
    if danger:
        return danger

    mime = sniff_type(filename, raw[:1024], mime_type)

    # Archives that are not Office documents, and calendar invites.
    fmt = archives.is_rar_or_7z(raw)
    if fmt:
        if depth:
            raise ValueError("Nested archive.")
        opener = archives.analyse_rar if fmt == "rar" else archives.analyse_7z
        return opener(
            raw, filename, inner=lambda data, name: dispatch_raw(data, name, None, depth + 1)
        )
    if mime == "text/calendar" or raw.lstrip()[:15].upper().startswith(b"BEGIN:VCALENDAR"):
        return archives.analyse_ics(raw, filename, extract_urls)

    # Office documents: modern ones are ZIPs, legacy / encrypted ones OLE2.
    # Any ZIP, whatever its name says, is read by what it holds (_read_zip).
    if raw.startswith(b"PK"):
        return _read_zip(raw, filename, depth)
    if mime in office.OOXML_MIMES:
        if raw.startswith(office.OLE2_MAGIC):
            # password-protected .docx/.xlsx are OLE2 containers
            return office.analyse_ole(raw, filename)
        return office.analyse_ooxml(raw, filename)
    if mime in office.LEGACY_MIMES:
        return office.analyse_ole(raw, filename)
    if mime in IMAGE_MIMES:
        return analyse_image(raw, filename)

    if mime == "application/pdf":
        return analyse_pdf(raw, filename)
    if mime in MIME_PAGE_TYPES or mime in PAGE_MIMES:
        return _read_page(raw, filename, mime)
    if mime == "text/plain":
        # trivial: treat as plain text
        text = without_invisible(raw.decode("utf-8", errors="ignore"))[:MAX_EXTRACTED_TEXT]
        return {
            "kind": "text",
            "filename": filename,
            "size_bytes": len(raw),
            "extracted_text": text,
            "extracted_text_chars": len(text),
            "extracted_urls": extract_urls(text),
            "notable_features": [],
        }

    raise ValueError(
        f"Unsupported attachment type: {mime}. "
        "Supported: PDF, HTML, SVG, web archives (.mht), plain text, "
        "images (PNG, JPEG, GIF, WebP, BMP, TIFF), "
        "Word, Excel and PowerPoint (modern and legacy formats), ZIP, RAR and 7z archives "
        "and calendar invites (.ics)."
    )
