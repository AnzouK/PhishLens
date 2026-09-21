"""
PhishLens — email attachment analysis.
=====================================================================
Extract text and URLs from email attachments (PDF, HTML for Phase 1;
DOCX / XLSX planned for Phase 2; images with OCR + steg heuristics for
Phase 3) and reuse the existing text / URL / reputation pipeline on
the extracted content.

The dispatcher (analyse_attachment) returns a JSON-serialisable dict
whose shape mirrors /analyse as closely as possible so the extension
and landing widgets can share their rendering code.
"""
from __future__ import annotations

import base64
import io
import re
from typing import Any

import logging
logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

# ---------------------------------------------------------------------
# Limits — enforced BEFORE decoding to protect the process.
# ---------------------------------------------------------------------
MAX_ATTACHMENT_BYTES  = 10 * 1024 * 1024      # 10 MB hard cap
MAX_EXTRACTED_TEXT    = 20_000                # chars fed to the text agent
MAX_EXTRACTED_URLS    = 200                   # URLs sent to reputation cascade
PDF_PAGE_LIMIT        = 50                    # abort text extraction past this

# ---------------------------------------------------------------------
# Optional deps — graceful fallback (endpoint still responds, but
# returns a clear error) if the module isn't in the runtime image.
# ---------------------------------------------------------------------
try:
    import pdfplumber                         # type: ignore
    _PDFPLUMBER_OK = True
except Exception as _e:
    _PDFPLUMBER_OK = False
    logger.warning("pdfplumber not available ({_e}); PDF attachments will be rejected.")

try:
    from bs4 import BeautifulSoup             # type: ignore
    _BS4_OK = True
except Exception as _e:
    _BS4_OK = False
    logger.warning("beautifulsoup4 not available ({_e}); HTML attachments will be rejected.")


# ---------------------------------------------------------------------
# MIME sniffing — trust the extension of the filename first, fall back
# to content sniffing. Client sends its own mime_type as a hint but we
# don't trust it blindly.
# ---------------------------------------------------------------------
_MIME_BY_EXT = {
    ".pdf":  "application/pdf",
    ".html": "text/html",
    ".htm":  "text/html",
    ".xhtml":"application/xhtml+xml",
    ".txt":  "text/plain",
}

def sniff_type(filename: str, content_head: bytes, client_hint: str | None) -> str:
    """
    Return a canonical MIME type. Extension-first, then magic-byte sniff.
    Client hint is used only as a last resort.
    """
    ext = ""
    if filename and "." in filename:
        ext = "." + filename.rsplit(".", 1)[1].lower()
    if ext in _MIME_BY_EXT:
        return _MIME_BY_EXT[ext]

    # magic bytes
    head = content_head[:16]
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.lstrip().lower().startswith((b"<!doctype html", b"<html", b"<!--", b"<head")):
        return "text/html"
    if head[:2] == b"PK":
        # ZIP-based (docx, xlsx, pptx, jar, ...) — Phase 2 territory
        return "application/zip"

    # Fall back to whatever the client claimed, sanitized.
    if client_hint and "/" in client_hint:
        return client_hint.lower().split(";", 1)[0].strip()
    return "application/octet-stream"


# ---------------------------------------------------------------------
# URL extraction — same regex the /analyse endpoint uses, plus we also
# pick up bare-domain "click here" style links (missing scheme).
# ---------------------------------------------------------------------
_URL_RE      = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
_URL_DEDUP_N = MAX_EXTRACTED_URLS

def extract_urls(text: str) -> list[str]:
    seen, out = set(), []
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;)")
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
# Suspicious PDF markers — presence of any of these is worth surfacing
# to the user, they're the classic phishing / malware droppers.
_PDF_SUSPICIOUS_MARKERS = {
    b"/JavaScript":    "contains_javascript",
    b"/JS":            "contains_javascript",
    b"/AcroForm":      "contains_form",
    b"/OpenAction":    "auto_execute_on_open",
    b"/Launch":        "launch_external_action",
    b"/EmbeddedFile":  "embeds_another_file",
    b"/GoToR":         "remote_link_action",
    b"/RichMedia":     "flash_or_richmedia",
    b"/URI":           "contains_link_annotation",
    b"/SubmitForm":    "submits_form_to_url",
}


def _pdf_scan_markers(raw: bytes) -> list[str]:
    """
    Cheap pattern scan on the raw PDF bytes. Doesn't attempt to parse
    object streams — it just looks for the well-known feature tags.
    Zero cost, high signal for phishing PDFs.
    """
    flags = []
    for needle, label in _PDF_SUSPICIOUS_MARKERS.items():
        if needle in raw and label not in flags:
            flags.append(label)
    return flags


def analyse_pdf(raw: bytes, filename: str) -> dict[str, Any]:
    """
    Extract text + URLs from a PDF, plus a list of qualitative feature
    flags. Returns a dict ready for the shared UI.
    """
    if not _PDFPLUMBER_OK:
        raise RuntimeError("PDF support is not available (pdfplumber missing).")

    markers = _pdf_scan_markers(raw)

    text_chunks: list[str] = []
    pages_read = 0
    page_count = 0
    try:
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
    except Exception as e:
        raise RuntimeError(f"PDF parse failed: {e}")

    text = "\n".join(text_chunks)[:MAX_EXTRACTED_TEXT]

    # URLs — extracted text can miss link annotations (clickable button
    # with no visible URL text). We also parse /URI markers directly.
    urls = extract_urls(text)
    if len(urls) < MAX_EXTRACTED_URLS:
        # Cheap annotation URI scan — grabs (/URI (https://…))
        for m in re.finditer(rb"/URI\s*\(([^)]+)\)", raw):
            try:
                u = m.group(1).decode("latin-1", errors="ignore").strip()
                if u.lower().startswith(("http://", "https://")) and u not in urls:
                    urls.append(u)
                    if len(urls) >= MAX_EXTRACTED_URLS:
                        break
            except Exception:
                continue

    return {
        "kind":              "pdf",
        "filename":          filename,
        "size_bytes":        len(raw),
        "page_count":        page_count,
        "pages_read":        pages_read,
        "extracted_text":    text,
        "extracted_text_chars": len(text),
        "extracted_urls":    urls,
        "notable_features":  markers,
    }


# =====================================================================
# HTML analysis
# =====================================================================
def analyse_html(raw: bytes, filename: str) -> dict[str, Any]:
    """
    Extract visible text + href / action URLs from an HTML attachment.
    HTML phishing attachments typically render a login form styled as
    a well-known brand, with an <form action="attacker.tld"> — we grab
    all such URLs regardless of visible text.
    """
    if not _BS4_OK:
        raise RuntimeError("HTML support is not available (beautifulsoup4 missing).")

    try:
        soup = BeautifulSoup(raw, "html.parser")
    except Exception as e:
        raise RuntimeError(f"HTML parse failed: {e}")

    # Strip noisy tags before extracting visible text
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    text = soup.get_text(separator=" ", strip=True)[:MAX_EXTRACTED_TEXT]

    # URLs from the DOM even when they're not in the visible text
    urls, seen = [], set()
    for tag in soup.find_all(["a", "form", "iframe", "link", "img", "script"]):
        for attr in ("href", "action", "src"):
            u = (tag.get(attr) or "").strip()
            if u.lower().startswith(("http://", "https://")) and u not in seen:
                seen.add(u)
                urls.append(u)
                if len(urls) >= MAX_EXTRACTED_URLS:
                    break

    # Notable features
    flags = []
    if soup.find("form"):
        flags.append("contains_form")
    if soup.find(["input"], attrs={"type": "password"}):
        flags.append("contains_password_field")
    if soup.find(["script"]) or soup.find(attrs={"onclick": True}) or soup.find(attrs={"onload": True}):
        flags.append("contains_javascript")
    if soup.find("iframe"):
        flags.append("contains_iframe")
    if soup.find("meta", attrs={"http-equiv": re.compile("^refresh$", re.I)}):
        flags.append("meta_refresh_redirect")

    return {
        "kind":              "html",
        "filename":          filename,
        "size_bytes":        len(raw),
        "extracted_text":    text,
        "extracted_text_chars": len(text),
        "extracted_urls":    urls,
        "notable_features":  flags,
    }


# =====================================================================
# Dispatcher — the public entry point.
# =====================================================================
def analyse_attachment(content_b64: str,
                       filename: str = "",
                       mime_type: str | None = None) -> dict[str, Any]:
    """
    Decode the base64 payload, dispatch by MIME, return a
    JSON-serialisable dict.

    Does NOT call the model agents itself — that's the /analyse_attachment
    endpoint's job (it wires the extracted text + URLs into text_agent /
    url_agent / reputation cascade the same way /analyse does for emails).

    Raises ValueError on unsupported types or oversized inputs.
    """
    if not content_b64:
        raise ValueError("Empty attachment.")

    try:
        raw = base64.b64decode(content_b64, validate=False)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise ValueError(f"Attachment exceeds {MAX_ATTACHMENT_BYTES // (1024*1024)} MB limit.")
    if not raw:
        raise ValueError("Attachment is empty after decode.")

    mime = sniff_type(filename or "", raw[:16], mime_type)

    if mime == "application/pdf":
        return analyse_pdf(raw, filename)
    if mime in ("text/html", "application/xhtml+xml"):
        return analyse_html(raw, filename)
    if mime == "text/plain":
        # trivial — treat as plain text
        text = raw.decode("utf-8", errors="ignore")[:MAX_EXTRACTED_TEXT]
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
        f"Phase 1 supports PDF, HTML and plain text. "
        f"DOCX/XLSX will land in Phase 2, images with OCR in Phase 3."
    )
