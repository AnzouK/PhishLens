"""
PhishLens: email attachment analysis.
=====================================================================
Extract text and URLs from email attachments and reuse the existing
text / URL / reputation pipeline on the extracted content.

Supported (v1.12): PDF (with OCR for scanned pages and QR decoding),
HTML, plain text, images (OCR + QR), Word / Excel / PowerPoint in both
modern and legacy formats (text, links and macro-style flags; see
office_analysis.py). OCR and QR live in ocr.py.
v1.14: ZIP archives (listed, risky entries flagged, supported files
inside analysed one level deep), RAR / 7z (opened the same way since
v1.15.3 when rarfile / py7zr are installed), calendar
invites (.ics), encrypted PDFs, and executable / script / shortcut /
disk-image files (flagged by type). See archive_analysis.py.

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

import archive_analysis as archives
import ocr
import office_analysis as office

# ---------------------------------------------------------------------
# Limits: enforced BEFORE decoding to protect the process.
# ---------------------------------------------------------------------
MAX_ATTACHMENT_BYTES  = 10 * 1024 * 1024      # 10 MB hard cap
MAX_EXTRACTED_TEXT    = 20_000                # chars fed to the text agent
MAX_EXTRACTED_URLS    = 200                   # URLs sent to reputation cascade
PDF_PAGE_LIMIT        = 50                    # abort text extraction past this
# A PDF with fewer extracted characters than this per page (on average)
# is treated as scanned / image-only and sent to OCR.
SCANNED_CHARS_PER_PAGE = 50

# ---------------------------------------------------------------------
# Optional deps: graceful fallback (endpoint still responds, but
# returns a clear error) if the module isn't in the runtime image.
# ---------------------------------------------------------------------
try:
    import pdfplumber                         # type: ignore
    _PDFPLUMBER_OK = True
except Exception as _e:
    _PDFPLUMBER_OK = False
    logger.warning(f"pdfplumber not available ({_e}); PDF attachments will be rejected.")

try:
    from bs4 import BeautifulSoup             # type: ignore
    _BS4_OK = True
except Exception as _e:
    _BS4_OK = False
    logger.warning(f"beautifulsoup4 not available ({_e}); HTML attachments will be rejected.")


# ---------------------------------------------------------------------
# MIME sniffing: trust the extension of the filename first, fall back
# to content sniffing. Client sends its own mime_type as a hint but we
# don't trust it blindly.
# ---------------------------------------------------------------------
_MIME_BY_EXT = {
    ".pdf":  "application/pdf",
    ".html": "text/html",
    ".htm":  "text/html",
    ".xhtml":"application/xhtml+xml",
    ".txt":  "text/plain",
    # Archives and calendar invites (v1.14)
    ".zip":  "application/zip",
    ".rar":  "application/vnd.rar",
    ".7z":   "application/x-7z-compressed",
    ".ics":  "text/calendar",
    # Office, modern (zip + xml)
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".docm": "application/vnd.ms-word.document.macroenabled.12",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.ms-excel.sheet.macroenabled.12",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".pptm": "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    # Office, legacy (OLE2)
    ".doc":  "application/msword",
    ".xls":  "application/vnd.ms-excel",
    ".ppt":  "application/vnd.ms-powerpoint",
    # Images
    ".png":  "image/png",
    ".jpg":  "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif":  "image/gif",
    ".webp": "image/webp",
    ".bmp":  "image/bmp",
    ".tif":  "image/tiff",
    ".tiff": "image/tiff",
}

IMAGE_MIMES = {m for m in _MIME_BY_EXT.values() if m.startswith("image/")}

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
    if head.startswith(b"BM"):
        return "image/bmp"
    if head.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"

    # Fall back to whatever the client claimed, sanitized.
    if client_hint and "/" in client_hint:
        return client_hint.lower().split(";", 1)[0].strip()
    return "application/octet-stream"


# ---------------------------------------------------------------------
# URL extraction: same regex the /analyse endpoint uses, plus we also
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
# Suspicious PDF markers: presence of any of these is worth surfacing
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
    object streams; it just looks for the well-known feature tags.
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
        if b"/Encrypt" in raw:
            # Password-protected PDF: nothing to read, which is the point
            # when the password travels in the email body.
            return {
                "kind":              "pdf",
                "filename":          filename,
                "size_bytes":        len(raw),
                "page_count":        0,
                "pages_read":        0,
                "extracted_text":    "",
                "extracted_text_chars": 0,
                "extracted_urls":    [],
                "notable_features":  markers + ["encrypted_document"],
            }
        raise RuntimeError(f"PDF parse failed: {e}")

    text = "\n".join(text_chunks)[:MAX_EXTRACTED_TEXT]

    # URLs: extracted text can miss link annotations (clickable button
    # with no visible URL text). We also parse /URI markers directly.
    urls = extract_urls(text)
    if len(urls) < MAX_EXTRACTED_URLS:
        # Cheap annotation URI scan: grabs (/URI (https://…)).
        # The inner class is length-capped (2048 bytes) to close a
        # polynomial-ReDoS surface that CodeQL flagged: a crafted PDF
        # with a very long /URI( body and no closing paren could push
        # the regex engine into O(n²) territory. 2 KB is more than any
        # legit annotation ever holds.
        for m in re.finditer(rb"/URI\s*\(([^)]{1,2048})\)", raw):
            try:
                u = m.group(1).decode("latin-1", errors="ignore").strip()
                if u.lower().startswith(("http://", "https://")) and u not in urls:
                    urls.append(u)
                    if len(urls) >= MAX_EXTRACTED_URLS:
                        break
            except Exception:
                continue

    # Scanned / image-only PDFs and QR codes (v1.12). The first pages are
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
            text = (text + "\n" + scan["text"]).strip()[:MAX_EXTRACTED_TEXT]
            ocr_used = True
            for u in extract_urls(scan["text"]):
                if u not in urls:
                    urls.append(u)
        qr_found = scan["qr_urls"]
        for u in qr_found:
            if u not in urls:
                urls.append(u)
    if scanned:
        markers.append("image_only_pdf")
    if qr_found:
        markers.append("contains_qr_code")
    if ocr_used:
        markers.append("text_from_ocr")

    return {
        "kind":              "pdf",
        "filename":          filename,
        "size_bytes":        len(raw),
        "page_count":        page_count,
        "pages_read":        pages_read,
        "extracted_text":    text,
        "extracted_text_chars": len(text),
        "extracted_urls":    urls[:MAX_EXTRACTED_URLS],
        "notable_features":  markers,
        "qr_urls":           qr_found,
        "ocr_used":          ocr_used,
        "capabilities":      caps,
    }


# =====================================================================
# Image analysis (v1.12): OCR + QR
# =====================================================================
def analyse_image(raw: bytes, filename: str) -> dict[str, Any]:
    img = ocr.load_image(raw)
    caps = ocr.capabilities()
    scan = ocr.scan_images([img], do_ocr=caps["ocr"])
    text = scan["text"][:MAX_EXTRACTED_TEXT]
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
        "kind":              "image",
        "filename":          filename,
        "size_bytes":        len(raw),
        "width":             img.size[0],
        "height":            img.size[1],
        "extracted_text":    text,
        "extracted_text_chars": len(text),
        "extracted_urls":    urls[:MAX_EXTRACTED_URLS],
        "notable_features":  flags,
        "qr_urls":           scan["qr_urls"],
        "ocr_used":          bool(text),
        "capabilities":      caps,
    }


# =====================================================================
# HTML analysis
# =====================================================================
def analyse_html(raw: bytes, filename: str) -> dict[str, Any]:
    """
    Extract visible text + href / action URLs from an HTML attachment.
    HTML phishing attachments typically render a login form styled as
    a well-known brand, with a <form action="attacker.tld">. We grab
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
# Dispatcher: the public entry point.
# =====================================================================
def analyse_attachment(content_b64: str,
                       filename: str = "",
                       mime_type: str | None = None) -> dict[str, Any]:
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
        raise ValueError(f"Base64 decode failed: {e}")

    if len(raw) > MAX_ATTACHMENT_BYTES:
        raise ValueError(f"Attachment exceeds {MAX_ATTACHMENT_BYTES // (1024*1024)} MB limit.")
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
        "kind":              "executable" if flags[0] == "dangerous_file_type" else "disk_image",
        "filename":          filename,
        "size_bytes":        len(raw),
        "extracted_text":    "",
        "extracted_text_chars": 0,
        "extracted_urls":    [],
        "notable_features":  flags,
    }


def dispatch_raw(raw: bytes, filename: str, mime_type: str | None = None,
                 depth: int = 0) -> dict[str, Any]:
    """Analyse decoded bytes. depth > 0 inside an archive (nested
    archives are flagged, not opened)."""
    danger = _dangerous_type(raw, filename)
    if danger:
        return danger

    mime = sniff_type(filename, raw[:16], mime_type)

    # Archives that are not Office documents, and calendar invites (v1.14).
    fmt = archives.is_rar_or_7z(raw)
    if fmt:
        if depth:
            raise ValueError("Nested archive.")
        opener = archives.analyse_rar if fmt == "rar" else archives.analyse_7z
        return opener(raw, filename,
                      inner=lambda data, name: dispatch_raw(data, name, None, depth + 1))
    if mime == "text/calendar" or raw.lstrip()[:15].upper().startswith(b"BEGIN:VCALENDAR"):
        return archives.analyse_ics(raw, filename, extract_urls)

    # Office documents: modern ones are ZIPs, legacy / encrypted ones OLE2.
    if mime == "application/zip":
        if office.detect_ooxml_kind(raw) is None:
            if depth:
                raise ValueError("Nested archive.")
            return archives.analyse_zip(
                raw, filename,
                inner=lambda data, name: dispatch_raw(data, name, None, depth + 1))
        return office.analyse_ooxml(raw, filename)
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
    if mime in ("text/html", "application/xhtml+xml"):
        return analyse_html(raw, filename)
    if mime == "text/plain":
        # trivial: treat as plain text
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
        "Supported: PDF, HTML, plain text, images (PNG, JPEG, GIF, WebP, BMP, TIFF), "
        "Word, Excel and PowerPoint (modern and legacy formats), ZIP, RAR and 7z archives "
        "and calendar invites (.ics)."
    )
