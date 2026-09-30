"""
PhishLens: OCR and QR code decoding for attachments (v1.12).
=====================================================================
Two evasion tricks this module closes:

* **Image-only content.** A phishing PDF that is just a scanned picture
  of a fake invoice, or a PNG of a login page, has no extractable text,
  so the text agent used to be skipped entirely. We render the pages and
  run Tesseract OCR on them.
* **QR codes ("quishing").** The link is drawn as a QR code so that
  neither the text nor the link annotations contain it. We decode QR
  codes with OpenCV and feed the URLs to the reputation cascade.

Every dependency is optional. If Tesseract, OpenCV or pypdfium2 is
missing, the matching step is skipped and ``capabilities()`` says so;
the endpoint keeps working on whatever text is available.

Resource limits (all env-tunable) protect the shared CPU-only demo:
at most ``OCR_MAX_PAGES`` pages rendered, images downscaled so the long
side is at most ``OCR_MAX_SIDE`` pixels, a Tesseract timeout per page,
and Pillow's decompression-bomb guard.
"""
from __future__ import annotations

import io
import logging
import os
import re
import shutil
from typing import Any

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

OCR_MAX_PAGES = int(os.environ.get("OCR_MAX_PAGES", "3"))
OCR_DPI = int(os.environ.get("OCR_DPI", "200"))
OCR_MAX_SIDE = int(os.environ.get("OCR_MAX_SIDE", "3000"))
OCR_TIMEOUT_S = int(os.environ.get("OCR_TIMEOUT_S", "10"))
OCR_LANG = os.environ.get("OCR_LANG", "eng")
IMAGE_MAX_PIXELS = 40_000_000  # about 6300 x 6300; beyond that it is a bomb, not a scan

# ---------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------
try:
    from PIL import Image  # type: ignore

    Image.MAX_IMAGE_PIXELS = IMAGE_MAX_PIXELS
    _PIL_OK = True
except Exception as _e:  # pragma: no cover - depends on the image
    Image = None  # type: ignore
    _PIL_OK = False
    logger.warning(f"Pillow not available ({_e}); OCR and QR decoding disabled.")

try:
    import pytesseract  # type: ignore

    _TESSERACT_OK = _PIL_OK and bool(
        shutil.which(pytesseract.pytesseract.tesseract_cmd) or shutil.which("tesseract")
    )
    if not _TESSERACT_OK:
        logger.warning("tesseract binary not found; OCR disabled.")
except Exception as _e:  # pragma: no cover
    _TESSERACT_OK = False
    logger.warning(f"pytesseract not available ({_e}); OCR disabled.")

try:
    import cv2  # type: ignore
    import numpy as np  # type: ignore

    _CV2_OK = _PIL_OK
except Exception as _e:  # pragma: no cover
    _CV2_OK = False
    logger.warning(f"OpenCV not available ({_e}); QR decoding disabled.")

try:
    import pypdfium2 as pdfium  # type: ignore

    _PDFIUM_OK = _PIL_OK
except Exception as _e:  # pragma: no cover
    _PDFIUM_OK = False
    logger.warning(f"pypdfium2 not available ({_e}); PDF page rendering disabled.")


def capabilities() -> dict[str, bool]:
    """Which steps can run in this process (surfaced in the API response)."""
    return {
        "ocr": _TESSERACT_OK,
        "qr": _CV2_OK,
        "pdf_render": _PDFIUM_OK,
    }


# ---------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------
def _downscale(img: "Image.Image") -> "Image.Image":
    w, h = img.size
    longest = max(w, h)
    if longest <= OCR_MAX_SIDE:
        return img
    ratio = OCR_MAX_SIDE / float(longest)
    return img.resize((max(1, int(w * ratio)), max(1, int(h * ratio))))


def load_image(raw: bytes) -> "Image.Image":
    """Decode image bytes into an RGB Pillow image, size-capped.

    Raises ValueError for undecodable or oversized (decompression bomb)
    images, so the endpoint answers 400 instead of burning memory.
    """
    if not _PIL_OK:
        raise RuntimeError("Image support is not available (Pillow missing).")
    try:
        img = Image.open(io.BytesIO(raw))
        # Only the first frame of animated GIF / multi-page TIFF.
        img.seek(0)
        img.load()
    except Image.DecompressionBombError as e:  # type: ignore[attr-defined]
        raise ValueError(f"Image is too large to analyse safely: {e}")
    except Exception as e:
        raise ValueError(f"Unsupported or corrupt image: {e}")
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    return _downscale(img)


def ocr_image(img: "Image.Image") -> str:
    """Tesseract OCR on one image. Returns '' when OCR is unavailable,
    times out, or finds nothing."""
    if not _TESSERACT_OK:
        return ""
    try:
        text = pytesseract.image_to_string(
            img.convert("L"), lang=OCR_LANG, timeout=OCR_TIMEOUT_S, config="--psm 3"
        )
    except RuntimeError:
        # pytesseract raises RuntimeError on timeout
        logger.warning("OCR timed out on one page; skipping it.")
        return ""
    except Exception as e:
        logger.warning(f"OCR failed: {e}")
        return ""
    # Collapse the whitespace noise Tesseract leaves between blocks.
    return re.sub(r"[ \t]+", " ", re.sub(r"\n{3,}", "\n\n", text)).strip()


_BARE_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,251}\.[a-z]{2,24}(/\S*)?$", re.IGNORECASE)


def _qr_payload_to_url(payload: str) -> str | None:
    """Keep only payloads that are links. A bare domain (no scheme) is a
    common trick to dodge naive URL matching, so it is normalised."""
    p = (payload or "").strip()
    if not p or len(p) > 2048:
        return None
    if p.lower().startswith(("http://", "https://")):
        return p
    if _BARE_DOMAIN_RE.match(p):
        return "http://" + p
    return None


def decode_qr(img: "Image.Image") -> list[str]:
    """Return the raw payloads of every QR code found in the image."""
    if not _CV2_OK:
        return []
    try:
        arr = np.array(img.convert("L"))
        detector = cv2.QRCodeDetector()
        payloads: list[str] = []
        try:
            ok, decoded, _points, _ = detector.detectAndDecodeMulti(arr)
            if ok:
                payloads.extend(d for d in decoded if d)
        except Exception:
            pass
        if not payloads:
            single, _points, _ = detector.detectAndDecode(arr)
            if single:
                payloads.append(single)
        # de-duplicate, keep order
        return list(dict.fromkeys(payloads))
    except Exception as e:
        logger.warning(f"QR decoding failed: {e}")
        return []


def qr_urls(payloads: list[str]) -> list[str]:
    urls = []
    for p in payloads:
        u = _qr_payload_to_url(p)
        if u and u not in urls:
            urls.append(u)
    return urls


# ---------------------------------------------------------------------
# PDF pages
# ---------------------------------------------------------------------
def render_pdf_pages(raw: bytes, max_pages: int = OCR_MAX_PAGES) -> list["Image.Image"]:
    """Render the first ``max_pages`` pages of a PDF to Pillow images.

    The scale is chosen per page so that the long side never exceeds
    OCR_MAX_SIDE, whatever size the PDF declares for its pages.
    """
    if not _PDFIUM_OK:
        return []
    images = []
    pdf = None
    try:
        pdf = pdfium.PdfDocument(raw)
        for i in range(min(len(pdf), max_pages)):
            page = pdf[i]
            try:
                w_pt, h_pt = page.get_size()
                scale = OCR_DPI / 72.0
                longest_px = max(w_pt, h_pt) * scale
                if longest_px > OCR_MAX_SIDE:
                    scale = OCR_MAX_SIDE / max(w_pt, h_pt)
                bitmap = page.render(scale=scale)
                images.append(bitmap.to_pil().convert("RGB"))
            finally:
                page.close()
    except Exception as e:
        logger.warning(f"PDF page rendering failed: {e}")
    finally:
        if pdf is not None:
            try:
                pdf.close()
            except Exception:
                pass
    return images


def scan_images(images: list["Image.Image"], do_ocr: bool) -> dict[str, Any]:
    """OCR (optional) and QR decoding over a list of page images."""
    texts, payloads = [], []
    for img in images:
        payloads.extend(decode_qr(img))
        if do_ocr:
            t = ocr_image(img)
            if t:
                texts.append(t)
    payloads = list(dict.fromkeys(payloads))
    return {
        "text": "\n\n".join(texts),
        "qr_payloads": payloads,
        "qr_urls": qr_urls(payloads),
        "pages_scanned": len(images),
    }
