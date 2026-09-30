"""
Tests for ocr.py and the image / scanned-PDF paths of attachment
analysis. They need Pillow, OpenCV, pypdfium2, pdfplumber and the
tesseract binary; each test is skipped when its dependency is missing
(CI installs all of them).
"""
from __future__ import annotations

import base64
import io

import pytest

import ocr
from attachment_analysis import analyse_attachment

PIL = pytest.importorskip("PIL")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

needs_tesseract = pytest.mark.skipif(not ocr.capabilities()["ocr"], reason="tesseract not installed")
needs_qr = pytest.mark.skipif(not ocr.capabilities()["qr"], reason="OpenCV not installed")
needs_render = pytest.mark.skipif(not ocr.capabilities()["pdf_render"], reason="pypdfium2 not installed")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def qr_image(payload: str, scale: int = 8) -> "Image.Image":
    cv2 = pytest.importorskip("cv2")
    q = cv2.QRCodeEncoder.create().encode(payload)
    q = cv2.resize(q, (q.shape[1] * scale, q.shape[0] * scale), interpolation=cv2.INTER_NEAREST)
    return Image.fromarray(q).convert("RGB")


def phishing_page(with_qr: str | None = None) -> "Image.Image":
    img = Image.new("RGB", (1400, 900), "white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=48)
    draw.text((60, 60), "Your account is suspended.", fill="black", font=font)
    draw.text((60, 140), "Verify your password at http://secure-verify.tk/login", fill="black", font=font)
    if with_qr:
        img.paste(qr_image(with_qr), (60, 300))
    return img


def to_bytes(img: "Image.Image", fmt: str) -> bytes:
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


# ---------------------------------------------------------------------
# Unit
# ---------------------------------------------------------------------
class TestHelpers:
    def test_qr_payload_filter(self):
        assert ocr.qr_urls(["https://a.example/x", "WIFI:S:home;;", "paypa1.com/login", ""]) == [
            "https://a.example/x",
            "http://paypa1.com/login",
        ]

    def test_decompression_bomb_rejected(self, monkeypatch):
        monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 1000)
        with pytest.raises(ValueError):
            ocr.load_image(to_bytes(Image.new("RGB", (200, 200)), "PNG"))

    def test_downscale(self, monkeypatch):
        monkeypatch.setattr(ocr, "OCR_MAX_SIDE", 500)
        img = ocr.load_image(to_bytes(Image.new("RGB", (2000, 1000), "white"), "PNG"))
        assert max(img.size) == 500

    def test_corrupt_image_rejected(self):
        with pytest.raises(ValueError):
            analyse_attachment(b64(b"\x89PNG\r\n\x1a\nnot really"), filename="x.png")


# ---------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------
@needs_qr
def test_qr_in_image_is_decoded():
    r = analyse_attachment(b64(to_bytes(qr_image("https://evil-qr.example/pay"), "PNG")), filename="scan.png")
    assert r["kind"] == "image"
    assert r["qr_urls"] == ["https://evil-qr.example/pay"]
    assert "contains_qr_code" in r["notable_features"]
    assert "https://evil-qr.example/pay" in r["extracted_urls"]


@needs_tesseract
def test_ocr_reads_image_text():
    r = analyse_attachment(b64(to_bytes(phishing_page(), "PNG")), filename="login.jpg")
    assert "suspended" in r["extracted_text"].lower()
    assert "http://secure-verify.tk/login" in r["extracted_urls"]
    assert "text_from_ocr" in r["notable_features"]


def test_blank_photo_has_no_flags():
    r = analyse_attachment(b64(to_bytes(Image.new("RGB", (300, 200), "skyblue"), "JPEG")), filename="photo.jpg")
    assert r["notable_features"] == []
    assert r["extracted_urls"] == []


# ---------------------------------------------------------------------
# Scanned PDFs
# ---------------------------------------------------------------------
@needs_render
@needs_tesseract
@needs_qr
def test_scanned_pdf_goes_through_ocr_and_qr():
    pytest.importorskip("pdfplumber")
    pdf = to_bytes(phishing_page(with_qr="https://evil-qr.example/pay"), "PDF")
    r = analyse_attachment(b64(pdf), filename="invoice.pdf")
    assert "image_only_pdf" in r["notable_features"]
    assert "text_from_ocr" in r["notable_features"]
    assert "contains_qr_code" in r["notable_features"]
    assert r["ocr_used"] is True
    assert "suspended" in r["extracted_text"].lower()
    assert "https://evil-qr.example/pay" in r["extracted_urls"]


@needs_render
@needs_qr
def test_text_pdf_is_not_flagged_as_scanned():
    pytest.importorskip("pdfplumber")
    pytest.importorskip("reportlab")
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    for i in range(5):
        c.drawString(72, 760 - i * 14, "Quarterly report for the finance team, figures attached below.")
    c.save()
    r = analyse_attachment(b64(buf.getvalue()), filename="report.pdf")
    assert "image_only_pdf" not in r["notable_features"]
    assert r["ocr_used"] is False
