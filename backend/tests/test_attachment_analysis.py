"""
Tests for attachment_analysis. Covers MIME sniffing, size cap, and the
HTML feature-flag extraction. PDF extraction is not tested here because
it depends on pdfplumber; the smoke test lives in the CI job's
`import` step and in end-to-end request tests.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attachment_analysis import (
    analyse_attachment,
    analyse_html,
    extract_urls,
    sniff_type,
    MAX_ATTACHMENT_BYTES,
)


# ---------------------------------------------------------------------
# MIME sniffing
# ---------------------------------------------------------------------
class TestSniffType:
    def test_pdf_by_magic_bytes(self):
        assert sniff_type("", b"%PDF-1.7\n", None) == "application/pdf"

    def test_pdf_by_extension(self):
        assert sniff_type("invoice.pdf", b"garbage", "text/plain") == "application/pdf"

    def test_html_by_extension(self):
        assert sniff_type("login.html", b"garbage", None) == "text/html"

    def test_html_by_magic_bytes(self):
        assert sniff_type("", b"<!doctype html>\n<html>", None) == "text/html"

    def test_zip_prefix_recognised_as_zip(self):
        # DOCX / XLSX are ZIP files under the hood — we return the zip
        # MIME here; analyse_attachment turns it into a 400.
        assert sniff_type("", b"PK\x03\x04garbage", None) == "application/zip"

    def test_unknown_falls_back_to_client_hint(self):
        assert sniff_type("f.xyz", b"garbage", "image/webp") == "image/webp"

    def test_unknown_and_no_hint(self):
        assert sniff_type("f.xyz", b"garbage", None) == "application/octet-stream"


# ---------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------
class TestExtractUrls:
    def test_finds_multiple_urls(self):
        text = "Visit https://a.com and http://b.tld/foo for more."
        urls = extract_urls(text)
        assert urls == ["https://a.com", "http://b.tld/foo"]

    def test_deduplicates(self):
        text = "https://a.com and again https://a.com"
        assert extract_urls(text) == ["https://a.com"]

    def test_strips_trailing_punctuation(self):
        text = "See https://a.com/path)."
        assert extract_urls(text) == ["https://a.com/path"]


# ---------------------------------------------------------------------
# HTML feature flags
# ---------------------------------------------------------------------
class TestAnalyseHtml:
    def test_plain_html_no_flags(self):
        raw = b"<html><body><p>Hello world</p></body></html>"
        r = analyse_html(raw, "notes.html")
        assert r["kind"] == "html"
        assert "Hello world" in r["extracted_text"]
        assert r["notable_features"] == []
        assert r["extracted_urls"] == []

    def test_login_form_flagged(self):
        raw = (b"<html><body><form action='http://attacker.tld/login'>"
               b"<input type='password' name='p'></form></body></html>")
        r = analyse_html(raw, "phish.html")
        flags = r["notable_features"]
        assert "contains_form" in flags
        assert "contains_password_field" in flags
        assert "http://attacker.tld/login" in r["extracted_urls"]

    def test_meta_refresh_redirect(self):
        raw = (b"<html><head>"
               b"<meta http-equiv='refresh' content='0; url=http://bad.tld'>"
               b"</head><body>redirect</body></html>")
        r = analyse_html(raw, "redirect.html")
        assert "meta_refresh_redirect" in r["notable_features"]

    def test_iframe_detected(self):
        raw = b"<html><body><iframe src='http://bad.tld'></iframe></body></html>"
        r = analyse_html(raw, "framed.html")
        assert "contains_iframe" in r["notable_features"]

    def test_stripped_scripts_dont_appear_in_extracted_text(self):
        raw = (b"<html><body><script>alert('xss')</script>"
               b"Visible text</body></html>")
        r = analyse_html(raw, "s.html")
        assert "alert" not in r["extracted_text"]
        assert "Visible text" in r["extracted_text"]


# ---------------------------------------------------------------------
# Dispatcher — size + type errors
# ---------------------------------------------------------------------
class TestAnalyseAttachment:
    def _b64(self, s: bytes) -> str:
        return base64.b64encode(s).decode()

    def test_empty_payload_rejected(self):
        with pytest.raises(ValueError, match="Empty"):
            analyse_attachment("", filename="x.pdf")

    def test_bad_base64_rejected(self):
        # base64 is very permissive so hard to make it error on decode.
        # Use a payload that decodes to nothing.
        with pytest.raises(ValueError, match="empty after decode"):
            analyse_attachment(self._b64(b""), filename="x.pdf")

    def test_oversized_rejected(self):
        # Craft an 11 MB blob
        oversized = b"A" * (MAX_ATTACHMENT_BYTES + 1)
        with pytest.raises(ValueError, match="exceeds"):
            analyse_attachment(self._b64(oversized), filename="x.html")

    def test_unsupported_zip_rejected(self):
        with pytest.raises(ValueError, match="Unsupported"):
            analyse_attachment(self._b64(b"PK\x03\x04garbage"),
                               filename="x.docx",
                               mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    def test_html_happy_path(self):
        raw = b"<html><body>Hello</body></html>"
        r = analyse_attachment(self._b64(raw), filename="x.html",
                               mime_type="text/html")
        assert r["kind"] == "html"
        assert r["size_bytes"] == len(raw)

    def test_plain_text_supported(self):
        raw = b"Follow this link: https://legit.tld/verify"
        r = analyse_attachment(self._b64(raw), filename="notes.txt",
                               mime_type="text/plain")
        assert r["kind"] == "text"
        assert "https://legit.tld/verify" in r["extracted_urls"]
