"""
Archives, calendar invites, encrypted PDFs and risky file types (v1.14).
Everything is built in memory; no native library is needed.
"""
from __future__ import annotations

import base64
import io
import zipfile

import pytest

import archive_analysis as archives
from attachment_analysis import analyse_attachment


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def make_zip(files: dict[str, str | bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:
        # Set the "encrypted" general-purpose bit in the local and central
        # headers: enough for the listing, the content is never read.
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            while i >= 0:
                raw[i + off] |= 1
                i = raw.find(sig, i + 4)
    return bytes(raw)


class TestClassifyNames:
    @pytest.mark.parametrize("name,flag", [
        ("setup.exe", "executable_in_archive"),
        ("run.js", "script_in_archive"),
        ("Invoice.lnk", "shortcut_in_archive"),
        ("disk.iso", "disk_image_in_archive"),
        ("more.zip", "nested_archive"),
        ("invoice.pdf.exe", "double_extension"),
        ("scan.jpg   .js", "double_extension"),
    ])
    def test_flags(self, name, flag):
        assert flag in archives.classify_names([name])

    def test_documents_are_not_flagged(self):
        assert archives.classify_names(["report.pdf", "photo.jpg", "notes.txt"]) == []


class TestZip:
    def test_executable_inside_and_inner_text_analysed(self):
        raw = make_zip({"invoice.pdf.exe": "MZ", "notes.txt": "see https://evil.example/login"})
        r = analyse_attachment(b64(raw), filename="docs.zip")
        assert r["kind"] == "archive"
        assert {"double_extension", "executable_in_archive"} <= set(r["notable_features"])
        assert r["extracted_urls"] == ["https://evil.example/login"]
        assert r["inner_files"][0]["filename"] == "notes.txt"

    def test_encrypted_zip_is_flagged_not_opened(self):
        r = analyse_attachment(b64(make_zip({"doc.txt": "hi"}, encrypted=True)), filename="secret.zip")
        assert r["encrypted"] is True
        assert "encrypted_archive" in r["notable_features"]
        assert r["inner_files"] == []

    def test_nested_archive_not_opened(self):
        r = analyse_attachment(b64(make_zip({"inner.zip": "PK"})), filename="n.zip")
        assert r["notable_features"] == ["nested_archive"]

    def test_rar_is_recognised_only(self):
        r = analyse_attachment(b64(b"Rar!\x1a\x07\x00rest"), filename="a.rar")
        assert r["archive_format"] == "rar"
        assert r["notable_features"] == ["uninspectable_archive"]


class TestOtherTypes:
    def test_ics_links_and_organizer(self):
        ics = (b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Payroll update\r\n"
               b"DESCRIPTION:Confirm here https://pay\r\n roll-verify.example/x\\nThanks\r\n"
               b"ORGANIZER:mailto:hr@corp.example\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
        r = analyse_attachment(b64(ics), filename="invite.ics")
        assert r["kind"] == "calendar"
        assert r["extracted_urls"] == ["https://payroll-verify.example/x"]
        assert r["organizer"] == "hr@corp.example"
        assert "calendar_with_links" in r["notable_features"]

    def test_executable_attachment(self):
        r = analyse_attachment(b64(b"MZ\x90\x00"), filename="setup.exe")
        assert r["notable_features"] == ["dangerous_file_type"]

    def test_disk_image_attachment(self):
        r = analyse_attachment(b64(b"\x00" * 32), filename="parcel.iso")
        assert r["notable_features"] == ["disk_image_attachment"]

    def test_encrypted_pdf(self, monkeypatch):
        pytest.importorskip("pdfplumber")
        import attachment_analysis as aa

        def locked(*_a, **_k):
            raise ValueError("password required")
        monkeypatch.setattr(aa.pdfplumber, "open", locked)
        raw = b"%PDF-1.4\n1 0 obj << /Encrypt 2 0 R >> endobj\ngarbage"
        r = analyse_attachment(b64(raw), filename="statement.pdf")
        assert r["kind"] == "pdf"
        assert "encrypted_document" in r["notable_features"]
