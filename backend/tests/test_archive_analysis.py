"""
Archives, calendar invites, encrypted PDFs and risky file types (v1.14),
RAR and 7z opened (v1.15.3). Everything is built in memory; the RAR and
7z tests are skipped when rarfile / py7zr are not installed.
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

    def test_damaged_rar_is_recognised(self):
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


def test_strip_tags_is_linear_on_crafted_input():
    assert archives._strip_tags("<p>Hi <b>there</b></p>").split() == ["Hi", "there"]
    assert archives._strip_tags("<" * 50_000) == ""


# ---------------------------------------------------------------------
# v1.15.3: RAR and 7z opened (rarfile / py7zr)
# ---------------------------------------------------------------------
def _vint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _rar5_block(htype: int, body: bytes, flags: int = 0, data_size: int | None = None) -> bytes:
    import zlib
    fields = _vint(htype) + _vint(flags)
    if data_size is not None:
        fields += _vint(data_size)
    fields += body
    sized = _vint(len(fields)) + fields
    return zlib.crc32(sized).to_bytes(4, "little") + sized


def make_rar5_stored(files: dict[str, bytes], encrypted_headers: bool = False) -> bytes:
    """Minimal RAR5 archive with uncompressed ("stored") members: readable
    by rarfile without any external tool. Built by hand because there is
    no free RAR writer."""
    import zlib
    out = b"Rar!\x1a\x07\x01\x00"
    if encrypted_headers:
        # Archive encryption header (type 4): AES-256, KDF count, salt.
        return out + _rar5_block(4, _vint(0) + _vint(0) + bytes([15]) + b"\x00" * 16)
    out += _rar5_block(1, _vint(0))                       # main archive header
    for name, data in files.items():
        n = name.encode()
        body = (_vint(0x4)                                # file flags: CRC32 present
                + _vint(len(data))                        # unpacked size
                + _vint(0x20)                             # attributes
                + zlib.crc32(data).to_bytes(4, "little")  # data CRC32
                + _vint(0)                                # compression: v0, store
                + _vint(0)                                # host OS: Windows
                + _vint(len(n)) + n)
        out += _rar5_block(2, body, flags=0x2, data_size=len(data)) + data
    return out + _rar5_block(5, _vint(0))                 # end of archive


def make_7z(files: dict[str, bytes], password: str | None = None) -> bytes:
    py7zr = pytest.importorskip("py7zr")
    buf = io.BytesIO()
    kwargs = {"password": password, "header_encryption": True} if password else {}
    with py7zr.SevenZipFile(buf, "w", **kwargs) as z:
        for name, data in files.items():
            z.writestr(data, name)
    return buf.getvalue()


class TestRar:
    def setup_method(self):
        pytest.importorskip("rarfile")

    def test_listing_flags_and_stored_text_analysed(self):
        raw = make_rar5_stored({"invoice.pdf.exe": b"MZ",
                                "notes.txt": b"login at https://evil.example/rar"})
        r = analyse_attachment(b64(raw), filename="docs.rar")
        assert r["archive_format"] == "rar"
        assert r["entry_count"] == 2
        assert {"double_extension", "executable_in_archive"} <= set(r["notable_features"])
        assert "https://evil.example/rar" in r["extracted_urls"]
        assert r["inner_files"][0]["filename"] == "notes.txt"

    def test_encrypted_headers_are_flagged(self):
        r = analyse_attachment(b64(make_rar5_stored({}, encrypted_headers=True)), filename="s.rar")
        assert r["archive_format"] == "rar"
        assert "encrypted_archive" in r["notable_features"]
        assert r["inner_files"] == []

    def test_members_without_decompression_tool(self, monkeypatch):
        import rarfile

        def no_tool(self, name, pwd=None):
            raise rarfile.RarCannotExec("no unrar / bsdtar")

        monkeypatch.setattr(rarfile.RarFile, "read", no_tool)
        r = analyse_attachment(b64(make_rar5_stored({"notes.txt": b"hello"})), filename="c.rar")
        assert r["entry_count"] == 1
        assert "inner_files_not_extracted" in r["notable_features"]
        assert r["inner_files"] == []

    def test_damaged_rar_is_uninspectable(self):
        r = analyse_attachment(b64(b"Rar!\x1a\x07\x00rest"), filename="a.rar")
        assert r["notable_features"] == ["uninspectable_archive"]


class Test7z:
    def test_listing_flags_and_inner_text_analysed(self):
        raw = make_7z({"run.js": b"WScript", "readme.txt": b"pay at https://evil.example/7z"})
        r = analyse_attachment(b64(raw), filename="pack.7z")
        assert r["archive_format"] == "7z"
        assert r["entry_count"] == 2
        assert "script_in_archive" in r["notable_features"]
        assert "https://evil.example/7z" in r["extracted_urls"]

    def test_password_protected_7z_is_flagged(self):
        raw = make_7z({"doc.txt": b"secret"}, password="1234")
        r = analyse_attachment(b64(raw), filename="secret.7z")
        assert "encrypted_archive" in r["notable_features"]
        assert r["inner_files"] == []

    def test_bomb_like_member_is_not_extracted(self, monkeypatch):
        monkeypatch.setattr(archives, "MAX_RATIO", 2)
        raw = make_7z({"big.txt": b"A" * 200_000})
        r = analyse_attachment(b64(raw), filename="b.7z")
        assert "zip_bomb_suspected" in r["notable_features"]
        assert r["inner_files"] == []


def test_without_libraries_rar_and_7z_stay_uninspectable(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name in ("rarfile", "py7zr"):
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    for raw, name in ((make_rar5_stored({"a.txt": b"x"}), "a.rar"), (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 26, "a.7z")):
        r = analyse_attachment(b64(raw), filename=name)
        assert r["notable_features"] == ["uninspectable_archive"]
