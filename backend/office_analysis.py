"""
PhishLens: Office document analysis (v1.12).
=====================================================================
Extracts text and links from Word, Excel and PowerPoint attachments and
flags the features attackers use to turn a document into a dropper.
Standard library only (zipfile + ElementTree): no python-docx or
openpyxl, so there is nothing extra to install and nothing that
executes document content.

Modern formats (.docx .docm .xlsx .xlsm .pptx .pptm) are ZIP containers
of XML parts. Legacy formats (.doc .xls .ppt) and password-protected
modern files are OLE2 compound files; for those we only scan the raw
bytes for macro and encryption markers and pull out URLs.

Flags raised (scored in extension_backend._RISK):

* contains_macros           VBA project or Excel 4.0 macro sheet
* remote_template           template loaded from an external URL
                            (template injection, CVE-2017-0199 family)
* dde_field                 DDE / DDEAUTO field that can run commands
* embedded_ole_object       embedded OLE object (often a hidden payload)
* contains_activex          ActiveX control
* external_data_connection  workbook pulls data from an external source
* encrypted_document        password-protected file: the password is
                            usually in the email, to blind scanners
* legacy_office_format      pre-2007 binary format
* suspicious_xml_doctype    an XML part declares a DOCTYPE (XXE attempt)

Safety limits: entry count, total uncompressed size (zip bombs), per
part size, and any part with a DOCTYPE is skipped instead of parsed.
"""
from __future__ import annotations

import io
import logging
import re
import zipfile
from typing import Any
from xml.etree import ElementTree as ET

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

MAX_ZIP_ENTRIES = 3000
MAX_UNCOMPRESSED_TOTAL = 60 * 1024 * 1024
MAX_PART_BYTES = 15 * 1024 * 1024
MAX_TEXT = 20_000
MAX_URLS = 200

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

OOXML_MIMES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
}
LEGACY_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/x-ole-storage",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]{3,2048}", re.IGNORECASE)
# Word field codes: HYPERLINK "https://..." and DDE / DDEAUTO
_HYPERLINK_FIELD_RE = re.compile(r'HYPERLINK\s+"([^"]{1,2048})"', re.IGNORECASE)
_DDE_FIELD_RE = re.compile(r"\bDDE(AUTO)?\b", re.IGNORECASE)

# XML namespaces: we match on local names so we don't depend on them.
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _urls_from(text: str, into: list[str]) -> None:
    for m in _URL_RE.finditer(text or ""):
        u = m.group(0).rstrip(".,;)")
        if u not in into:
            into.append(u)
            if len(into) >= MAX_URLS:
                return


# =====================================================================
# OOXML (zip + xml)
# =====================================================================
def detect_ooxml_kind(raw: bytes) -> str | None:
    """Return 'docx', 'xlsx' or 'pptx' for a valid OOXML container, None
    for any other ZIP (or a corrupt one)."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = set(zf.namelist())
    except Exception:
        return None
    if "[Content_Types].xml" not in names:
        return None
    if any(n.startswith("word/") for n in names):
        return "docx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    return None


def _read_part(zf: zipfile.ZipFile, name: str, flags: list[str]) -> bytes | None:
    try:
        with zf.open(name) as fh:
            data = fh.read(MAX_PART_BYTES + 1)
    except Exception:
        return None
    if len(data) > MAX_PART_BYTES:
        return None
    head = data[:2048].upper()
    if b"<!DOCTYPE" in head or b"<!ENTITY" in head:
        if "suspicious_xml_doctype" not in flags:
            flags.append("suspicious_xml_doctype")
        return None
    return data


def _text_from_xml(data: bytes, text_tags: set[str], block_tags: set[str]) -> str:
    """Collect text nodes, with a newline at the end of each block
    (paragraph, table row, shared string)."""
    out: list[str] = []
    try:
        for event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
            name = _local(el.tag)
            if name in text_tags and el.text:
                out.append(el.text)
            elif name in block_tags:
                out.append("\n")
            el.clear()
    except ET.ParseError:
        pass
    return re.sub(r"\n{2,}", "\n", "".join(out)).strip()


def _field_codes(data: bytes) -> str:
    """Word field instructions (instrText and fldSimple@instr)."""
    out = []
    try:
        for _event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
            name = _local(el.tag)
            if name == "instrText" and el.text:
                out.append(el.text)
            elif name == "fldSimple":
                for k, v in el.attrib.items():
                    if _local(k) == "instr":
                        out.append(v)
            el.clear()
    except ET.ParseError:
        pass
    return " ".join(out)


def _external_rels(data: bytes) -> list[tuple[str, str]]:
    """(relationship type suffix, target) for every TargetMode=External rel."""
    rels = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return rels
    for el in root:
        if _local(el.tag) != "Relationship":
            continue
        if (el.get("TargetMode") or "").lower() != "external":
            continue
        rtype = (el.get("Type") or "").rsplit("/", 1)[-1]
        rels.append((rtype, el.get("Target") or ""))
    return rels


def analyse_ooxml(raw: bytes, filename: str) -> dict[str, Any]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise ValueError("Unsupported or corrupt Office document: not a valid ZIP container.")

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError("Office document has too many parts to analyse safely.")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_TOTAL:
            raise ValueError("Office document expands beyond the safe size limit (possible zip bomb).")

        names = [i.filename for i in infos]
        kind = detect_ooxml_kind(raw)
        if kind is None:
            raise ValueError("Unsupported ZIP attachment: not a Word, Excel or PowerPoint document.")

        flags: list[str] = []
        lower = [n.lower() for n in names]
        if any(n.endswith("vbaproject.bin") for n in lower) or any(
            n.startswith("xl/macrosheets/") for n in lower
        ):
            flags.append("contains_macros")
        if any("/embeddings/" in n and (n.endswith(".bin") or "oleobject" in n) for n in lower):
            flags.append("embedded_ole_object")
        if any("/activex/" in n for n in lower):
            flags.append("contains_activex")
        if "xl/connections.xml" in lower:
            flags.append("external_data_connection")

        texts: list[str] = []
        urls: list[str] = []

        if kind == "docx":
            parts = [n for n in names if re.fullmatch(r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml", n)]
            text_tags, block_tags = {"t"}, {"p", "tr"}
        elif kind == "xlsx":
            parts = [n for n in names if n == "xl/sharedStrings.xml" or re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)]
            text_tags, block_tags = {"t", "f"}, {"si", "row"}
        else:
            parts = [n for n in names if re.fullmatch(r"ppt/(slides/slide\d+|notesSlides/notesSlide\d+)\.xml", n)]
            text_tags, block_tags = {"t"}, {"p"}

        # stable order: document.xml / sheet1 / slide1 first
        parts.sort(key=lambda n: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", n)])

        for name in parts:
            data = _read_part(zf, name, flags)
            if data is None:
                continue
            texts.append(_text_from_xml(data, text_tags, block_tags))
            if kind == "docx":
                codes = _field_codes(data)
                if _DDE_FIELD_RE.search(codes) and "dde_field" not in flags:
                    flags.append("dde_field")
                for m in _HYPERLINK_FIELD_RE.finditer(codes):
                    _urls_from(m.group(1), urls)
            if sum(len(t) for t in texts) >= MAX_TEXT:
                break

        # Relationships: hyperlinks, remote templates, external OLE links
        for name in names:
            if not name.endswith(".rels"):
                continue
            data = _read_part(zf, name, flags)
            if data is None:
                continue
            for rtype, target in _external_rels(data):
                if rtype == "attachedTemplate" and "remote_template" not in flags:
                    flags.append("remote_template")
                if rtype == "oleObject" and "embedded_ole_object" not in flags:
                    flags.append("embedded_ole_object")
                _urls_from(target, urls)

    text = "\n".join(t for t in texts if t)[:MAX_TEXT]
    _urls_from(text, urls)

    return {
        "kind": kind,
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": text,
        "extracted_text_chars": len(text),
        "extracted_urls": urls[:MAX_URLS],
        "notable_features": flags,
    }


# =====================================================================
# OLE2 (legacy .doc/.xls/.ppt, or an encrypted modern file)
# =====================================================================
def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


# "_VBA_PROJECT" is the stream every VBA project has (Word, Excel,
# PowerPoint); "Macros" is the Word 97-2003 storage that holds it.
_OLE_VBA_MARKERS = (_utf16("_VBA_PROJECT"), b"Attribute VB_Name")
_OLE_XLM_MARKERS = (_utf16("Macros"),)
_OLE_ENCRYPTED_MARKERS = (_utf16("EncryptedPackage"), _utf16("EncryptionInfo"))
_OLE_OBJECT_MARKERS = (_utf16("ObjectPool"), _utf16("Ole10Native"))


def analyse_ole(raw: bytes, filename: str) -> dict[str, Any]:
    if not raw.startswith(OLE2_MAGIC):
        raise ValueError("Unsupported or corrupt Office document: not an OLE2 file.")

    flags: list[str] = []
    encrypted = any(m in raw for m in _OLE_ENCRYPTED_MARKERS)
    if encrypted:
        # A password-protected .docx/.xlsx is stored as OLE2 too.
        flags.append("encrypted_document")
    else:
        flags.append("legacy_office_format")
    if any(m in raw for m in _OLE_VBA_MARKERS + _OLE_XLM_MARKERS):
        flags.append("contains_macros")
    if any(m in raw for m in _OLE_OBJECT_MARKERS):
        flags.append("embedded_ole_object")
    if b"DDEAUTO" in raw or _utf16("DDEAUTO") in raw:
        flags.append("dde_field")

    # Binary formats keep text in either cp1252 or UTF-16LE runs. We only
    # pull URLs out of them; the text agent is skipped (too noisy).
    urls: list[str] = []
    _urls_from(raw.decode("latin-1", errors="ignore"), urls)
    try:
        _urls_from(raw.decode("utf-16-le", errors="ignore"), urls)
    except Exception:
        pass

    return {
        "kind": "office_legacy",
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": "",
        "extracted_text_chars": 0,
        "extracted_urls": urls[:MAX_URLS],
        "notable_features": flags,
    }
