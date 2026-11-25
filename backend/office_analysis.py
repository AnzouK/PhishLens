"""
PhishLens: Office document analysis.

Pulls text and links out of Word, Excel and PowerPoint attachments and
flags the features attackers use to turn a document into a dropper.
It only uses zipfile and defusedxml. python-docx and openpyxl are left
out on purpose, so nothing extra is installed and nothing ever runs
document content.

Modern formats (.docx .docm .xlsx .xlsm .pptx .pptm and their templates,
shows and add-ins) are ZIP files of XML parts. Legacy formats (.doc .xls
.ppt) and password-protected modern files are OLE2 compound files. For
those we read the directory and scan the raw bytes for macro and
encryption markers and URLs.

Flags raised (scored in fusion.FEATURE_RISK):

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
* launch_external_action    "Run program" action, or a link to a share,
                            a local file, a protocol handler or a program
* document_not_fully_read   reading stopped at the time limit
* executable_in_archive...  a program, script or shortcut packed in an
                            embedded object (archive_analysis names)

We cap the entry count, the total uncompressed size (zip bombs) and the
size of each part. A part that declares a DOCTYPE is skipped, never parsed.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import time
import zipfile
from typing import Any

# defusedxml has the xml.etree API but refuses entity expansion and
# external entities, which matters for untrusted Office XML.
from defusedxml import ElementTree as ET

import archive_analysis as archives
from email_parsing import absolute_http, urls_in_text
from unicode_text import without_invisible

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

MAX_ZIP_ENTRIES = 3000
MAX_UNCOMPRESSED_TOTAL = 60 * 1024 * 1024
MAX_PART_BYTES = 15 * 1024 * 1024
MAX_TEXT = 20_000
MAX_URLS = 200

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

OOXML_MIMES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-word.document.macroenabled.12",
    "application/vnd.ms-word.template.macroenabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/vnd.ms-excel.sheet.macroenabled.12",
    "application/vnd.ms-excel.sheet.binary.macroenabled.12",
    "application/vnd.ms-excel.template.macroenabled.12",
    "application/vnd.ms-excel.addin.macroenabled.12",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.presentationml.template",
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
    "application/vnd.ms-powerpoint.presentation.macroenabled.12",
    "application/vnd.ms-powerpoint.template.macroenabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
    "application/vnd.ms-powerpoint.addin.macroenabled.12",
}
LEGACY_MIMES = {
    "application/msword",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/x-ole-storage",
}

# Word field codes. DDE and DDEAUTO can start a program. HYPERLINK,
# INCLUDEPICTURE and INCLUDETEXT carry an address, quoted or not, before
# or after switches (HYPERLINK \o "tip" "https://..." or HYPERLINK https://...).
_DDE_FIELD_RE = re.compile(r"\bDDE(AUTO)?\b", re.IGNORECASE)
_LINK_FIELD_RE = re.compile(
    r"\b(?:HYPERLINK|INCLUDEPICTURE|INCLUDETEXT)\b((?:\s+(?:\\\w(?:\s+\"[^\"]*\")?|\"[^\"]*\"|[^\s\"\\]+))*)",
    re.IGNORECASE,
)
_FIELD_ARG_RE = re.compile(r'"([^"]{1,2048})"|([^\s"\\]{1,2048})')
_FIELD_SWITCH_RE = re.compile(r'\\\w(?:\s+"[^"]*")?')
# Excel formulas and DDE links that start a program, such as
# =cmd|'/c calc'!A1 or =MSEXCEL|'\..\..\Windows\System32\cmd.exe /c ...'!A1.
# We match one line at a time (one <f>, or one run of a binary part). The
# program name opens the formula or comes after an operator or separator,
# and a cell reference (quoted or not) follows the "!". Strings in double
# quotes are removed first because they are not formulas.
_DDE_FORMULA_RE = re.compile(
    r"(?:^|(?<=[=+\-@(,;&]))[ \t]*[\w.\\]{1,64}[ \t]*\|[ \t]*['\"]?[^|'\"\r\n]{0,300}['\"]?"
    r"[ \t]*![ \t]*'?[$A-Za-z0-9_]",
    re.IGNORECASE | re.MULTILINE,
)
_DOUBLE_QUOTED_RE = re.compile(r'"[^"\r\n]*"')
# PowerPoint "Run program" and macro actions on a click or mouse-over.
_PIPE_RE = re.compile(rb"\||&#0*124;|&#x0*7c;", re.IGNORECASE)
# A document built to be slow to read must come back as "not fully read",
# never as read and clean.
_READ_SECONDS = 4.0
_RUN_ACTION_RE = re.compile(rb"ppaction://(?:program|macro|ole)", re.IGNORECASE)


# We match elements on their local name and ignore namespaces.
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _urls_from(text: str, into: list[str]) -> None:
    """Find URLs in document text the same way we do for email bodies."""
    for u in urls_in_text(text or ""):
        if u not in into:
            into.append(u)
            if len(into) >= MAX_URLS:
                return


# OOXML (zip + xml)
# Main part of each kind of document. Office ignores case in part names,
# so we compare them in lower case.
_MAIN_PART = {
    "docx": re.compile(r"word/document\d*\.xml"),
    "xlsx": re.compile(r"xl/workbook\.(?:xml|bin)"),
    "pptx": re.compile(r"ppt/presentation\.xml"),
}
# Root entries of a real Office package. Anything else in the ZIP is not
# part of the document (see attachment_analysis._plain_archive).
OOXML_ROOTS = (
    "[content_types].xml",
    "_rels/",
    "docprops/",
    "docmetadata/",
    "customxml/",
    "customui/",
    "_xmlsignatures/",
    "word/",
    "xl/",
    "ppt/",
)
# Extensions a genuine package part can have. A part with any other
# extension (a page, a PDF, a program) is handed to attachment_analysis
# and read like an archive member.
OFFICE_PART_EXTS = frozenset(
    [
        "xml",
        "rels",
        "bin",
        "vml",
        "emf",
        "wmf",
        "emz",
        "wmz",
        "png",
        "jpg",
        "jpeg",
        "jpe",
        "jfif",
        "gif",
        "bmp",
        "tif",
        "tiff",
        "wdp",
        "jxr",
        "hdp",
        "odttf",
        "ttf",
        "otf",
        "fntdata",
        "sigs",
        "psdsxs",
        "mp3",
        "mp4",
        "m4a",
        "wav",
        "wma",
        "wmv",
        "avi",
        "mov",
        "glb",
    ]
)
_MEDIA_EXTS = frozenset(["png", "jpg", "jpeg", "jpe", "jfif", "gif", "bmp", "tif", "tiff"])


def part_name(name: str) -> str:
    """Normalise an entry name the way Office resolves it.

    Backslashes become slashes, the leading slash goes and case is folded.
    """
    return name.replace("\\", "/").lstrip("/").lower()


def is_office_part(name: str) -> bool:
    """Return True if the entry looks like a normal Office part.

    It has to sit under a known folder, use a part extension and have no
    ".." in its path.
    """
    n = part_name(name)
    return (
        n.startswith(OOXML_ROOTS)
        and ".." not in n.split("/")
        and (n == "[content_types].xml" or archives._ext(n) in OFFICE_PART_EXTS)
    )


# Files Office itself adds to a package, such as the SVG copy of a picture
# or the workbook behind a chart. We still read them because they can
# carry links or macros, but we don't list them as extra files. Office
# writes these as .xlsx, .docx or .pptx (OLE objects as .bin), so a
# macro-enabled or legacy file here is not one of them.
_EXTRA_EMBEDDED = frozenset(["xlsx", "docx", "pptx"])


def office_extra(name: str) -> bool:
    n = part_name(name)
    if not n.startswith(OOXML_ROOTS) or ".." in n.split("/"):
        return False
    ext = archives._ext(n)
    return ("/media/" in n and ext == "svg") or ("/embeddings/" in n and ext in _EXTRA_EMBEDDED)


def media_parts(names: list[str]) -> list[str]:
    """Return the package's images. Some lures are a single picture with no text."""
    return [
        n
        for n in names
        if is_office_part(n) and "/media/" in part_name(n) and archives._ext(n) in _MEDIA_EXTS
    ]


def detect_ooxml_kind(raw: bytes) -> str | None:
    """Return 'docx', 'xlsx' or 'pptx', or None for any other ZIP.

    A package needs [Content_Types].xml and the main part of its kind.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = {part_name(n) for n in zf.namelist()[:MAX_ZIP_ENTRIES]}
    except Exception:
        return None
    if "[content_types].xml" not in names:
        return None
    for kind, main in _MAIN_PART.items():
        if any(main.fullmatch(n) for n in names):
            return kind
    return None


class _Part(str):
    """A part name that remembers its zip entry, so the exact entry can be
    opened even when two entries share a name."""

    info: zipfile.ZipInfo

    def __new__(cls, info: zipfile.ZipInfo) -> _Part:
        part = super().__new__(cls, info.filename)
        part.info = info
        return part


def _read_part(zf: zipfile.ZipFile, name: str, flags: list[str]) -> bytes | None:
    try:
        with zf.open(getattr(name, "info", name)) as fh:
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


def _text_from_xml(data: bytes, text_tags: set[str] | None, block_tags: set[str]) -> str:
    """Join the text nodes and end each paragraph, row or string with a newline."""
    out: list[str] = []
    try:
        for _event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
            name = _local(el.tag)
            if (text_tags is None or name in text_tags) and el.text:
                out.append(el.text)
            elif name in block_tags:
                out.append("\n")
            el.clear()
    except ET.ParseError:
        pass
    return re.sub(r"\n{2,}", "\n", "".join(out)).strip()


class _Fields:
    """Keep track of nested Word fields while we walk a document.

    Each open field gets a frame with its instruction text, its result text
    and a flag for whether the separator has been seen.
    """

    def __init__(self) -> None:
        self.codes: list[str] = []
        self.stack: list[tuple[list[str], list[str], list[bool]]] = []

    def in_instruction(self) -> bool:
        return bool(self.stack) and not self.stack[-1][2][0]

    def char(self, kind: str) -> None:
        if kind == "begin" and len(self.stack) < 64:
            self.stack.append(([], [], [False]))
        elif kind == "separate" and self.stack:
            self.stack[-1][2][0] = True
        elif kind == "end" and self.stack:
            self.close()

    def instruction(self, text: str) -> None:
        if self.in_instruction():
            self.stack[-1][0].append(text)
        elif not self.stack:
            self.codes.append(text)

    def result(self, text: str) -> None:
        if self.stack and self.stack[-1][2][0]:
            self.stack[-1][1].append(text)

    def close(self) -> None:
        instr, result, _sep = self.stack.pop()
        if instr:
            self.codes.append("".join(instr))
        if self.in_instruction():
            self.stack[-1][0].append("".join(result))


def _field_codes(data: bytes) -> str:
    """Rebuild Word field instructions the way Word does.

    Word joins instrText runs without spaces, so "DD" + "EAUTO" becomes
    DDEAUTO. A nested field contributes its result, which lets an attacker
    write DDE as "DD" + {QUOTE "EAUTO"}. We keep each nested field's own
    instruction as well. fldSimple@instr counts as one field.
    """
    fields = _Fields()
    try:
        for _event, el in ET.iterparse(io.BytesIO(data), events=("end",)):
            name = _local(el.tag)
            if name == "fldChar":
                fields.char(
                    next(
                        (v.lower() for k, v in el.attrib.items() if _local(k) == "fldCharType"), ""
                    )
                )
            elif name == "instrText" and el.text:
                fields.instruction(el.text)
            elif name == "t" and el.text:
                fields.result(el.text)
            elif name == "fldSimple":
                fields.codes += [v for k, v in el.attrib.items() if _local(k) == "instr"]
            el.clear()
    except ET.ParseError:
        pass
    while fields.stack:
        fields.close()
    return " ".join(fields.codes)


def _field_urls(codes: str, urls: list[str]) -> None:
    """Add the addresses in HYPERLINK, INCLUDEPICTURE and INCLUDETEXT fields to urls.

    We take the first argument that is not a switch, and also any URL that
    appears elsewhere in the field code.
    """
    for m in _LINK_FIELD_RE.finditer(codes):
        args = _FIELD_SWITCH_RE.sub(" ", m.group(1))
        for a in _FIELD_ARG_RE.finditer(args):
            target = a.group(1) or a.group(2) or ""
            href = absolute_http(target)
            if href and href not in urls:
                urls.append(href)
            break
    _urls_from(codes, urls)


def _relationships(data: bytes) -> list[tuple[str, str, bool]]:
    """(type suffix, target, is_external) for each relationship in a .rels part."""
    rels = []
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return rels
    for el in root:
        if _local(el.tag) != "Relationship":
            continue
        external = (el.get("TargetMode") or "").strip().lower() == "external"
        rtype = (el.get("Type") or "").rsplit("/", 1)[-1].strip().lower()
        rels.append((rtype, (el.get("Target") or "").strip(), external))
    return rels


def _part_name_flags(names: list[str]) -> list[str]:
    """Flag risky features we can see from part names alone."""
    flags: list[str] = []
    lower = [part_name(n) for n in names]
    if any(n.endswith("vbaproject.bin") for n in lower) or any(
        n.startswith("xl/macrosheets/") for n in lower
    ):
        flags.append("contains_macros")
    if any("/embeddings/" in n and (n.endswith(".bin") or "oleobject" in n) for n in lower):
        flags.append("embedded_ole_object")
    if any("/activex/" in n for n in lower):
        flags.append("contains_activex")
    if any(n.startswith(("xl/connections.", "xl/externallinks/")) for n in lower):
        # A data connection or a linked workbook, XML (.xlsx) or binary (.xlsb).
        flags.append("external_data_connection")
    return flags


# Parts in the main folder that never hold document text.
_NOT_TEXT = re.compile(
    r".*/(styles|stylesWithEffects|settings|webSettings|fontTable|numbering|theme\d*|"
    r"presProps|viewProps|tableStyles|calcChain|people|commentsIds|commentsExtended)\.xml",
    re.IGNORECASE,
)


def _text_parts(kind: str, names: list[str]) -> tuple[list[str], set[str], set[str]]:
    """List the XML parts that hold document text, in reading order.

    We read every XML part in the main folder except styles, settings and
    themes. Attackers rename parts ("Document.xml", "document2.xml") and
    Office still opens them, so we can't rely on the usual names.
    """
    folder = {"docx": "word/", "xlsx": "xl/", "pptx": "ppt/"}[kind]
    if kind == "docx":
        text_tags, block_tags = {"t"}, {"p", "tr"}
    elif kind == "xlsx":
        text_tags, block_tags = {"t", "f"}, {"si", "row"}
    else:
        text_tags, block_tags = {"t"}, {"p"}
    parts = [
        n
        for n in names
        if part_name(n).startswith(folder)
        and part_name(n).endswith(".xml")
        and not _NOT_TEXT.fullmatch(part_name(n))
    ]
    main = _MAIN_PART[kind]
    # Main part first, then natural order so sheet2 comes before sheet10.
    parts.sort(
        key=lambda n: (
            not main.fullmatch(part_name(n)),
            [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", part_name(n))],
        )
    )
    return parts, text_tags, block_tags


# Relationship types that make Office fetch something as the file opens.
# Templates and frames are the template injection route.
_LOADING_RELS = {
    "attachedtemplate": "remote_template",
    "frame": "remote_template",
    "subdocument": "remote_template",
    "oleobject": "embedded_ole_object",
    "externallinkpath": "external_data_connection",
    "externallink": "external_data_connection",
}
_MACRO_RELS = {"vbaproject", "wordvbadata", "xlmacrosheet", "xlintlmacrosheet", "macrosheet"}
# Content types used only by macro projects, controls and OLE objects.
_CONTENT_TYPE_FLAGS = (
    (re.compile(rb"vbaproject|macrosheet|vbadata", re.I), "contains_macros"),
    (re.compile(rb"activex", re.I), "contains_activex"),
    (re.compile(rb"oleobject", re.I), "embedded_ole_object"),
)


_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]*:")
_DRIVE_RE = re.compile(r"[a-z]:[\\/]")
# Link targets that open something other than a web page.
_RUNNING_TARGETS = (
    "\\\\",
    "file:",
    "ms-",
    "mhtml:",
    "search-ms:",
    "search:",
    "javascript:",
    "vbscript:",
    "shell:",
)


def _add(flags: list[str], flag: str) -> None:
    if flag not in flags:
        flags.append(flag)


def _scan_relationships(
    zf: zipfile.ZipFile, names: list[str], flags: list[str], urls: list[str]
) -> None:
    """Read the relationship parts for links and for anything Office would load.

    This catches remote templates and frames, external OLE links and macro
    projects under any part name. It also flags targets that are not web
    addresses, such as "\\\\host\\share", file:, ms-msdt:, mhtml: or a program.
    """
    for name in names:
        if not part_name(name).endswith(".rels"):
            continue
        data = _read_part(zf, name, flags)
        if data is None:
            continue
        for rtype, target, external in _relationships(data):
            if rtype in _MACRO_RELS:
                _add(flags, "contains_macros")
            if rtype == "control":
                _add(flags, "contains_activex")
            if rtype in ("oleobject", "package"):
                # Embedded object or package, internal or external.
                _add(flags, "embedded_ole_object")
            if not external:
                continue
            if rtype in _LOADING_RELS:
                _add(flags, _LOADING_RELS[rtype])
            low = target.lower()
            # Opening a "\\\\host\\share" target also leaks the user's
            # Windows password hash to that host.
            href = "" if low.startswith(_RUNNING_TARGETS) else absolute_http(target)
            # Only web addresses go into the link list. "calc.exe" or
            # "..\\run.lnk" are flagged above and left out.
            path = not _SCHEME_RE.match(low) or _DRIVE_RE.match(low)
            if low.startswith(_RUNNING_TARGETS) or (
                not href and path and archives.entry_reasons(target.split("?")[0])
            ):
                _add(flags, "launch_external_action")
            if href:
                if href not in urls:
                    urls.append(href)
                continue
            _urls_from(target, urls)


def _content_type_flags(zf: zipfile.ZipFile, names: list[str], flags: list[str]) -> None:
    for name in names:
        if part_name(name) == "[content_types].xml":
            data = _read_part(zf, name, flags) or b""
            for pattern, flag in _CONTENT_TYPE_FLAGS:
                if pattern.search(data):
                    _add(flags, flag)
            return


# Ole10Native streams carry the file name of an OLE "Package" object. That
# is the "double-click to open" icon that hides a script in a document.
_PACKAGE_NAME_RE = re.compile(rb"([^\x00-\x1f\\/:*?\"<>|]{1,200}\.[A-Za-z0-9-]{1,20})\x00")


def _embedded_files(zf: zipfile.ZipFile, names: list[str], flags: list[str]) -> None:
    """Flag programs, scripts and shortcuts packed into embedded objects.

    They are one double-click away, so we treat them like archive members.
    """
    for name in names:
        # Check magic bytes, not names. "word/media/x.png" can be an OLE file.
        try:
            with zf.open(getattr(name, "info", name)) as fh:
                if fh.read(8) != OLE2_MAGIC:
                    continue
        except Exception:
            continue
        data = _read_part(zf, name, flags)
        if not data:
            continue
        for flag in _cfb_flags(data) or []:
            if flag != "encrypted_document":
                _add(flags, flag)
        if not set(cfb_names(data) or []) & _CFB_OBJECT and b"O\x00l\x00e\x001\x000" not in data:
            continue
        found = [m.decode("latin-1") for m in _PACKAGE_NAME_RE.findall(data[:2_000_000])]
        for flag in archives.classify_names(found):
            _add(flags, flag)


# Printable runs of 4 or more characters in a binary part, either
# single-byte or UTF-16 at any offset.
_UTF16_RUN_RE = re.compile(rb"(?:[\x20-\x7e\xa0-\xff][\x00]){4,}")
_BYTE_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")
# Parts that keep text outside the body (VML shapes, custom XML, document
# properties). We only scan element text for URLs. Attributes are skipped
# because namespace declarations are URLs too.
_HREF_ATTR_RE = re.compile(rb"""\bhref\s*=\s*["']([^"']{1,2048})["']""", re.IGNORECASE)


def _binary_strings(data: bytes) -> str:
    runs = [
        m.decode("utf-16-le", "ignore") for k in (0, 1) for m in _UTF16_RUN_RE.findall(data[k:])
    ]
    runs += [m.decode("latin-1") for m in _BYTE_RUN_RE.findall(data)]
    return "\n".join(runs)


def _other_parts(
    zf: zipfile.ZipFile, names: list[str], flags: list[str], urls: list[str], deadline: float
) -> str:
    """Read the parts that _text_parts skips.

    .xlsb workbooks are binary, so we pull printable runs out of them. VML
    drawings, custom XML and document properties are scanned for URLs
    only. The shared strings of an .xlsb are returned for the text model.
    """
    text: list[str] = []
    for name in names:
        if time.monotonic() > deadline:
            _add(flags, "document_not_fully_read")
            break
        n = part_name(name)
        if n.startswith("xl/") and n.endswith(".bin") and "vbaproject" not in n:
            data = _read_part(zf, name, flags)
            if not data or data.startswith(OLE2_MAGIC):
                continue
            strings = _binary_strings(data[:MAX_PART_BYTES])
            # Shared strings are cell text, not formulas.
            if "sharedstrings" not in n and (
                _DDE_FORMULA_RE.search(strings) or _LEGACY_DDE_RE.search(strings)
            ):
                _add(flags, "dde_field")
            _urls_from(strings, urls)
            if "sharedstrings" in n:
                text.append(strings)
        elif n.endswith((".vml", ".svg")):
            # Read drawing and SVG links here too. When the document sits
            # inside an archive, its members are never opened on their own.
            data = _read_part(zf, name, flags) or b""
            for m in _HREF_ATTR_RE.findall(data):
                href = absolute_http(m.decode("utf-8", "ignore"))
                if href and href not in urls:
                    urls.append(href)
        elif n.endswith(".xml") and n.startswith(("customxml/", "docprops/")):
            data = _read_part(zf, name, flags)
            if data:
                _urls_from(_text_from_xml(data, None, set()), urls)
    return without_invisible("\n".join(text))[:MAX_TEXT]


def _active_content(kind: str, name: str, data: bytes, flags: list[str], urls: list[str]) -> None:
    """Look for "Run program" actions, DDE fields and formulas, and link field URLs."""
    if _RUN_ACTION_RE.search(data):
        _add(flags, "launch_external_action")
    # A cheap substring test decides whether to parse. Element names can't
    # be escaped in XML, but "|" can be written as a character reference,
    # so that one is checked in both forms.
    if kind == "docx" and (b"instrText" in data or b"fldSimple" in data):
        codes = _field_codes(data)
        if _DDE_FIELD_RE.search(codes):
            _add(flags, "dde_field")
        _field_urls(codes, urls)
    elif kind == "xlsx":
        if part_name(name).startswith("xl/externallinks/") and b"ddeLink" in data:
            _add(flags, "dde_field")
        if _PIPE_RE.search(data) and _DDE_FORMULA_RE.search(
            _DOUBLE_QUOTED_RE.sub('""', _text_from_xml(data, {"f"}, {"f"}))
        ):
            _add(flags, "dde_field")


def analyse_ooxml(raw: bytes, filename: str) -> dict[str, Any]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise ValueError(
            "Unsupported or corrupt Office document: not a valid ZIP container."
        ) from e

    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError("Office document has too many parts to analyse safely.")
        if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED_TOTAL:
            raise ValueError(
                "Office document expands beyond the safe size limit (possible zip bomb)."
            )

        # Iterate over entries, not names. A ZIP can hold two parts with the
        # same name and opening by name only returns one of them.
        names = [_Part(i) for i in infos if not archives.is_dir(i.filename)]
        kind = detect_ooxml_kind(raw)
        if kind is None:
            raise ValueError(
                "Unsupported ZIP attachment: not a Word, Excel or PowerPoint document."
            )

        flags = _part_name_flags(names)
        # Office never puts programs, scripts or disk images in a package,
        # and never encrypts parts at the ZIP level.
        for flag in archives.classify_names(names):
            if flag not in flags:
                flags.append(flag)
        if any(i.flag_bits & 0x1 for i in infos) and "encrypted_document" not in flags:
            flags.append("encrypted_document")
        _content_type_flags(zf, names, flags)
        texts: list[str] = []
        urls: list[str] = []
        parts, text_tags, block_tags = _text_parts(kind, names)
        deadline = time.monotonic() + _READ_SECONDS
        for name in parts:
            if time.monotonic() > deadline:
                _add(flags, "document_not_fully_read")
                break
            data = _read_part(zf, name, flags)
            if data is None:
                continue
            # Text stops at MAX_TEXT but the active-content checks keep going.
            _active_content(kind, name, data, flags, urls)
            if sum(len(t) for t in texts) < MAX_TEXT:
                texts.append(without_invisible(_text_from_xml(data, text_tags, block_tags)))

        _scan_relationships(zf, names, flags, urls)
        texts.append(_other_parts(zf, names, flags, urls, deadline))
        _embedded_files(zf, names, flags)

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


# OLE2 (legacy .doc/.xls/.ppt, or an encrypted modern file)
def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


# "_VBA_PROJECT" is the stream every VBA project has (Word, Excel,
# PowerPoint); "Macros" is the Word 97-2003 storage that holds it.
def cfb_names(raw: bytes) -> list[str] | None:
    """Read storage and stream names from an OLE2 directory (MS-CFB).

    Names come back in lower case because the format ignores case. Returns
    None if the directory can't be read. The loop is bounded for any input.
    """
    if not raw.startswith(OLE2_MAGIC) or len(raw) < 512:
        return None
    shift = int.from_bytes(raw[30:32], "little")
    if shift not in (9, 12):
        return None
    size = 1 << shift
    per = size // 4

    def sector(n: int) -> bytes:
        return raw[(n + 1) * size : (n + 2) * size]

    def words(data: bytes) -> tuple[int, ...]:
        return struct.unpack_from(f"<{len(data) // 4}I", data)

    end = 0xFFFFFFFA
    difat = [d for d in words(raw[76:512]) if d < end]
    nxt, seen = int.from_bytes(raw[68:72], "little"), set()
    while nxt < end and nxt not in seen and len(seen) < 2000:
        seen.add(nxt)
        vals = words(sector(nxt))
        if len(vals) < per:
            break
        difat += [d for d in vals[:-1] if d < end]
        nxt = vals[-1]
    fat: list[int] = []
    # 512 FAT sectors map at least 32 MB, more than any attachment. A
    # sector listed twice is only read once.
    for d in list(dict.fromkeys(difat))[:512]:
        fat.extend(words(sector(d)))
    names: list[str] = []
    cur, visited = int.from_bytes(raw[48:52], "little"), set()
    while cur < end and cur not in visited and len(visited) < 20_000:
        visited.add(cur)
        data = sector(cur)
        if not data:
            break
        for k in range(0, len(data) - 127, 128):
            length = int.from_bytes(data[k + 64 : k + 66], "little")
            if 2 <= length <= 64 and data[k + 66] in (1, 2, 5):
                # Office stops at the first NUL whatever length the entry claims.
                name = data[k : k + length - 2].decode("utf-16-le", "replace")
                name = name.partition("\x00")[0].lower()
                if name:
                    names.append(name)
        cur = fat[cur] if cur < len(fat) else end
    # An empty result means we never found the directory.
    return names or None


# Lower-case directory names that indicate macros, encryption or an object.
_CFB_VBA = {"_vba_project", "vba", "macros", "_xlm"}
_CFB_ENCRYPTED = {"encryptedpackage", "encryptioninfo"}
_CFB_OBJECT = {"objectpool", "\x01ole10native", "ole10native"}


def _cfb_flags(raw: bytes) -> list[str] | None:
    names = cfb_names(raw)
    if names is None:
        return None
    have = set(names)
    flags = []
    if have & _CFB_ENCRYPTED:
        flags.append("encrypted_document")
    if have & _CFB_VBA:
        flags.append("contains_macros")
    if have & _CFB_OBJECT:
        flags.append("embedded_ole_object")
    return flags


_OLE_VBA_MARKERS = (_utf16("_VBA_PROJECT"), b"Attribute VB_Name")
_OLE_XLM_MARKERS = (_utf16("Macros"),)
_OLE_ENCRYPTED_MARKERS = (_utf16("EncryptedPackage"), _utf16("EncryptionInfo"))
_OLE_OBJECT_MARKERS = (_utf16("ObjectPool"), _utf16("Ole10Native"))


_LEGACY_DDE_RE = re.compile(r"\bDDEAUTO\b|\x13\s*DDE\b", re.IGNORECASE)


def analyse_ole(raw: bytes, filename: str) -> dict[str, Any]:
    if not raw.startswith(OLE2_MAGIC):
        raise ValueError("Unsupported or corrupt Office document: not an OLE2 file.")

    # Trust the directory first. Byte markers are the fallback when it
    # can't be read, except "Attribute VB_Name", which always counts.
    found = _cfb_flags(raw)
    if found is None:
        found = []
        if any(m in raw for m in _OLE_ENCRYPTED_MARKERS):
            found.append("encrypted_document")
        if any(m in raw for m in _OLE_VBA_MARKERS + _OLE_XLM_MARKERS):
            found.append("contains_macros")
        if any(m in raw for m in _OLE_OBJECT_MARKERS):
            found.append("embedded_ole_object")
    if b"Attribute VB_Name" in raw and "contains_macros" not in found:
        found.append("contains_macros")
    flags: list[str] = []
    if "encrypted_document" in found:
        # A password-protected .docx/.xlsx is stored as OLE2 too.
        flags.append("encrypted_document")
    else:
        flags.append("legacy_office_format")
    flags += [f for f in found if f != "encrypted_document"]
    if "embedded_ole_object" in flags:
        # Packaged file name, e.g. "invoice.pdf.js" behind an icon.
        found = [m.decode("latin-1") for m in _PACKAGE_NAME_RE.findall(raw[:5_000_000])]
        for flag in archives.classify_names(found):
            _add(flags, flag)

    # Binary formats store text as cp1252 or UTF-16LE runs, and a field
    # starts with U+0013. We only take URLs and DDE fields from them. The
    # text model would see too much noise.
    texts = [raw.decode("latin-1", errors="ignore")]
    # UTF-16 runs start at an even or an odd offset.
    texts += [raw[k:].decode("utf-16-le", errors="ignore") for k in (0, 1)]
    if any(_LEGACY_DDE_RE.search(t) for t in texts):
        flags.append("dde_field")
    # Scan run by run. On the whole file the NUL that ends a string would
    # be dropped as invisible and glue the URL to the next word
    # ("https://evil.tk" + NUL + "Click").
    urls: list[str] = []
    _urls_from(_binary_strings(raw), urls)

    return {
        "kind": "office_legacy",
        "filename": filename,
        "size_bytes": len(raw),
        "extracted_text": "",
        "extracted_text_chars": 0,
        "extracted_urls": urls[:MAX_URLS],
        "notable_features": flags,
    }
