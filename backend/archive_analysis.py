"""
PhishLens: archive and calendar-invite attachments.
=====================================================================
Archives are the classic way to get a payload past mail scanners:

  - a password-protected ZIP cannot be opened by Gmail's scanner, so the
    password is put in the email body ("password: 1234");
  - executables, scripts and shortcut files (.exe, .js, .lnk, ...) are
    blocked as direct attachments but slip through inside archives;
  - disk images (.iso, .img, .vhd) mount as a drive on double-click and
    bypass the "downloaded from the internet" warning;
  - double extensions ("invoice.pdf.exe") hide the real type.

ZIP archives are opened with the standard library (no extraction to
disk). RAR (rarfile) and 7z (py7zr) archives are listed
and opened the same way, with the same limits. Supported files inside
(PDF, HTML, Office, images, text) are analysed one level deep with the
same dispatcher as a direct attachment. Without those libraries, RAR
and 7z are recognised and reported as not inspectable.

Calendar invites (.ics) carry links in their description and location
fields and land in the calendar even when the email is ignored.

Standard library at import time (rarfile and py7zr are imported lazily):
safe to import anywhere.
"""

from __future__ import annotations

import io
import re
import tempfile
import unicodedata
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------
# Limits (zip-bomb and abuse protection)
# ---------------------------------------------------------------------
MAX_ENTRIES = 500  # entries listed
MAX_INNER_FILES = 5  # supported inner files analysed
MAX_INNER_BYTES = 5 * 1024 * 1024  # per inner file, uncompressed
MAX_TOTAL_INNER = 15 * 1024 * 1024  # all inner files together
MAX_RATIO = 100  # uncompressed / compressed

RAR_MAGIC = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"

EXECUTABLE_EXTS = {
    "exe",
    "scr",
    "com",
    "pif",
    "cpl",
    "dll",
    "msi",
    "msix",
    "msp",
    "appx",
    "jar",
    "apk",
    "app",
    "dmg",
    "pkg",
    "reg",
    "sys",
}
SCRIPT_EXTS = {
    "js",
    "jse",
    "vbs",
    "vbe",
    "wsf",
    "wsh",
    "wsc",
    "hta",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "sct",
    "vb",
    "scf",
    "inf",
    "chm",
}
SHORTCUT_EXTS = {"lnk", "url", "desktop", "website", "library-ms", "search-ms"}
DISK_IMAGE_EXTS = {"iso", "img", "vhd", "vhdx"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "arj", "ace", "xz", "bz2"}
DOCUMENT_EXTS = {
    "pdf",
    "doc",
    "docx",
    "docm",
    "xls",
    "xlsx",
    "xlsm",
    "ppt",
    "pptx",
    "pptm",
    "txt",
    "rtf",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "html",
    "htm",
    "csv",
}

# Types whose presence forces the phishing verdict (like Office macros).
DROPPER_FLAGS = {
    "executable_in_archive",
    "script_in_archive",
    "shortcut_in_archive",
    "double_extension",
}


# Characters that reorder how a name is shown: "invoice\u202efdp.exe" is
# displayed "invoiceexe.pdf".
_BIDI = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _base_name(name: str) -> str:
    """The file name as Windows reads it: the last part of the path ("/"
    or "\\"), in compatibility form, without trailing spaces and dots
    ("invoice.exe ." runs as .exe)."""
    base = unicodedata.normalize("NFKC", name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
    return base.rstrip(" .\t")


def _ext(name: str) -> str:
    """The extension Windows would run the file by, in lower case."""
    base = _base_name(name)
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _double_extension(name: str) -> bool:
    """invoice.pdf.exe, "scan.jpg   .js": a document extension followed
    by an executable, script or shortcut one."""
    parts = _base_name(name).lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-2].strip() in DOCUMENT_EXTS and parts[-1].strip() in (
        EXECUTABLE_EXTS | SCRIPT_EXTS | SHORTCUT_EXTS
    )


def classify_names(names: list[str]) -> list[str]:
    """Risk flags from a list of file names (archive entries)."""
    flags: list[str] = []

    def add(f: str) -> None:
        if f not in flags:
            flags.append(f)

    for n in names:
        e = _ext(n)
        if _double_extension(n) or _BIDI.intersection(n):
            add("double_extension")
        if e in EXECUTABLE_EXTS:
            add("executable_in_archive")
        elif e in SCRIPT_EXTS:
            add("script_in_archive")
        elif e in SHORTCUT_EXTS:
            add("shortcut_in_archive")
        elif e in DISK_IMAGE_EXTS:
            add("disk_image_in_archive")
        elif e in ARCHIVE_EXTS:
            add("nested_archive")
    return flags


# Plain-English reason for each risky name flag (per-file report).
NAME_REASONS = {
    "double_extension": "fake extension",
    "executable_in_archive": "program",
    "script_in_archive": "script",
    "shortcut_in_archive": "shortcut",
    "disk_image_in_archive": "disk image",
    "nested_archive": "archive inside the archive",
}


def entry_reasons(name: str) -> list[str]:
    """Why one archive member is risky, from its name alone."""
    return [NAME_REASONS[f] for f in classify_names([name]) if f in NAME_REASONS]


def is_rar_or_7z(raw: bytes) -> str | None:
    if raw.startswith(RAR_MAGIC):
        return "rar"
    if raw.startswith(SEVENZ_MAGIC):
        return "7z"
    return None


class _Entry:
    """One archive member, whatever the format."""

    __slots__ = ("name", "size", "packed", "is_dir")

    def __init__(self, name: str, size: int | None, packed: int | None, is_dir: bool):
        self.name, self.size, self.packed, self.is_dir = name, size, packed, is_dir


def _choose_inner(raw: bytes, entries: list[_Entry], add: Callable[[str], None]) -> list[str]:
    """Supported inner files within the size and ratio limits."""
    chosen: list[str] = []
    total = 0
    for e in entries:
        if len(chosen) >= MAX_INNER_FILES:
            break
        if e.is_dir or _ext(e.name) not in DOCUMENT_EXTS:
            continue
        if e.size is None:
            # No size in the listing: it cannot be checked before
            # extraction, so the file is not extracted.
            add("inner_files_not_extracted")
            continue
        size = e.size
        if size > MAX_INNER_BYTES or total + size > MAX_TOTAL_INNER:
            add("oversized_inner_file")
            continue
        # Ratio per member when the format gives it, else against the
        # whole archive (solid 7z / RAR blocks have no per-file size).
        packed = e.packed if e.packed else len(raw)
        if size / max(packed, 1) > MAX_RATIO:
            add("zip_bomb_suspected")
            continue
        chosen.append(e.name)
        total += size
    return chosen


def _inner_result(inner, data: bytes, name: str) -> dict[str, Any] | None:
    try:
        return inner(data[:MAX_INNER_BYTES], name)
    except (ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
        return None


def _inner_entry(name: str, res: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": name,
        "kind": res.get("kind"),
        "notable_features": res.get("notable_features", []),
        "url_count": len(res.get("extracted_urls", []) or []),
        # Private, for the per-file report; removed by the endpoint before
        # the response is sent.
        "_text": (res.get("extracted_text") or "")[:4000],
        "_urls": list(res.get("extracted_urls", []) or [])[:50],
    }


def _analyse_listing(
    raw: bytes,
    filename: str,
    fmt: str,
    entries: list[_Entry],
    encrypted: bool,
    read: Callable[[list[str]], dict[str, bytes]] | None,
    inner: Callable[[bytes, str], dict[str, Any]] | None,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Shared by ZIP, RAR and 7z: flag risky names, pick the supported
    inner files within the size limits, read them through `read(names)`
    (format specific) and analyse them with `inner`."""
    names = [e.name for e in entries if not e.is_dir]
    flags = list(flags or [])

    def add(f: str) -> None:
        if f not in flags:
            flags.append(f)

    for f in classify_names(names):
        add(f)
    if encrypted:
        add("encrypted_archive")

    chosen = _choose_inner(raw, entries, add) if inner and read and not encrypted else []
    texts: list[str] = []
    urls: list[str] = []
    inner_results: list[dict[str, Any]] = []
    if chosen:
        try:
            data_by_name = read(chosen)
        except _NotExtracted:
            data_by_name = {}
            add("inner_files_not_extracted")
        for name in chosen:
            data = data_by_name.get(name)
            res = _inner_result(inner, data, name) if data is not None else None
            if res is None:
                continue
            inner_results.append(_inner_entry(name, res))
            if res.get("extracted_text"):
                texts.append(res["extracted_text"])
            urls.extend(
                dict.fromkeys(u for u in res.get("extracted_urls", []) or [] if u not in urls)
            )
            for f in res.get("notable_features", []) or []:
                add(f)

    text = "\n".join(texts)
    return {
        "kind": "archive",
        "filename": filename,
        "size_bytes": len(raw),
        "archive_format": fmt,
        "entries": names[:50],
        "entry_count": len(names),
        "encrypted": encrypted,
        "inner_files": inner_results,
        "extracted_text": text,
        "extracted_text_chars": len(text),
        "extracted_urls": urls,
        "notable_features": flags,
    }


class _NotExtracted(Exception):
    """The listing worked but the members cannot be decompressed here."""


def _encrypted_unlisted(raw: bytes, filename: str, fmt: str) -> dict[str, Any]:
    """Archive whose file list itself is encrypted (rar -hp, 7z -mhe)."""
    r = _analyse_listing(raw, filename, fmt, [], True, None, None)
    r["entry_count"] = None
    return r


def _looks_like_password_error(e: Exception) -> bool:
    text = (type(e).__name__ + " " + str(e)).lower()
    return "password" in text or "encrypt" in text


def analyse_zip(
    raw: bytes, filename: str, inner: Callable[[bytes, str], dict[str, Any]] | None = None
) -> dict[str, Any]:
    """List a ZIP archive, flag risky content, analyse supported files.

    `inner(raw, name)` analyses one inner file (the attachment dispatcher,
    called with depth + 1); it may raise ValueError for unsupported types.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        infos = zf.infolist()[:MAX_ENTRIES]
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"ZIP parse failed: {e}") from e

    entries = [_Entry(i.filename, i.file_size, i.compress_size, i.is_dir()) for i in infos]
    encrypted = any(i.flag_bits & 0x1 for i in infos)

    def read(names: list[str]) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for n in names:
            try:
                # Bounded read: never more than the limit is decompressed,
                # whatever size the archive declares.
                with zf.open(n) as fh:
                    out[n] = fh.read(MAX_INNER_BYTES)
            except (zipfile.BadZipFile, NotImplementedError, RuntimeError, KeyError):
                continue
        return out

    return _analyse_listing(raw, filename, "zip", entries, encrypted, read, inner)


def analyse_7z(
    raw: bytes, filename: str, inner: Callable[[bytes, str], dict[str, Any]] | None = None
) -> dict[str, Any]:
    """7z, with py7zr. Only the chosen supported files (size-checked
    first) are extracted, in memory."""
    try:
        import py7zr
    except ImportError:
        return analyse_uninspectable_archive(raw, filename, "7z")
    try:
        szf = py7zr.SevenZipFile(io.BytesIO(raw), mode="r")
    except Exception as e:  # PasswordRequired (encrypted header), Bad7zFile...
        if _looks_like_password_error(e):
            return _encrypted_unlisted(raw, filename, "7z")
        return analyse_uninspectable_archive(raw, filename, "7z")

    with szf:
        try:
            infos = szf.list()[:MAX_ENTRIES]
            encrypted = bool(szf.needs_password())
        except Exception as e:
            if _looks_like_password_error(e):
                return _encrypted_unlisted(raw, filename, "7z")
            return analyse_uninspectable_archive(raw, filename, "7z")
        entries = [
            _Entry(
                i.filename,
                getattr(i, "uncompressed", None),
                getattr(i, "compressed", None),
                bool(getattr(i, "is_directory", False)),
            )
            for i in infos
        ]

        def read(names: list[str]) -> dict[str, bytes]:
            # In memory, each member cut at MAX_INNER_BYTES whatever size
            # the listing declared: nothing is written to disk.
            from py7zr.io import BytesIOFactory

            factory = BytesIOFactory(MAX_INNER_BYTES)
            try:
                szf.reset()
                szf.extract(targets=names, factory=factory)
            except Exception as e:
                raise _NotExtracted(str(e)) from e
            out: dict[str, bytes] = {}
            for n in names:
                product = factory.products.get(n)
                if product is not None:
                    product.seek(0)
                    out[n] = product.read(MAX_INNER_BYTES)
            return out

        return _analyse_listing(raw, filename, "7z", entries, encrypted, read, inner)


def analyse_rar(
    raw: bytes, filename: str, inner: Callable[[bytes, str], dict[str, Any]] | None = None
) -> dict[str, Any]:
    """RAR 4 and 5, with rarfile. The listing (names, sizes,
    encryption) is pure Python; decompressing members needs an external
    tool (unrar, unar, 7z or bsdtar; the Docker image ships bsdtar). Without
    one, stored members are still read and the rest is reported as
    "inner_files_not_extracted"."""
    try:
        import rarfile
    except ImportError:
        return analyse_uninspectable_archive(raw, filename, "rar")

    with tempfile.TemporaryDirectory(prefix="plrar-") as tmp:
        path = Path(tmp) / "a.rar"
        path.write_bytes(raw)
        try:
            rf = rarfile.RarFile(str(path), errors="strict")
            infos = rf.infolist()[:MAX_ENTRIES]
            encrypted = bool(rf.needs_password())
        except Exception as e:  # PasswordRequired, NeedFirstVolume, BadRarFile...
            if _looks_like_password_error(e):
                return _encrypted_unlisted(raw, filename, "rar")
            return analyse_uninspectable_archive(raw, filename, "rar")
        if not infos and not encrypted:
            # Nothing listed: truncated or damaged headers.
            return analyse_uninspectable_archive(raw, filename, "rar")

        entries = [
            _Entry(i.filename, i.file_size, getattr(i, "compress_size", None), i.is_dir())
            for i in infos
        ]

        def read(names: list[str]) -> dict[str, bytes]:
            out: dict[str, bytes] = {}
            missing_tool = False
            for n in names:
                try:
                    with rf.open(n) as fh:
                        out[n] = fh.read(MAX_INNER_BYTES)
                except Exception as e:
                    if type(e).__name__ in ("RarCannotExec", "RarExecError"):
                        missing_tool = True
                    continue
            if missing_tool and not out:
                raise _NotExtracted("no RAR decompression tool")
            return out

        with rf:
            return _analyse_listing(raw, filename, "rar", entries, encrypted, read, inner)


def analyse_uninspectable_archive(raw: bytes, filename: str, fmt: str) -> dict[str, Any]:
    """RAR / 7z the server cannot open (library missing, multi-volume or
    damaged archive): recognised, reported as not inspectable."""
    return {
        "kind": "archive",
        "filename": filename,
        "size_bytes": len(raw),
        "archive_format": fmt,
        "entries": [],
        "entry_count": None,
        "encrypted": None,
        "inner_files": [],
        "extracted_text": "",
        "extracted_text_chars": 0,
        "extracted_urls": [],
        "notable_features": ["uninspectable_archive"],
    }


# ---------------------------------------------------------------------
# Calendar invites (.ics)
# ---------------------------------------------------------------------
def _strip_tags(html: str) -> str:
    """Drop <...> tags without a regex (linear, safe on crafted input)."""
    out = []
    for i, chunk in enumerate(html[:20_000].split("<")):
        if i == 0:
            out.append(chunk)
        else:
            _tag, sep, rest = chunk.partition(">")
            out.append(" " + rest if sep else "")
    return "".join(out)


_ICS_FIELDS = ("SUMMARY", "DESCRIPTION", "LOCATION", "URL", "ATTACH", "ORGANIZER", "X-ALT-DESC")


def analyse_ics(
    raw: bytes, filename: str, extract_urls: Callable[[str], list[str]]
) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="ignore")
    # RFC 5545 line unfolding: a line starting with a space continues the previous one.
    text = re.sub(r"\r?\n[ \t]", "", text)
    kept: list[str] = []
    organizer = None
    for line in text.splitlines():
        key = line.split(":", 1)[0].split(";", 1)[0].upper()
        if key in _ICS_FIELDS and ":" in line:
            value = line.split(":", 1)[1]
            value = value.replace("\\n", "\n").replace("\\,", ",").replace("\\;", ";")
            if key == "ORGANIZER":
                organizer = value.replace("mailto:", "").replace("MAILTO:", "").strip()
                continue
            if key == "X-ALT-DESC":
                value = _strip_tags(value)
            kept.append(value)
    body = "\n".join(kept)[:20_000]
    urls = extract_urls(body)
    flags = ["calendar_invite"]
    if urls:
        flags.append("calendar_with_links")
    return {
        "kind": "calendar",
        "filename": filename,
        "size_bytes": len(raw),
        "organizer": organizer,
        "extracted_text": body,
        "extracted_text_chars": len(body),
        "extracted_urls": urls,
        "notable_features": flags,
    }
