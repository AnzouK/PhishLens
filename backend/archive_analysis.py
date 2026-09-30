"""
PhishLens: archive and calendar-invite attachments (v1.14).
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
disk). Supported files inside (PDF, HTML, Office, images, text) are
analysed one level deep with the same dispatcher as a direct attachment.
RAR and 7z need extra native libraries, so they are only recognised and
reported as not inspectable.

Calendar invites (.ics) carry links in their description and location
fields and land in the calendar even when the email is ignored.

Pure standard library: safe to import anywhere.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any, Callable

# ---------------------------------------------------------------------
# Limits (zip-bomb and abuse protection)
# ---------------------------------------------------------------------
MAX_ENTRIES          = 500                 # entries listed
MAX_INNER_FILES      = 5                   # supported inner files analysed
MAX_INNER_BYTES      = 5 * 1024 * 1024     # per inner file, uncompressed
MAX_TOTAL_INNER      = 15 * 1024 * 1024    # all inner files together
MAX_RATIO            = 100                 # uncompressed / compressed

RAR_MAGIC = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"

EXECUTABLE_EXTS = {
    "exe", "scr", "com", "pif", "cpl", "dll", "msi", "msix", "msp", "appx",
    "jar", "apk", "app", "dmg", "pkg", "reg", "sys",
}
SCRIPT_EXTS = {
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "hta", "bat", "cmd",
    "ps1", "psm1", "sct", "vb", "scf", "inf", "chm",
}
SHORTCUT_EXTS = {"lnk", "url", "desktop", "website", "library-ms", "search-ms"}
DISK_IMAGE_EXTS = {"iso", "img", "vhd", "vhdx"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "arj", "ace", "xz", "bz2"}
DOCUMENT_EXTS = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
                 "pptm", "txt", "rtf", "jpg", "jpeg", "png", "gif", "html", "htm", "csv"}

# Types whose presence forces the phishing verdict (like Office macros).
DROPPER_FLAGS = {"executable_in_archive", "script_in_archive",
                 "shortcut_in_archive", "double_extension"}


def _ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def _double_extension(name: str) -> bool:
    """invoice.pdf.exe, "scan.jpg   .js": a document extension followed
    by an executable, script or shortcut one."""
    parts = name.rsplit("/", 1)[-1].lower().split(".")
    if len(parts) < 3:
        return False
    return parts[-2].strip() in DOCUMENT_EXTS and parts[-1].strip() in (
        EXECUTABLE_EXTS | SCRIPT_EXTS | SHORTCUT_EXTS)


def classify_names(names: list[str]) -> list[str]:
    """Risk flags from a list of file names (archive entries)."""
    flags: list[str] = []

    def add(f: str) -> None:
        if f not in flags:
            flags.append(f)

    for n in names:
        e = _ext(n)
        if _double_extension(n):
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


def is_rar_or_7z(raw: bytes) -> str | None:
    if raw.startswith(RAR_MAGIC):
        return "rar"
    if raw.startswith(SEVENZ_MAGIC):
        return "7z"
    return None


def analyse_zip(raw: bytes, filename: str,
                inner: Callable[[bytes, str], dict[str, Any]] | None = None) -> dict[str, Any]:
    """List a ZIP archive, flag risky content, analyse supported files.

    `inner(raw, name)` analyses one inner file (the attachment dispatcher,
    called with depth + 1); it may raise ValueError for unsupported types.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        infos = zf.infolist()[:MAX_ENTRIES]
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"ZIP parse failed: {e}")

    names = [i.filename for i in infos if not i.is_dir()]
    flags = classify_names(names)
    encrypted = any(i.flag_bits & 0x1 for i in infos)
    if encrypted:
        flags.append("encrypted_archive")

    texts: list[str] = []
    urls: list[str] = []
    inner_results: list[dict[str, Any]] = []
    total = 0
    if inner and not encrypted:
        for i in infos:
            if len(inner_results) >= MAX_INNER_FILES:
                break
            if i.is_dir() or _ext(i.filename) not in DOCUMENT_EXTS:
                continue
            if i.file_size > MAX_INNER_BYTES or total + i.file_size > MAX_TOTAL_INNER:
                if "oversized_inner_file" not in flags:
                    flags.append("oversized_inner_file")
                continue
            if i.compress_size and i.file_size / max(i.compress_size, 1) > MAX_RATIO:
                if "zip_bomb_suspected" not in flags:
                    flags.append("zip_bomb_suspected")
                continue
            try:
                data = zf.read(i)[:MAX_INNER_BYTES]
                total += len(data)
                res = inner(data, i.filename)
            except (ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                continue
            inner_results.append({
                "filename": i.filename,
                "kind": res.get("kind"),
                "notable_features": res.get("notable_features", []),
            })
            if res.get("extracted_text"):
                texts.append(res["extracted_text"])
            for u in res.get("extracted_urls", []) or []:
                if u not in urls:
                    urls.append(u)
            for f in res.get("notable_features", []) or []:
                if f not in flags:
                    flags.append(f)

    text = "\n".join(texts)
    return {
        "kind":              "archive",
        "filename":          filename,
        "size_bytes":        len(raw),
        "archive_format":    "zip",
        "entries":           names[:50],
        "entry_count":       len(names),
        "encrypted":         encrypted,
        "inner_files":       inner_results,
        "extracted_text":    text,
        "extracted_text_chars": len(text),
        "extracted_urls":    urls,
        "notable_features":  flags,
    }


def analyse_uninspectable_archive(raw: bytes, filename: str, fmt: str) -> dict[str, Any]:
    """RAR / 7z: recognised, not opened (needs native libraries)."""
    return {
        "kind":              "archive",
        "filename":          filename,
        "size_bytes":        len(raw),
        "archive_format":    fmt,
        "entries":           [],
        "entry_count":       None,
        "encrypted":         None,
        "inner_files":       [],
        "extracted_text":    "",
        "extracted_text_chars": 0,
        "extracted_urls":    [],
        "notable_features":  ["uninspectable_archive"],
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


def analyse_ics(raw: bytes, filename: str, extract_urls: Callable[[str], list[str]]) -> dict[str, Any]:
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
        "kind":              "calendar",
        "filename":          filename,
        "size_bytes":        len(raw),
        "organizer":         organizer,
        "extracted_text":    body,
        "extracted_text_chars": len(body),
        "extracted_urls":    urls,
        "notable_features":  flags,
    }
