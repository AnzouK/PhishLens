// Values the popup, the content scripts and the service worker must agree on.
(function () {
"use strict";

// Files sent to /analyse_attachment. An .eml goes to /analyse instead.
const ATTACHMENT_EXTS = Object.freeze([
    "pdf", "html", "htm", "xhtml", "shtml", "svg", "svgz", "mht", "mhtml",
    "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff",
    "docx", "docm", "doc", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xls", "xltx", "xltm",
    "pptx", "pptm", "ppt", "potx", "potm", "ppsx", "ppsm",
    "zip", "rar", "7z", "ics", "txt",
]);

// Files that run or mount when opened (programs, scripts, shortcuts, disk
// images). There is nothing to read, so the server flags them by type.
// Same list as backend/archive_analysis.py (EXECUTABLE, SCRIPT, SHORTCUT,
// DISK_IMAGE).
const DANGEROUS_EXTS = Object.freeze((
    "apk app appinstaller application appx appxbundle bat chm cmd com command cpl desktop diagcab " +
    "dll dmg drv exe gadget hta img inetloc inf iso jar jnlp js jse library-ms lnk msc msh mshxml " +
    "msi msix msixbundle msp msu ocx pif pkg ppam ps1 psc1 psm1 reg scf scr sct search-ms " +
    "settingcontent-ms sys udf udl url vb vbe vbs vhd vhdx webloc website ws wsb wsc wsf wsh xbap " +
    "xlam xll"
).split(" "));

// Attachment flags meaning PhishLens could not look inside. A low score
// is then not reassuring, so these get a caution verdict instead of
// "safe".
const CAUTION_FLAGS = Object.freeze([
    "encrypted_archive", "encrypted_document", "uninspectable_archive",
    "disk_image_attachment", "disk_image_in_archive", "zip_bomb_suspected", "inner_files_not_extracted",
    "document_not_fully_read",
]);

const MAX_FILE_MB = 10;

// Threat-intel sources as the server names them, and their display names.
const SOURCE_LABELS = Object.freeze({
    google_safe_browsing: "Google Safe Browsing",
    phishtank: "PhishTank",
    urlhaus: "URLhaus",
    spamhaus_dbl: "Spamhaus DBL",
});

// eslint-disable-next-line no-undef
const { withoutInvisible } = globalThis.PhishLensShared || require("./shared.js");

// The extension a system would use to open the file. The name is put in
// compatibility form, invisible characters are removed, ideographic full
// stops count as dots, only the last part of the path is kept, and
// trailing dots and white space of any kind are dropped. So "invoice.exe .",
// "invoice.exe\r" and "invoice.pdf.exe" followed by a zero-width space are
// all .exe files. Same as backend/archive_analysis._ext
// (tests/fixtures/file_name_cases.json).
function fileExt(name) {
    const norm = withoutInvisible(String(name || "").normalize("NFKC")).replace(/[\u3002\uff61\ufe52]/g, ".");
    const base = norm.split(/[/\\]/).pop().replace(/[.\s]+$/u, "");
    const parts = base.split(".");
    return parts.length > 1 ? parts.pop().trim().toLowerCase() : "";
}

function isCaution(flags) {
    return (flags || []).some((f) => CAUTION_FLAGS.includes(f));
}

const PhishLensConstants = Object.freeze({
    ATTACHMENT_EXTS, CAUTION_FLAGS, DANGEROUS_EXTS, MAX_FILE_MB, SOURCE_LABELS, fileExt, isCaution,
});
globalThis.PhishLensConstants = PhishLensConstants;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensConstants;
})();
