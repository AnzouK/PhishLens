// Values the popup, the content scripts and the service worker must agree on.
(function () {
"use strict";

// Files sent to /analyse_attachment. An .eml goes to /analyse instead.
const ATTACHMENT_EXTS = Object.freeze([
    "pdf", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff",
    "docx", "docm", "doc", "xlsx", "xlsm", "xls", "pptx", "pptm", "ppt",
    "zip", "rar", "7z", "ics", "txt",
]);

// Files that run or mount when opened (programs, scripts, shortcuts, disk
// images): nothing to read, the server flags them by type. Same list as
// backend/archive_analysis.py (EXECUTABLE, SCRIPT, SHORTCUT, DISK_IMAGE).
const DANGEROUS_EXTS = Object.freeze((
    "apk app appx bat chm cmd com cpl desktop dll dmg exe hta img inf iso jar js jse library-ms lnk " +
    "msi msix msp pif pkg ps1 psm1 reg scf scr sct search-ms sys url vb vbe vbs vhd vhdx website wsc wsf wsh"
).split(" "));

// Attachment flags meaning "PhishLens could not look inside": a low score
// is not reassuring, so these get a caution verdict instead of "safe".
const CAUTION_FLAGS = Object.freeze([
    "encrypted_archive", "encrypted_document", "uninspectable_archive",
    "disk_image_attachment", "disk_image_in_archive", "zip_bomb_suspected", "inner_files_not_extracted",
]);

const MAX_FILE_MB = 10;

// Threat-intel sources as the server names them, and their display names.
const SOURCE_LABELS = Object.freeze({
    google_safe_browsing: "Google Safe Browsing",
    phishtank: "PhishTank",
    urlhaus: "URLhaus",
    spamhaus_dbl: "Spamhaus DBL",
});

// The extension a system would open the file by: compatibility form,
// trailing dots and spaces dropped ("invoice.exe ." is an .exe).
function fileExt(name) {
    const parts = String(name || "").normalize("NFKC").replace(/[.\s]+$/, "").split(".");
    return parts.length > 1 ? parts.pop().toLowerCase() : "";
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
