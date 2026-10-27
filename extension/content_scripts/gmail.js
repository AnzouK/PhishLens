// Last Gmail content script: reads the options and starts the page
// watchers. The work itself is in gmail_scan.js, attachments.js and
// autoscan.js.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
if (!PL.isGmail) return;
const { debug } = PhishLensShared;

chrome.storage?.local?.get(["opt_full_headers", "opt_auto_scan"], (s) => {
    PL.opts.fullHeaders = s.opt_full_headers !== false;
    PL.opts.autoScan = s.opt_auto_scan === true;
    if (PL.opts.autoScan) PL.scheduleAutoScan();
});
chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.opt_full_headers) PL.opts.fullHeaders = changes.opt_full_headers.newValue !== false;
    if (changes.opt_auto_scan) {
        PL.opts.autoScan = changes.opt_auto_scan.newValue === true;
        if (PL.opts.autoScan) PL.scheduleAutoScan();
    }
});

// Each watcher waits for the page to settle before doing its work.
function debounced(ms, fn) {
    let queued = false;
    return () => {
        if (queued) return;
        queued = true;
        setTimeout(() => { queued = false; fn(); }, ms);
    };
}

// An open email gets its scan button.
PL.observe(() => {
    if (PL.shutdownIfDead()) return;
    PL.refreshTheme();
    PL.scheduleScan();
});

// Attachment tiles can appear after the email opens (Gmail lazy-loads them).
const scanAttachments = debounced(400, () => {
    document.querySelectorAll('div[role="main"]').forEach((view) => {
        try {
            PL.installAttachmentButtons(view);
        } catch (e) {
            console.warn(PL.TAG, "attachment buttons failed:", e);
        }
    });
});
PL.observe(() => { if (!PL.shutdownIfDead()) scanAttachments(); });

// New mail and list redraws: automatic scan and the row pills.
const paintBadges = debounced(300, () => PL.paintAutoBadges());
PL.observe(() => {
    if (PL.shutdownIfDead()) return;
    if (PL.opts.autoScan) PL.scheduleAutoScan();
    paintBadges();
});

PL.loadAutoCache().catch((e) => debug("automatic scan cache", e));
})();
