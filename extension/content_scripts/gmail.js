// =====================================================================
// PhishLens content script: Gmail, start-up.
// =====================================================================
// Loaded last on Gmail: starts the page observers and reads the options.
// The functions they call live in gmail_scan.js, attachments.js and
// autoscan.js.
// =====================================================================

// ---------------------------------------------------------------------
// MutationObserver entry point
// ---------------------------------------------------------------------
const obs = new MutationObserver(() => { if (!pllShutdownIfDead()) scheduleScan(); });
PLL_OBSERVERS.push(obs);
if (PLL_IS_GMAIL) obs.observe(document.body, { childList: true, subtree: true });

// ---------------------------------------------------------------------
// Options and Gmail's "Show original"
// ---------------------------------------------------------------------
// The options set in the popup (PLL_OPTS, core.js), kept up to date.
chrome.storage?.local?.get(["opt_full_headers", "opt_auto_scan"], (s) => {
    PLL_OPTS.fullHeaders = s.opt_full_headers !== false;
    PLL_OPTS.autoScan = s.opt_auto_scan === true;
    if (PLL_OPTS.autoScan) scheduleAutoScan();
});
chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.opt_full_headers) PLL_OPTS.fullHeaders = changes.opt_full_headers.newValue !== false;
    if (changes.opt_auto_scan) {
        PLL_OPTS.autoScan = changes.opt_auto_scan.newValue === true;
        if (PLL_OPTS.autoScan) scheduleAutoScan();
    }
});
// A dedicated debounced observer for attachment tiles; they can
// appear AFTER the email opens (Gmail lazy-loads them) so we can't
// rely on the main injectIfNeeded() pass. Re-scans every open email
// view whenever the DOM settles.
let _attScanQueued = false;
const _attObs = new MutationObserver(() => {
    if (pllShutdownIfDead() || _attScanQueued) return;
    _attScanQueued = true;
    setTimeout(() => {
        _attScanQueued = false;
        document.querySelectorAll('div[role="main"]').forEach((view) => {
            try { installAttachmentButtons(view); } catch (e) {
                console.warn(TAG, "attachment scan failed:", e);
            }
        });
    }, 400);
});
PLL_OBSERVERS.push(_attObs);
if (PLL_IS_GMAIL) _attObs.observe(document.body, { childList: true, subtree: true });

// New mail and list redraws both mutate the DOM: piggy-back on them.
let _paintQueued = false;
const _autoObs = new MutationObserver(() => {
    if (pllShutdownIfDead()) return;
    if (PLL_OPTS.autoScan) scheduleAutoScan();
    if (_paintQueued) return;
    _paintQueued = true;
    setTimeout(() => { _paintQueued = false; paintAutoBadges(); }, 300);
});
PLL_OBSERVERS.push(_autoObs);
if (PLL_IS_GMAIL) _autoObs.observe(document.body, { childList: true, subtree: true });

if (PLL_IS_GMAIL) _autoCacheGet().then((c) => { _autoCacheMem = c; paintAutoBadges(); }).catch(() => {});
