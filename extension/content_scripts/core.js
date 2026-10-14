// =====================================================================
// PhishLens content script: shared core (Gmail and Outlook).
// =====================================================================
// Loaded first, after lib/: names, icons, theme, Gmail selectors and
// small helpers used by every other content script. Content scripts of
// one entry share a scope, so these top-level names are visible to the
// files loaded after this one (see the manifest).
// =====================================================================

const TAG = "[PhishLens]";
const { escapeHTML } = PhishLensShared;      // lib/shared.js, loaded first
// This file is also loaded on Outlook for its banner code; the
// Gmail-specific watchers only run on Gmail.
const PLL_IS_GMAIL = location.hostname === "mail.google.com";
// After an extension update or reload, the previous copy of this script
// stays in open tabs, cut off from the extension ("context invalidated").
// Each copy tags the buttons it creates; a newer copy replaces older ones,
// so users do not have to refresh Gmail after an update.
const PLL_INSTANCE = Math.random().toString(36).slice(2, 10);
// False once this copy has been cut off from the extension; it then
// stops touching the page and leaves it to the new copy.
function pllAlive() {
    try { return !!chrome.runtime?.id; } catch { return false; }
}
// Every observer of this copy, so a disconnected copy can stop them all.
const PLL_OBSERVERS = [];
function pllShutdownIfDead() {
    if (pllAlive()) return false;
    PLL_OBSERVERS.forEach((o) => o.disconnect());
    PLL_OBSERVERS.length = 0;
    return true;
}
// A call to chrome.* from a disconnected copy throws "Extension context
// invalidated"; those are expected after an update and not worth a red
// entry on the extensions page.
window.addEventListener("unhandledrejection", (ev) => {
    if (/Extension context invalidated/i.test(String(ev.reason?.message || ev.reason))) ev.preventDefault();
});

// Inline SVG icons (no emoji: they render differently on every OS).
const PLL_ICON = {
    shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"/></svg>',
    shieldCheck: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
    clip: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 11l-8.6 8.6a5 5 0 01-7-7L14 4a3.5 3.5 0 015 5l-8.6 8.6a2 2 0 01-2.8-2.8L15 7.5"/></svg>',
    close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    spinner: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a9 9 0 109 9"/></svg>',
};

// ---------------------------------------------------------------------
// Theme: read the popup's saved choice and apply to injected UI.
// The popup writes to chrome.storage.local under key "theme".
// ---------------------------------------------------------------------
function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
        document.documentElement.setAttribute("data-phishlens-theme", theme);
    } else {
        document.documentElement.removeAttribute("data-phishlens-theme");
    }
}
chrome.storage?.local?.get(["theme"], (s) => applyTheme(s.theme));
chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area === "local" && changes.theme) applyTheme(changes.theme.newValue);
});

// ---------------------------------------------------------------------
// Detection: which DOM nodes mean "an email view is open"?
// ---------------------------------------------------------------------
// Gmail wraps each open email view in <h2 class="hP">Subject text</h2>.
// We watch for those.
const SUBJECT_SEL  = "h2.hP";
const BODY_SEL     = ".a3s.aiL";          // the message body container
const SENDER_SEL   = ".gD[email]";        // <span class="gD" email="...">Name</span>
const HEADER_BAR   = ".aeF";              // bar at the top of the email view

const PROCESSED = new WeakSet();

// Options set in the popup (Settings): full headers on by default,
// automatic scanning of new emails off by default (it sends emails to
// the backend without a click, so it is opt-in). Kept up to date by gmail.js.
const PLL_OPTS = { fullHeaders: true, autoScan: false };

function setBtnLoading(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("pll-scan-btn--loading", on);
    btn.querySelector(".pll-scan-btn__icon").innerHTML = on ? PLL_ICON.spinner : PLL_ICON.shield;
    btn.querySelector(".pll-scan-btn__label").textContent =
        on ? "Scanning…" : "Scan again";
}

// ---------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------
function textOf(el) {
    if (!el) return "";
    return el.innerText.replace(/\s+\n/g, "\n").trim();
}
function utf8ToB64(text) {
    const bytes = new TextEncoder().encode(text);
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
}

// http(s) targets of the links in the message body, deduplicated, max 50.
function linkTargetsOf(el) {
    if (!el) return [];
    const out = new Set();
    for (const a of el.querySelectorAll("a[href]")) {
        const href = a.href || "";
        if (/^https?:\/\//i.test(href) && href.length <= 2048) out.add(href);
        if (out.size >= 50) break;
    }
    return [...out];
}
function pct(p) { return p == null ? "n/a" : Math.round(p * 100); }

// Deterministic short id from the filename so the same attachment
// updates its own banner instead of appending duplicates on re-scan.
function _fileKey(name) {
    return String(name || "").replace(/[^a-z0-9]+/gi, "-").slice(0, 60).toLowerCase();
}

// Fast base64 encoding of a raw ArrayBuffer without blowing the stack
// on large files.
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunk = 0x8000;
    let binary = "";
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}
