// =====================================================================
// PhishLens — client-side LIME cache.
// =====================================================================
// LIME on the backend runs 100 model forward passes per /explain — that's
// ~8-15 seconds on the CPU-only Oracle VM. If you re-open the same email
// (or two users at the same org scan the same phishing template), the
// server does the same expensive work again.
//
// This module caches /explain responses in chrome.storage.local keyed by
// {backend_url, sha256(payload)}. A hit returns instantly; a miss falls
// through to the network as before, then writes the result back.
//
// Storage: one key `limeCache` -> { [key]: {features, ts} }.
// Cap: LRU by timestamp. Bytes stay well under the 5 MB chrome.storage cap.
//
// This whole file is wrapped in an IIFE so that internals (constants,
// helpers) don't leak to the global scope — popup.html loads history.js
// alongside us as classic <script>, and both defined _get/_set/etc.
// The only symbol we export is window.PhishLensLimeCache.
// =====================================================================
(function () {
"use strict";

const CACHE_KEY   = "limeCache";
const MAX_ENTRIES = 200;
const TTL_MS      = 30 * 24 * 3600 * 1000;    // 30 days

// ---------------------------------------------------------------------
// Payload hash — SHA-256 over a canonical representation of the input.
// The backend uses the same body text for /analyse and /explain, so
// keying on the payload gets us cache hits across re-opens of the same
// email even without a stable email id.
// ---------------------------------------------------------------------
async function hashPayload(backendBase, payload) {
    // Only the fields that actually influence the LIME output matter.
    // sender_email doesn't touch the text agent, so we ignore it.
    const canon = JSON.stringify({
        b: (backendBase || "").replace(/\/$/, ""),
        t: payload.raw_text || null,
        e: payload.raw_email_b64 || null,
    });
    const buf = new TextEncoder().encode(canon);
    const digest = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

// ---------------------------------------------------------------------
// chrome.storage helpers
// ---------------------------------------------------------------------
function _get() {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.get([CACHE_KEY], (s) => resolve(s[CACHE_KEY] || {}));
        } catch { resolve({}); }
    });
}
function _set(obj) {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.set({ [CACHE_KEY]: obj }, resolve);
        } catch { resolve(); }
    });
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------
async function get(backendBase, payload) {
    try {
        const key = await hashPayload(backendBase, payload);
        const store = await _get();
        const entry = store[key];
        if (!entry) return null;
        if (Date.now() - entry.ts > TTL_MS) return null;
        return { features: entry.features, cached: true };
    } catch {
        return null;
    }
}

async function put(backendBase, payload, features) {
    if (!Array.isArray(features) || !features.length) return;
    try {
        const key = await hashPayload(backendBase, payload);
        const store = await _get();
        store[key] = { features, ts: Date.now() };
        // LRU eviction — sort by ts asc, keep last MAX_ENTRIES.
        const entries = Object.entries(store).sort((a, b) => a[1].ts - b[1].ts);
        while (entries.length > MAX_ENTRIES) {
            const [k] = entries.shift();
            delete store[k];
        }
        await _set(store);
    } catch {}
}

async function clear() {
    await _set({});
}

async function stats() {
    const store = await _get();
    return { entries: Object.keys(store).length };
}

// ---------------------------------------------------------------------
// Export — works in popup, content scripts, service worker.
// ---------------------------------------------------------------------
const PhishLensLimeCache = { get, put, clear, stats, hashPayload };

if (typeof globalThis !== "undefined") globalThis.PhishLensLimeCache = PhishLensLimeCache;
if (typeof window     !== "undefined") window.PhishLensLimeCache     = PhishLensLimeCache;
if (typeof self       !== "undefined") self.PhishLensLimeCache       = PhishLensLimeCache;

if (typeof module !== "undefined" && module.exports) module.exports = PhishLensLimeCache;
})();
