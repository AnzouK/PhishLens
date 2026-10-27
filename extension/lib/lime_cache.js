// Local cache of /explain answers. LIME runs the text model about a
// hundred times per explanation (seconds on the server), so re-opening
// the same email reuses the first answer. Used by the service worker.
//
// "limeCache.v2" in chrome.storage.local: { [sha256(server, text)]: { features, ts } },
// at most MAX_ENTRIES, each kept TTL_MS. The version changes with the
// text model, so explanations of an older model are not reused.
(function () {
"use strict";

const CACHE_KEY = "limeCache.v2";
const MAX_ENTRIES = 200;
const TTL_MS = 30 * 24 * 3600 * 1000;

// Only what changes the explanation: the server and the text (the
// sender, for one, does not reach the text model).
async function hashPayload(backendBase, payload) {
    const canon = JSON.stringify({
        b: (backendBase || "").replace(/\/$/, ""),
        t: payload.raw_text || null,
        e: payload.raw_email_b64 || null,
    });
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon));
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function load() {
    return new Promise((resolve) => chrome.storage.local.get([CACHE_KEY], (s) => resolve(s?.[CACHE_KEY] || {})));
}

function save(store) {
    return new Promise((resolve) => chrome.storage.local.set({ [CACHE_KEY]: store }, resolve));
}

// { features, cached: true } or null. A cache that cannot be read is a miss.
async function get(backendBase, payload) {
    try {
        const entry = (await load())[await hashPayload(backendBase, payload)];
        if (!entry || Date.now() - entry.ts > TTL_MS) return null;
        return { features: entry.features, cached: true };
    } catch (e) {
        console.debug("[PhishLens] explanation cache not read:", e?.message || e);
        return null;
    }
}

// Keeps the newest MAX_ENTRIES. A failed write only costs a later miss.
async function put(backendBase, payload, features) {
    if (!Array.isArray(features) || !features.length) return;
    try {
        const key = await hashPayload(backendBase, payload);
        const store = await load();
        store[key] = { features, ts: Date.now() };
        const oldestFirst = Object.entries(store).sort((a, b) => a[1].ts - b[1].ts);
        while (oldestFirst.length > MAX_ENTRIES) delete store[oldestFirst.shift()[0]];
        await save(store);
    } catch (e) {
        console.debug("[PhishLens] explanation cache not written:", e?.message || e);
    }
}

async function clear() {
    await save({});
}

async function stats() {
    return { entries: Object.keys(await load()).length };
}

const PhishLensLimeCache = Object.freeze({ get, put, clear, stats, hashPayload });
globalThis.PhishLensLimeCache = PhishLensLimeCache;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensLimeCache;
})();
