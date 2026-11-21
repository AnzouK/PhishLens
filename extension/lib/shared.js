// Helpers shared by the popup, the content scripts and the service worker.
(function () {
"use strict";

// Servers the user can choose in Settings ("custom" takes a typed URL).
const BACKEND_PRESETS = Object.freeze({
    local: "http://127.0.0.1:8000",
    cloud: "https://phishlens.dev",
});
const DEFAULT_BACKEND = "cloud";

// A typed server address as stored and compared everywhere: trimmed,
// scheme in lowercase ("HTTPS://" is accepted when typed), without
// trailing slashes.
function normalizeBaseUrl(value) {
    return String(value || "").trim().replace(/\/+$/, "")
        .replace(/^[a-z][a-z0-9+.-]*:/i, (scheme) => scheme.toLowerCase());
}

// Host permission pattern for a server address. The port is left out
// because Firefox rejects ports in match patterns, and without one Chrome
// matches every port.
function hostPattern(value) {
    try {
        const u = new URL(normalizeBaseUrl(value));
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        return `${u.protocol}//${u.hostname}/*`;
    } catch {
        return null;
    }
}

// The privacy policy on the website, in the interface language. The site
// serves its pages without ".html" (Cloudflare Pages).
function privacyUrl(lang) {
    return `https://phishlens.dev/${lang && lang !== "en" ? lang + "/" : ""}privacy`;
}

// Base URL for a stored choice, without a trailing slash.
function resolveBackend(choice, customUrl) {
    if (choice === "custom") return normalizeBaseUrl(customUrl);
    return BACKEND_PRESETS[choice] || BACKEND_PRESETS[DEFAULT_BACKEND];
}

// Base URL of the server chosen in Settings.
async function getBackendBase() {
    try {
        const s = await new Promise((resolve) =>
            chrome.storage.local.get(["backend", "backend_custom_url"], resolve));
        return resolveBackend(s.backend || DEFAULT_BACKEND, s.backend_custom_url);
    } catch (e) {
        debug("settings not readable, using the default server", e);
        return BACKEND_PRESETS[DEFAULT_BACKEND];
    }
}

// True for http:// to a server outside the user's own machine or network,
// where emails would cross the internet unencrypted. Local and private
// addresses are fine: loopback, .localhost and .local names, RFC 1918 and
// CGNAT ranges (Tailscale uses 100.64.0.0/10 and *.ts.net), IPv6 loopback,
// unique-local (fc00::/7) and link-local (fe80::/10).
function isPlainRemoteUrl(value) {
    let u;
    try {
        u = new URL(value);
    } catch {
        return false;            // not a URL yet (still being typed)
    }
    if (u.protocol !== "http:") return false;
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (host === "localhost" || /\.(localhost|local|ts\.net)$/.test(host) || host === "::1") return false;
    if (/^f[cd][0-9a-f]{0,2}:/.test(host) || /^fe[89ab][0-9a-f]?:/.test(host)) return false;
    const m = host.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
    if (m) {
        const a = Number(m[1]), b = Number(m[2]);
        if (a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)) return false;
        if (a === 100 && b >= 64 && b <= 127) return false;
    }
    return true;
}

// For failures that change nothing for the user, such as a cache miss or
// a page element that is gone. Visible at the console's "Verbose" level.
function debug(where, err) {
    console.debug(`[PhishLens] ${where}:`, err?.message || err);
}

// Message of a failed API call. FastAPI returns {"detail": "..."}, or a
// list of field errors for an invalid request. The message is in the
// interface language when lib/i18n.js is loaded.
function apiErrorMessage(data, status) {
    if (typeof data?.detail === "string") return data.detail;
    const t = globalThis.PhishLensI18n?.t;
    if (status === 413 || status === 422) return t ? t("err_too_large") : "This email is too large or malformed for PhishLens.";
    if (status === 429) return t ? t("err_rate") : "Too many scans in a short time. Wait a minute and try again.";
    return t ? t("err_server", { status }) : `Server error (HTTP ${status}).`;
}

// A file name as shown to the user, with the characters that reorder text
// made visible ("invoice\u202efdp.exe" would display as "invoiceexe.pdf").
function safeName(name) {
    return String(name || "").replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, "\u2420");
}

// Characters that take no room on screen: what Unicode calls default
// ignorable (format characters, fillers, variation selectors, tags) and
// control characters other than tab, line feed, form feed and carriage
// return. Same rule as backend/unicode_text.py, with shared cases in
// tests/fixtures/invisible_cases.json.
const INVISIBLE_SOURCE = "[\\p{Cf}\\x00-\\x08\\x0B\\x0E-\\x1F\\x7F-\\x9F\\u034F\\u115F\\u1160\\u17B4\\u17B5" +
    "\\u180B-\\u180D\\u180F\\u0890\\u0891\\u3164\\uFFA0\\uFE00-\\uFE0F\\uFFF0-\\uFFF8\\u{13430}-\\u{1343F}" +
    "\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E0FFF}]";
const INVISIBLE_ONE = new RegExp(INVISIBLE_SOURCE, "u");
// The scripts whose shape the joiners change: Arabic and Persian (with
// their presentation forms), the Indic scripts.
const SHAPED_BLOCK = /[\u0600-\u08FF\u0900-\u0DFF\uFB50-\uFDFF\uFE70-\uFEFC]/u;
const shapedLetter = (c) => !!c && SHAPED_BLOCK.test(c) && /\p{L}/u.test(c) && !INVISIBLE_ONE.test(c);
const shapedMark = (c) => !!c && SHAPED_BLOCK.test(c) && /\p{Mn}|\p{Mc}/u.test(c) && !INVISIBLE_ONE.test(c);

// True when the joiner at i sits where those scripts use one, after one
// of their letters (with its vowel signs or virama) and before another.
// Marks alone, invisible characters or Latin letters never count.
function joins(s, i) {
    if (!shapedLetter(s[i + 1])) return false;
    let j = i - 1;
    while (j >= 0 && shapedMark(s[j])) j--;
    return j >= 0 && shapedLetter(s[j]);
}

function withoutInvisible(text) {
    const s = String(text ?? "");
    return s.replace(new RegExp(INVISIBLE_SOURCE, "gu"),
        (c, i) => ((c === "\u200C" || c === "\u200D") && joins(s, i) ? c : ""));
}

// Cuts each run of invisible characters to its first one. The server's
// text model gets the page text as written
// (backend/unicode_text.collapse_invisible), but padding cannot fill it.
function collapseInvisible(text) {
    return String(text ?? "").replace(new RegExp(INVISIBLE_SOURCE + "+", "gu"), (run) => [...run][0]);
}

const PhishLensShared = Object.freeze({
    BACKEND_PRESETS, DEFAULT_BACKEND, resolveBackend, getBackendBase, apiErrorMessage, debug, safeName,
    INVISIBLE_SOURCE, withoutInvisible, collapseInvisible, isPlainRemoteUrl,
    normalizeBaseUrl, hostPattern, privacyUrl,
});
globalThis.PhishLensShared = PhishLensShared;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensShared;
})();
