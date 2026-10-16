// =====================================================================
// PhishLens: helpers shared by the popup, the content scripts and the
// service worker (one implementation of each, instead of a copy per file).
// =====================================================================
// Exported as globalThis.PhishLensShared (classic scripts, no bundler).
// =====================================================================
(function () {
"use strict";

// Servers the user can choose in Settings ("custom" takes a typed URL).
const BACKEND_PRESETS = Object.freeze({
    local: "http://127.0.0.1:8000",
    cloud: "https://phishlens.dev",
});
const DEFAULT_BACKEND = "cloud";

// Base URL for a stored choice, without a trailing slash.
function resolveBackend(choice, customUrl) {
    if (choice === "custom") return String(customUrl || "").replace(/\/$/, "");
    return BACKEND_PRESETS[choice] || BACKEND_PRESETS[DEFAULT_BACKEND];
}

// Base URL of the server chosen in Settings.
async function getBackendBase() {
    try {
        const s = await new Promise((resolve) =>
            chrome.storage.local.get(["backend", "backend_custom_url"], resolve));
        return resolveBackend(s.backend || DEFAULT_BACKEND, s.backend_custom_url);
    } catch {
        return BACKEND_PRESETS[DEFAULT_BACKEND];
    }
}

// Text for innerHTML: every character with a meaning in HTML escaped.
const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function escapeHTML(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

// The message of a failed API call: FastAPI returns {"detail": "..."},
// or a list of field errors for an invalid request.
// In the interface language when lib/i18n.js is loaded.
function apiErrorMessage(data, status) {
    if (typeof data?.detail === "string") return data.detail;
    const t = globalThis.PhishLensI18n?.t;
    if (status === 413 || status === 422) return t ? t("err_too_large") : "This email is too large or malformed for PhishLens.";
    if (status === 429) return t ? t("err_rate") : "Too many scans in a short time. Wait a minute and try again.";
    return t ? t("err_server", { status }) : `Server error (HTTP ${status}).`;
}

const PhishLensShared = Object.freeze({
    BACKEND_PRESETS, DEFAULT_BACKEND, resolveBackend, getBackendBase, escapeHTML, apiErrorMessage,
});
globalThis.PhishLensShared = PhishLensShared;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensShared;
})();
