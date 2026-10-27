// The one way the popup and the content scripts reach the PhishLens
// server: a message to the service worker (background.js), which picks
// the server chosen in Settings and makes the request. Gmail's page CSP
// would block a direct request from a content script anyway.
(function () {
"use strict";

function t(key, vars) {
    return globalThis.PhishLensI18n?.t(key, vars) ?? key;
}

// After an extension update, a copy of a content script left in an open
// tab can no longer reach the service worker; the fix is a page reload.
function isContextLost(message) {
    return /context invalidated|message port closed|Receiving end does not exist/i.test(message);
}

// Resolves to the server's answer, or throws an Error with a message the
// interface can show as is.
async function call(type, payload, fields) {
    let reply;
    try {
        reply = await chrome.runtime.sendMessage({ type, payload, ...fields });
    } catch (e) {
        const message = String(e?.message || e);
        throw new Error(isContextLost(message) ? t("reloaded") : message);
    }
    if (!reply?.ok) throw new Error(reply?.error || t("unknown_error"));
    return reply.data;
}

const PhishLensApi = Object.freeze({
    analyse: (payload) => call("phishlens.analyse", payload),
    analyseAttachment: (payload) => call("phishlens.analyse_attachment", payload),
    // { features, cached }: cached when the explanation was already
    // computed for this text on this server (lib/lime_cache.js).
    explain: (payload) => call("phishlens.explain", payload),
    // The /health answer of the server chosen in Settings.
    health: () => call("phishlens.health"),
    // A report the user confirmed; resolves to its reference.
    feedback: (payload) => call("phishlens.feedback", payload).then((data) => data?.reference),
    // The local history, kept by the service worker for the content
    // scripts (lib/history.js has the details).
    history: Object.freeze({
        save: (entry) => call("phishlens.history.save", undefined, { entry }),
        update: (id, patch) => call("phishlens.history.update", undefined, { id, patch }),
        draft: (id, text) => call("phishlens.history.draft", undefined, { id, text }),
        attachTokens: (id, tokens) => call("phishlens.history.attachTokens", undefined, { id, tokens }),
    }),
    notify: (title, message) => call("phishlens.notify", undefined, { title, message }),
    isContextLost,
});
globalThis.PhishLensApi = PhishLensApi;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensApi;
})();
