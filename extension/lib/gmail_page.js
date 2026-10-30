// Everything PhishLens assumes about Gmail's page, in one place. Gmail
// has no public API for an open message: these are observations of its
// current page (class names, an inline script, the "Show original" view)
// and they break when Gmail changes. Each one is covered by a test on a
// sample page (tests/extension/gmail_page.test.js, tests/fixtures/gmail/);
// when Gmail changes, update the sample and the code here together.
(function () {
"use strict";

const SEL = Object.freeze({
    subject: "h2.hP",                    // subject of the open conversation
    body: ".a3s.aiL",                    // body of one message
    sender: ".gD[email]",                // <span class="gD" email="…">Name</span>
    headerBar: ".aeF",                   // bar above the open conversation
    message: ".adn",                     // one message of a conversation
    attachmentStrip: ".aQH, .aQe, .hq",  // attachment tiles, current and older layouts
    attachmentTile: ".aZo, [data-attachmentid], .aQw",
    attachmentName: ".aV3, .aQw, .aQA, .a1V",
    inboxRow: "tr.zA",                   // one row of the message list
    unreadRowClass: "zE",
    rowSubject: ".bog",
    rowThreadId: "[data-legacy-thread-id]",
});

// Gmail's per-account token "ik", needed by its own URLs: the 10th value
// of `var GLOBALS=[…]` in an inline script of the page. Content scripts
// cannot read page variables, but they can read the script text.
function ikFromScripts(scriptTexts) {
    for (const src of scriptTexts) {
        const i = String(src || "").indexOf("var GLOBALS=[");
        if (i < 0) continue;
        const parts = src.slice(i + 13, i + 4000).split(",");
        const value = (parts[9] || "").trim().replace(/^"|"$/g, "");
        if (/^[0-9a-f]{6,20}$/.test(value)) return value;
    }
    return null;
}

// "/mail/u/1" for the second signed-in account.
function accountPath(pathname) {
    const m = String(pathname || "").match(/^\/mail\/u\/\d+/);
    return m ? m[0] : "/mail/u/0";
}

// Query naming one message for the "Show original" view: from a message
// element's data-message-id ("#msg-f:123…") or data-legacy-message-id
// (hex), or a thread id from the message list. null when none fits.
function originalQuery({ thread, messageId, legacyId } = {}) {
    if (thread) return "th=" + encodeURIComponent(thread);
    const perm = String(messageId || "").replace(/^#/, "");
    if (/^msg-[a-z]:[a-z]?-?\d+$/.test(perm)) return "permmsgid=" + encodeURIComponent(perm);
    if (/^[0-9a-f]{8,20}$/.test(legacyId || "")) return "th=" + legacyId;
    return null;
}

function originalUrl(origin, pathname, ik, query) {
    return `${origin}${accountPath(pathname)}/?ik=${ik}&view=om&${query}`;
}

const ENTITIES = { "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&amp;": "&" };
const MAX_RAW = 2 * 1024 * 1024;

// The raw message in the "Show original" page: the <pre id="raw_message_text">
// (headers and text parts; Gmail leaves attachment bodies out).
// Returns { raw } or { reason } saying why it was not usable.
function parseShowOriginal(html) {
    const start = html.indexOf('id="raw_message_text"');
    if (start < 0) return { reason: "unexpected page layout" };
    const open = html.indexOf(">", start);
    const close = html.indexOf("</pre>", open);
    if (open < 0 || close < 0) return { reason: "unexpected page layout" };
    const raw = html.slice(open + 1, close).replace(/&(?:lt|gt|quot|#39|amp);/g, (e) => ENTITIES[e]);
    if (!/^(?:from|received|delivered-to|return-path):/im.test(raw.slice(0, 20000))) {
        return { reason: "content is not an email" };
    }
    // A message the user sent (or a draft) has no delivery headers:
    // nothing to verify, and the sender checks would read it wrong.
    const headerEnd = raw.search(/\r?\n\r?\n/);
    if (!/^Received:/im.test(raw.slice(0, headerEnd > 0 ? headerEnd : 20000))) {
        return { reason: "no delivery headers (a message you sent?)" };
    }
    return { raw: raw.slice(0, MAX_RAW) };
}

// Labels of the "mailed-by" / "signed-by" rows of the message details,
// in the interface languages PhishLens supports. Only a fallback: with
// "Read full headers" on, the real Authentication-Results header is used.
const MAILED_BY = new Set(["mailed-by", "envoyé par", "enviado por", "gesendet von", "inviato da", "verzonden door"]);
const SIGNED_BY = new Set(["signed-by", "signé par", "firmado por", "assinado por", "signiert von", "firmato da",
    "ondertekend door"]);

function authRowKind(labelText) {
    const label = String(labelText || "").trim().toLowerCase().replace(/\s*:$/, "");
    return MAILED_BY.has(label) ? "mailedBy" : SIGNED_BY.has(label) ? "signedBy" : null;
}

// The domain of the "via example.com" hint next to the sender.
function viaDomain(text) {
    const m = String(text || "").trim().toLowerCase().match(/^via\s+([a-z0-9.-]+\.[a-z]{2,})$/i);
    return m ? m[1] : null;
}

// Spam and Trash have their own hash in Gmail's URL; a search can reach
// them too ("in:spam", "in:anywhere").
function inInbox(hash) {
    return !/spam|trash|anywhere/i.test(String(hash || ""));
}

const PhishLensGmail = Object.freeze({
    SEL, ikFromScripts, accountPath, originalQuery, originalUrl, parseShowOriginal, authRowKind, viaDomain, inInbox,
});
globalThis.PhishLensGmail = PhishLensGmail;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensGmail;
})();
