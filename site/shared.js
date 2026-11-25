// Helpers shared by the popup, the content scripts and the service worker.
(function () {
"use strict";

// Servers the user can choose in Settings ("custom" takes a typed URL).
const BACKEND_PRESETS = Object.freeze({
    local: "http://127.0.0.1:8000",
    cloud: "https://phishlens.dev",
});
const DEFAULT_BACKEND = "cloud";

// Normalises a typed server address before it is stored or compared. We
// trim it, lower-case the scheme and drop trailing slashes.
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

// Characters that take no room on screen. That is Unicode's default
// ignorable set plus control characters other than tab, line feed, form
// feed and carriage return. backend/unicode_text.py uses the same rule and
// both are tested against tests/fixtures/invisible_cases.json.
const INVISIBLE_SOURCE = "[\\p{Cf}\\x00-\\x08\\x0B\\x0E-\\x1F\\x7F-\\x9F\\u034F\\u115F\\u1160\\u17B4\\u17B5" +
    "\\u180B-\\u180D\\u180F\\u0890\\u0891\\u3164\\uFFA0\\uFE00-\\uFE0F\\uFFF0-\\uFFF8\\u{13430}-\\u{1343F}" +
    "\\u{1BCA0}-\\u{1BCA3}\\u{1D173}-\\u{1D17A}\\u{E0000}-\\u{E0FFF}]";
const INVISIBLE_ONE = new RegExp(INVISIBLE_SOURCE, "u");
// Scripts whose letter shapes depend on joiners, such as Arabic, Persian
// and the Indic scripts.
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

// Meter level for a score. 70% and up is "high" (red), 40% and up is
// "mid", the rest is "low". We compare the rounded percentage the user sees.
const HIGH_SCORE_PCT = 70;
const MID_SCORE_PCT = 40;
function scoreLevel(probability) {
    const pct = Math.round((Number(probability) || 0) * 100);
    return pct >= HIGH_SCORE_PCT ? "high" : pct >= MID_SCORE_PCT ? "mid" : "low";
}

// Attachment flags meaning PhishLens could not look inside. A low score
// is then not reassuring.
const CAUTION_FLAGS = Object.freeze([
    "encrypted_archive", "encrypted_document", "uninspectable_archive",
    "disk_image_attachment", "disk_image_in_archive", "zip_bomb_suspected", "inner_files_not_extracted",
    "document_not_fully_read",
]);

function isCaution(flags) {
    return (flags || []).some((f) => CAUTION_FLAGS.includes(f));
}

// Attachment flags that only describe the file, such as OCR text, links,
// an invite or an old Office format. They show as neutral chips. Every
// other flag is a warning and shows in orange.
const NEUTRAL_FLAGS = Object.freeze([
    "text_from_ocr", "contains_link_annotation", "calendar_invite", "legacy_office_format",
]);
const isWarningFlag = (flag) => !NEUTRAL_FLAGS.includes(flag);

// The agent scores shown next to a verdict. The text score is not shown
// when the text model did not count (almost no text), nor the sender
// score when there was no sender information.
function shownScores(data) {
    const a = data?.agents || {};
    return [
        data?.text_agent_used === false ? null : a.text?.phishing_probability,
        a.url?.phishing_probability,
        a.metadata?.checked === false ? null : a.metadata?.phishing_probability,
    ].filter((p) => p != null);
}

// True when sender authentication failed in a way worth warning about.
// DKIM or DMARC failing counts. SPF failing only counts without a DMARC
// pass, because mailing lists and forwarders resend from their own
// servers and break SPF while DKIM still aligns.
function authFailed(auth) {
    if (auth?.dkim === "fail" || auth?.dmarc === "fail") return true;
    return auth?.spf === "fail" && auth?.dmarc !== "pass";
}

// Names of the signs in the result that we show as an orange or red chip
// (empty array when there are none): brand impersonation, forwards,
// shared files or forms, links flagged by threat intelligence, failed
// sender authentication, a sender on Spamhaus and the warning flags of an
// attachment.
function unusualSigns(data) {
    const auth = data?.sender_auth || {};
    const signs = [];
    if (auth.impersonation?.brand) signs.push("impersonation");
    if (data?.forwarded?.detected) signs.push("forwarded");
    if (data?.shared_links?.count) signs.push("shared_links");
    if (data?.url_reputation?.malicious_count > 0) signs.push("flagged_links");
    if (authFailed(auth)) signs.push("auth_fail");
    if (auth.spamhaus_dbl_listed) signs.push("spamhaus");
    if ((data?.attachment?.notable_features || []).some(isWarningFlag)) signs.push("file_flags");
    return signs;
}

// Short reason for a safe verdict, or null when nothing needs explaining.
// "forwarded", "shared" and "no_text" come first. When an agent score is
// high, the reason says why it didn't count ("trusted", "crypto",
// "internal", "gmail" or "one_signal"). The banner and the popup each
// turn it into their own sentence.
function safeReason(data) {
    if (data?.forwarded?.detected) return "forwarded";
    if (data?.shared_links?.count) return "shared";
    if (data?.text_agent_used === false) return "no_text";
    if (!shownScores(data).some((p) => scoreLevel(p) === "high")) return null;
    if (data.trust_path === "trusted_sender" || data.trusted_sender) return "trusted";
    const byPath = { crypto_verified: "crypto", outlook_internal: "internal", gmail_inbox_soft: "gmail" };
    return byPath[data.trust_path] || "one_signal";
}

// Display style for a verdict. Phishing is "danger". A safe verdict next
// to a red meter or an unusual sign is "caution", because a green "looks
// safe" above them would contradict the details. Everything else is
// "safe". The server's verdict and scores are never changed.
function displayVerdict(data) {
    if (data?.verdict === "phishing") return "danger";
    const high = shownScores(data).some((p) => scoreLevel(p) === "high");
    return high || unusualSigns(data).length ? "caution" : "safe";
}

const PhishLensShared = Object.freeze({
    BACKEND_PRESETS, DEFAULT_BACKEND, resolveBackend, getBackendBase, apiErrorMessage, debug, safeName,
    INVISIBLE_SOURCE, withoutInvisible, collapseInvisible, isPlainRemoteUrl,
    normalizeBaseUrl, hostPattern, privacyUrl,
    scoreLevel, isCaution, isWarningFlag, shownScores, authFailed, unusualSigns, safeReason, displayVerdict,
});
globalThis.PhishLensShared = PhishLensShared;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensShared;
})();
