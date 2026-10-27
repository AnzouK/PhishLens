// Gmail: the "Scan with PhishLens" button of an open email. Reads the
// message (text, sender, links, Gmail's sender checks, and the original
// message when "Read full headers" is on) and sends it to /analyse.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t } = PhishLensI18n;
const G = PhishLensGmail;
const { SEL } = G;

const processed = new WeakSet();
let scanQueued = false;

// Gmail mutates the page constantly: look for new emails at most every 250 ms.
PL.scheduleScan = function scheduleScan() {
    if (scanQueued) return;
    scanQueued = true;
    setTimeout(() => {
        scanQueued = false;
        injectIfNeeded();
    }, 250);
};

function injectIfNeeded() {
    if (!PL.alive()) return;
    document.querySelectorAll(SEL.subject).forEach((subjectEl) => {
        if (processed.has(subjectEl)) return;
        // An open email has a body; a subject in the list does not.
        const emailView = subjectEl.closest('div[role="main"]') || subjectEl.closest("body");
        if (!emailView?.querySelector(SEL.body)) return;
        processed.add(subjectEl);
        installScanButton(subjectEl, emailView);
    });
}

function installScanButton(subjectEl, emailView) {
    if (subjectEl.dataset.pllHooked === PL.instance) return;
    let wrap = subjectEl.parentElement?.classList.contains("pll-subject-wrap") ? subjectEl.parentElement : null;
    if (subjectEl.dataset.pllHooked && wrap) {
        // Hooked by an older copy of the scripts: drop its dead buttons.
        wrap.querySelectorAll(".pll-scan-btn").forEach((b) => b.remove());
    }
    subjectEl.dataset.pllHooked = PL.instance;
    if (!wrap) {
        wrap = document.createElement("div");
        wrap.className = "pll-subject-wrap";
        subjectEl.parentNode.insertBefore(wrap, subjectEl);
        wrap.appendChild(subjectEl);
    }
    wrap.appendChild(PL.scanButton({
        label: t("scan_button"),
        title: t("scan_button_title"),
        onClick: (btn) => runScan(emailView, btn),
    }));
}

// In a conversation several messages can be expanded. The one scanned is
// the last expanded message; body, sender, links and the sender checks
// are all read from it, so they cannot come from two different emails.
function currentMessage(emailView) {
    const msgs = [...emailView.querySelectorAll(SEL.message)].filter((m) => m.querySelector(SEL.body));
    return { msg: msgs.length ? msgs[msgs.length - 1] : emailView, count: msgs.length };
}

// No text and no links: nothing to score. Usually an email that only
// carries an attachment (a classic lure), so the attachments are scanned.
function nothingToScan(emailView, hasAttachments, attBtn) {
    if (hasAttachments) {
        PL.showBanner(emailView, {
            verdict: "error",
            title: t("nothing_text_title"),
            error: attBtn ? t("nothing_text_lead_scanning") : t("nothing_text_lead"),
        });
        if (attBtn && !attBtn.disabled) attBtn.click();
    } else {
        PL.showBanner(emailView, { verdict: "error", title: t("nothing_title"), error: t("nothing_lead") });
    }
}

async function buildPayload(emailView, msg, { body, subject, links, count, sender }) {
    const shortBody = !body || body.length < PL.MIN_BODY;
    // Gmail ran SPF/DKIM/DMARC before delivery; its results on the page
    // let the server trust a verified sender even without the headers.
    const gmailAuth = extractGmailAuthSignals(emailView, msg);
    const original = PL.opts.fullHeaders ? await PL.fetchOriginalMessage(msg) : null;
    console.info(PL.TAG, original ? `full headers: ${original.length} chars from Show original`
        : `full headers: not used (option ${PL.opts.fullHeaders ? "on" : "off"})`);
    const payload = {
        // With the original, the headers come from it but the text is the
        // one the page shows: plain-text parts spell URLs out and skew the
        // text model.
        ...(original
            ? { raw_email_b64: PL.utf8ToB64(original), ...(shortBody ? {} : { raw_text: body.slice(0, 4000) }) }
            : { raw_text: PL.rawText(subject, body) }),
        sender_email: sender.getAttribute?.("email") || null,
        sender_name: sender.textContent?.trim() || null,
        client_context: {
            origin: "gmail",
            subject,
            ...(original ? { headers_source: "gmail_show_original" } : {}),
            gmail_signed_by: gmailAuth.signedBy,
            gmail_mailed_by: gmailAuth.mailedBy,
            gmail_via: gmailAuth.via,
            gmail_in_inbox: gmailAuth.inInbox,
            link_urls: links,
            thread_messages: count,
        },
    };
    return { payload, fullHeaders: !!original };
}

async function runScan(emailView, btn) {
    const { msg, count } = currentMessage(emailView);
    const bodyEl = msg.querySelector(SEL.body);
    const body = PL.textOf(bodyEl);
    const sender = msg.querySelector(SEL.sender) || emailView.querySelector(SEL.sender) || {};
    const subject = emailView.querySelector(SEL.subject)?.textContent?.trim() || "";
    const links = PL.linkTargetsOf(bodyEl);
    const hasAttachments = !!(msg.querySelector(SEL.attachmentStrip) || emailView.querySelector(SEL.attachmentStrip));
    const attBtn = emailView.querySelector(".pll-scan-btn--all");
    const shortBody = !body || body.length < PL.MIN_BODY;

    if (shortBody && !links.length) {
        nothingToScan(emailView, hasAttachments, attBtn);
        return;
    }
    // Almost no text but some links (image-only emails): the links and the
    // sender are scored, and the attachments scanned too.
    if (shortBody && hasAttachments && attBtn && !attBtn.disabled) attBtn.click();

    PL.setBtnLoading(btn, true);
    try {
        const { payload, fullHeaders } = await buildPayload(emailView, msg, { body, subject, links, count, sender });
        const data = await PhishLensApi.analyse(payload);
        PL.showBanner(emailView, { ...data, _threadMessages: count, _fullHeaders: fullHeaders });
        const senderText = payload.sender_email || payload.sender_name || "";
        const historyId = await PL.saveScan(data, { source: "gmail", subject, sender: senderText });
        PL.attachFeedback(emailView, data, { historyId, source: "gmail", subject, body, links });
        PL.explainInBackground(emailView, payload, data, historyId);
    } catch (e) {
        PL.showError(emailView, e);
    } finally {
        PL.setBtnLoading(btn, false);
    }
}

let ikCache = null;
function gmailIk() {
    ikCache ||= G.ikFromScripts([...document.scripts].map((s) => s.textContent));
    return ikCache;
}

// The raw message behind "Show original". `ref` is the message element
// or { thread: id } from the message list. null when Gmail does not
// serve it (changed page, timeout): the scan then uses the visible page.
PL.fetchOriginalMessage = async function fetchOriginalMessage(ref) {
    const fallback = (why) => {
        console.info(PL.TAG, `full headers: ${why}, using the visible page`);
        return null;
    };
    const ik = gmailIk();
    if (!ik) return fallback("Gmail token not found");
    const query = G.originalQuery(ref?.thread ? { thread: ref.thread } : {
        messageId: ref?.getAttribute?.("data-message-id"),
        legacyId: ref?.getAttribute?.("data-legacy-message-id"),
    });
    if (!query) return fallback("no message id");
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
        // Absolute URL: a relative one is not resolved against the page in
        // every content-script context.
        const resp = await fetch(G.originalUrl(location.origin, location.pathname, ik, query),
            { credentials: "include", signal: ctrl.signal });
        if (!resp.ok) return fallback(`Gmail answered HTTP ${resp.status}`);
        const { raw, reason } = G.parseShowOriginal(await resp.text());
        return raw || fallback(reason);
    } catch (e) {
        return fallback("fetch failed: " + String(e?.message || e));
    } finally {
        clearTimeout(timer);
    }
};

// Gmail's own sender checks, as shown on the page: the "mailed-by" and
// "signed-by" rows of the message details (present only when the user
// opened them; opening them automatically was too intrusive), the "via
// example.com" hint, and whether the mail is outside Spam and Trash.
// Matched on visible labels, not on Gmail's class names.
function extractGmailAuthSignals(emailView, msg) {
    const out = { signedBy: null, mailedBy: null, via: null, inInbox: G.inInbox(location.hash) };
    if (msg) scrapeAuthRows(msg, out);
    if (!out.signedBy && !out.mailedBy) scrapeAuthRows(document.body, out);
    for (const el of (msg || emailView).querySelectorAll("span")) {
        out.via = G.viaDomain(el.textContent);
        if (out.via) break;
    }
    return out;
}

function scrapeAuthRows(root, out) {
    for (const el of root.querySelectorAll("td, span, div")) {
        const raw = el.textContent || "";
        if (!raw || raw.length > 40) continue;
        const kind = G.authRowKind(raw);
        if (!kind) continue;
        const value = el.nextElementSibling?.textContent?.trim();
        if (value && /\./.test(value) && !/\s/.test(value)) out[kind] = value;
    }
}

// Exposed for tests.
PL.extractGmailAuthSignals = extractGmailAuthSignals;
PL.runScan = runScan;
})();
