// Outlook on the web: the scan button and the verdict banner (banner.js).
// What this file assumes about Outlook's page (2026):
//   reading pane   [data-app-section="MailReadCompose"]
//   subject        [role="heading"][id^="CONV_"][id$="_SUBJECT"]
//   one message    body [id^="UniqueMessageBody"], sender [id^="MSG_"][id$="_FROM"]
// Outlook shows only the NAME of senders in the user's organisation; the
// address is read from the "From" line when there is one.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t } = PhishLensI18n;

const SEL = Object.freeze({
    pane: '[data-app-section="MailReadCompose"]',
    subject: '[role="heading"][id^="CONV_"][id$="_SUBJECT"]',
    body: '[id^="UniqueMessageBody"]',
    from: '[id^="MSG_"][id$="_FROM"]',
});
const EMAIL_RE = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/;
// Drafts sit in the conversation too, with an editor; never scanned.
const DRAFT_RE = /\[(Draft|Brouillon|Borrador|Rascunho|Entwurf|Bozza|Concept)\]/i;

PL.olInject = function olInject() {
    if (!PL.alive()) return;
    const pane = document.querySelector(SEL.pane);
    const subject = pane?.querySelector(SEL.subject);
    if (!subject || subject.dataset.pllHooked === PL.instance || !pane.querySelector(SEL.body)) return;
    // Replace a button left by an older copy of the scripts.
    subject.parentElement?.querySelectorAll(".pll-scan-btn--outlook").forEach((b) => b.remove());
    subject.dataset.pllHooked = PL.instance;

    const btn = PL.scanButton({
        extraClass: "pll-scan-btn--outlook",
        label: t("scan_button"),
        title: t("scan_button_title"),
        onClick: (b) => olScan(pane, b),
    });
    // Outlook listens to pointer events on the header: keep ours to us.
    for (const evt of ["pointerdown", "mousedown", "mouseup", "keydown"]) {
        btn.addEventListener(evt, (ev) => ev.stopPropagation());
    }
    subject.insertAdjacentElement("afterend", btn);
};

function isDraft(body) {
    let el = body;
    for (let i = 0; i < 8 && el && el !== document.body; i++) {
        el = el.parentElement;
        if (!el) break;
        if (el.querySelector('[contenteditable="true"]')) return true;
        if (DRAFT_RE.test((el.innerText || "").slice(0, 300))) return true;
        if (el.querySelector(SEL.from)) return false;   // reached the message card
    }
    return false;
}

// The last expanded message of the conversation, drafts excluded, and
// its sender: the last "From" line placed before its body.
function currentMessage(pane) {
    const all = [...pane.querySelectorAll(SEL.body)];
    const bodies = all.filter((b) => !isDraft(b));
    const body = bodies[bodies.length - 1] || null;
    // The From line of this message: before its body, after every other
    // body (else it is an earlier message's), and not inside a body (an
    // email can contain an element with that id).
    const before = (a, b) => !!(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    let from = null;
    for (const f of pane.querySelectorAll(SEL.from)) {
        if (!body || PL.inMessageBody(f) || !before(f, body)) continue;
        if (all.some((other) => other !== body && before(f, other) && before(other, body))) continue;
        from = f;
    }
    // The address may be in the text or in a label or title of any part
    // of the line (the first labelled part is often the avatar, with the
    // name only): every one is read.
    const texts = from ? [from.textContent || ""] : [];
    for (const el of from?.querySelectorAll("[aria-label], [title]") || []) {
        texts.push(el.getAttribute("aria-label") || "", el.getAttribute("title") || "");
    }
    const email = texts.map((x) => (x.match(EMAIL_RE) || [])[0]).find(Boolean) || "";
    const fromText = (from?.textContent || "").replace(/^\s*(From|De|Von|Da|Van)\s*:\s*/i, "").trim();
    return {
        body,
        count: bodies.length,
        // "Internal" only when there is a From line and no address in it.
        foundFrom: !!from && !texts.some((x) => x.includes("@")),
        senderEmail: email.toLowerCase(),
        // "Name <address>" -> "Name"
        senderName: fromText.split("<")[0].trim(),
    };
}

// Domain of the signed-in account, from the folder pane ("name@org").
function accountDomain() {
    for (const el of document.querySelectorAll('[role="treeitem"][title*="@"], [role="tree"] [title*="@"]')) {
        const m = (el.getAttribute("title") || "").trim().match(/^[\w.+-]+@([\w-]+(?:\.[\w-]+)+)$/);
        if (m) return m[1].toLowerCase();
    }
    return null;
}

// An empty holder right after the subject bar; the banner goes before it.
function bannerSlot(pane) {
    let slot = pane.querySelector(".pll-ol-slot-anchor");
    if (slot) return slot;
    // The bar: the highest ancestor of the subject without the messages.
    let bar = pane.querySelector(SEL.subject);
    while (bar?.parentElement && bar.parentElement !== pane && !bar.parentElement.querySelector(SEL.body)) {
        bar = bar.parentElement;
    }
    const holder = document.createElement("div");
    holder.className = "pll-ol-slot";
    slot = document.createElement("div");
    slot.className = "pll-ol-slot-anchor";
    holder.appendChild(slot);
    (bar || pane).insertAdjacentElement(bar ? "afterend" : "afterbegin", holder);
    return slot;
}

async function olScan(pane, btn) {
    const { body: bodyEl, count, senderEmail, senderName, foundFrom } = currentMessage(pane);
    const subjectEl = pane.querySelector(SEL.subject);
    const subject = subjectEl?.getAttribute("title") || subjectEl?.textContent?.trim() || "";
    const hidden = PL.hiddenParts(bodyEl);       // one walk for the text and the links
    const body = PL.textOf(bodyEl, hidden);
    const linkGroups = PL.linkGroupsOf(bodyEl, hidden);
    const links = [...linkGroups.visible, ...linkGroups.hidden];
    const anchor = bannerSlot(pane);

    if ((!body || body.length < PL.MIN_BODY) && !links.length) {
        PL.showBanner(pane, { verdict: "error", title: t("nothing_title"), error: t("nothing_lead_outlook") }, anchor);
        return;
    }
    if (!(await PL.confirmCloudUse(pane, anchor))) return;

    PL.setBtnLoading(btn, true);
    try {
        const payload = {
            raw_text: PL.rawText(subject, body),
            sender_email: senderEmail.slice(0, 512) || null,
            sender_name: PL.senderName(senderName),
            client_context: {
                origin: "outlook",
                subject,
                // A From line without an address: a sender of the user's own
                // organisation (soft path only, see docs/architecture.md).
                ...(foundFrom && !senderEmail ? { outlook_internal: true, org_domain: accountDomain() } : {}),
                link_urls: linkGroups.visible,
                hidden_link_urls: linkGroups.hidden,
                thread_messages: count,
            },
        };
        const data = await PhishLensApi.analyse(payload);
        PL.showBanner(pane, { ...data, _threadMessages: count }, anchor);
        const historyId = await PL.saveScan(data, { source: "outlook", subject, sender: senderEmail || senderName });
        PL.attachFeedback(pane, data, { historyId, source: "outlook", subject, body, links });
        PL.explainInBackground(pane, payload, data, historyId);
    } catch (e) {
        PL.showError(pane, e, anchor);
    } finally {
        PL.setBtnLoading(btn, false);
    }
}

let queued = false;
PL.observe(() => {
    if (PL.shutdownIfDead() || queued) return;
    queued = true;
    setTimeout(() => { queued = false; PL.refreshTheme(); PL.olInject(); }, 300);
});
})();
