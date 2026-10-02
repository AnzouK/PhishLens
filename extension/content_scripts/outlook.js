// =====================================================================
// PhishLens content script: Outlook on the web (v1.15).
// =====================================================================
// Loaded after gmail.js, whose banner, explanation and helper functions
// it reuses (gmail.js only starts its Gmail watchers on Gmail).
//
// Outlook page structure (Outlook on the web, 2026):
//   reading pane   [data-app-section="MailReadCompose"]
//   subject        [role="heading"][id$="_SUBJECT"]   (CONV_… for the thread)
//   one message    body [id^="UniqueMessageBody"], sender [id$="_FROM"]
// Outlook shows only the sender's NAME for people in the same
// organisation; the address is read from the "From" line when present.
// =====================================================================

/* global PLL_ICON, PLL_INSTANCE, pllAlive, pllShutdownIfDead, PLL_OBSERVERS, textOf, linkTargetsOf, showBanner, attachExplanation, setBtnLoading, _getBackendBase */

const OL_PANE_SEL = '[data-app-section="MailReadCompose"]';
const OL_SUBJECT_SEL = '[role="heading"][id^="CONV_"][id$="_SUBJECT"]';
const OL_BODY_SEL = '[id^="UniqueMessageBody"]';
const OL_EMAIL_RE = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/;

let _olQueued = false;
const _olObs = new MutationObserver(() => {
    if (pllShutdownIfDead() || _olQueued) return;
    _olQueued = true;
    setTimeout(() => { _olQueued = false; olInject(); }, 300);
});
PLL_OBSERVERS.push(_olObs);
_olObs.observe(document.body, { childList: true, subtree: true });

function olInject() {
    if (!pllAlive()) return;
    const pane = document.querySelector(OL_PANE_SEL);
    const subject = pane?.querySelector(OL_SUBJECT_SEL);
    if (!subject || subject.dataset.pllHooked === PLL_INSTANCE) return;
    if (!pane.querySelector(OL_BODY_SEL)) return;
    // Replace a button left by an older copy of the script (see gmail.js).
    subject.parentElement?.querySelectorAll(".pll-scan-btn--outlook").forEach((b) => b.remove());
    subject.dataset.pllHooked = PLL_INSTANCE;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pll-scan-btn pll-scan-btn--outlook";
    btn.innerHTML = `<span class="pll-scan-btn__icon">${PLL_ICON.shield}</span><span class="pll-scan-btn__label">Scan with PhishLens</span>`;
    btn.title = "Check this email for phishing";
    subject.insertAdjacentElement("afterend", btn);
    // Outlook listens to pointer events on the header: keep ours to us.
    for (const t of ["pointerdown", "mousedown", "mouseup", "keydown"]) {
        btn.addEventListener(t, (ev) => ev.stopPropagation());
    }
    btn.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        olScan(pane, btn);
    });
}

// Drafts sit in the conversation too ("[Draft]", "[Brouillon]"…, with
// an editor); they are never the message to scan.
const OL_DRAFT_RE = /\[(Draft|Brouillon|Borrador|Rascunho|Entwurf|Bozza)\]/i;
function olIsDraft(body) {
    let el = body;
    for (let i = 0; i < 8 && el && el !== document.body; i++) {
        el = el.parentElement;
        if (!el) break;
        if (el.querySelector('[contenteditable="true"]')) return true;
        if (OL_DRAFT_RE.test((el.innerText || "").slice(0, 300))) return true;
        if (el.querySelector('[id^="MSG_"][id$="_FROM"]')) return false;   // reached the message card
    }
    return false;
}

// The last message of the conversation that is expanded (has a body),
// drafts excluded.
function olCurrentMessage(pane) {
    const bodies = [...pane.querySelectorAll(OL_BODY_SEL)].filter((b) => !olIsDraft(b));
    const body = bodies[bodies.length - 1] || null;
    // Its sender: the last "_FROM" element placed before the body.
    let from = null;
    for (const f of pane.querySelectorAll('[id^="MSG_"][id$="_FROM"]')) {
        if (body && (f.compareDocumentPosition(body) & Node.DOCUMENT_POSITION_FOLLOWING)) from = f;
    }
    const fromText = (from?.querySelector("[aria-label]")?.getAttribute("aria-label") || from?.textContent || "")
        .replace(/^\s*(De|From)\s*:\s*/i, "").trim();
    const email = (fromText.match(OL_EMAIL_RE) || [])[0] || "";
    return { body, count: bodies.length, senderEmail: email.toLowerCase(), senderName: fromText.replace(/<[^>]*>/, "").trim() };
}

async function olScan(pane, btn) {
    const { body: bodyEl, count, senderEmail, senderName } = olCurrentMessage(pane);
    const subject = pane.querySelector(OL_SUBJECT_SEL)?.getAttribute("title")
                 || pane.querySelector(OL_SUBJECT_SEL)?.textContent?.trim() || "";
    const body = textOf(bodyEl);
    const links = linkTargetsOf(bodyEl);
    // The banner goes under the subject bar, not inside the message.
    const anchor = olBannerSlot(pane);

    if ((!body || body.length < 20) && !links.length) {
        showBanner(pane, {
            verdict: "error",
            title: "Nothing to scan in this email",
            error: "The body is empty or too short to analyse. Attachments can be dropped into the PhishLens popup.",
        }, anchor);
        return;
    }

    setBtnLoading(btn, true);
    try {
        const payload = {
            raw_text: ((!body || body.length < 20) ? [subject, body].filter(Boolean).join("\n") || "(no text)" : body).slice(0, 4000),
            sender_email: senderEmail || null,
            client_context: {
                origin: "outlook",
                subject,
                link_urls: links,
                thread_messages: count,
            },
        };
        const r = await chrome.runtime.sendMessage({ type: "phishlens.analyse", payload });
        if (!r?.ok) throw new Error(r?.error || "Unknown error");
        showBanner(pane, { ...r.data, _threadMessages: count }, anchor);

        const saved = await chrome.runtime.sendMessage({
            type: "phishlens.history.save",
            entry: {
                source: "outlook", subject, sender: senderEmail || senderName,
                verdict: r.data.verdict, score: Number(r.data.fused_score) || 0,
                agents: {
                    text: Number(r.data.agents?.text?.phishing_probability) || 0,
                    url: Number(r.data.agents?.url?.phishing_probability) || 0,
                    metadata: Number(r.data.agents?.metadata?.phishing_probability) || 0,
                },
                trusted: !!r.data.trusted_sender,
            },
        }).catch(() => null);

        // Word-level explanation, as in Gmail (cached by payload). Runs in
        // the background so the button is free again right away.
        olExplain(pane, payload, r.data, saved?.id);
    } catch (e) {
        const msg = String(e?.message || e);
        showBanner(pane, {
            verdict: "error",
            error: /context invalidated|message port closed/i.test(msg)
                ? "PhishLens was just reloaded: please refresh this Outlook tab to reconnect."
                : msg,
        }, anchor);
    } finally {
        setBtnLoading(btn, false);
    }
}

// An empty holder right after the subject bar; showBanner inserts the
// banner before it.
function olBannerSlot(pane) {
    let slot = pane.querySelector(".pll-ol-slot-anchor");
    if (slot) return slot;
    const subject = pane.querySelector(OL_SUBJECT_SEL);
    // The bar: the highest ancestor of the subject that does not contain
    // the messages (its parent holds the bar and the conversation).
    let bar = subject;
    while (bar?.parentElement && bar.parentElement !== pane &&
           !bar.parentElement.querySelector(OL_BODY_SEL)) {
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

async function olExplain(pane, payload, data, savedId) {
    try {
        if (data.text_agent_used === false) {
            const slot = pane.querySelector(".pll-banner .pll-banner__tokens");
            if (slot) slot.textContent = "This email has almost no text, so the verdict rests on its links and sender.";
            return;
        }
        let features = null, cached = false;
        try {
            const hit = await window.PhishLensLimeCache?.get(await _getBackendBase(), payload);
            if (hit) { features = hit.features; cached = true; }
        } catch {}
        if (!features) {
            const rr = await chrome.runtime.sendMessage({ type: "phishlens.explain", payload }).catch(() => null);
            if (!rr?.ok) return;
            features = rr.data.features || [];
            try { window.PhishLensLimeCache?.put(await _getBackendBase(), payload, features); } catch {}
        }
        attachExplanation(pane, features, cached);
        if (savedId) {
            chrome.runtime.sendMessage({
                type: "phishlens.history.attachTokens", id: savedId,
                tokens: features.slice(0, 5).map((f) => ({ token: f.token || "", weight: f.weight || 0 })),
            }).catch(() => {});
        }
    } catch {
        // explanation is best-effort
    }
}
