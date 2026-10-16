// =====================================================================
// PhishLens content script: Gmail, scanning the open email.
// =====================================================================
// Injects the "Scan with PhishLens" button next to the subject, reads
// the message (text, sender, links, Gmail's sender checks, and the full
// original message when the option is on) and sends it to /analyse.
// =====================================================================

let scanQueued = false;
function scheduleScan() {
    if (scanQueued) return;
    scanQueued = true;
    setTimeout(() => {
        scanQueued = false;
        injectIfNeeded();
    }, 250);                   // debounce: Gmail mutates a LOT
}

function injectIfNeeded() {
    if (!pllAlive()) return;
    document.querySelectorAll(SUBJECT_SEL).forEach((subjectEl) => {
        if (PROCESSED.has(subjectEl)) return;
        // Make sure we're looking at a real open email, not a list row.
        const emailView = subjectEl.closest('div[role="main"]') ||
                          subjectEl.closest("body");
        const bodyEl   = emailView?.querySelector(BODY_SEL);
        if (!bodyEl) return;
        PROCESSED.add(subjectEl);
        installScanButton(subjectEl, emailView);
    });
}

// ---------------------------------------------------------------------
// Inject the "Scan with PhishLens" button + verdict banner placeholder
// ---------------------------------------------------------------------
function installScanButton(subjectEl, emailView) {
    // wrap the subject in a flex container so we can put the button after it
    if (subjectEl.dataset.pllHooked === PLL_INSTANCE) return;
    let wrap = subjectEl.parentElement?.classList.contains("pll-subject-wrap") ? subjectEl.parentElement : null;
    if (subjectEl.dataset.pllHooked && wrap) {
        // Hooked by an older copy of the script: drop its dead buttons.
        wrap.querySelectorAll(".pll-scan-btn").forEach((b) => b.remove());
    }
    subjectEl.dataset.pllHooked = PLL_INSTANCE;

    if (!wrap) {
        wrap = document.createElement("div");
        wrap.className = "pll-subject-wrap";
        subjectEl.parentNode.insertBefore(wrap, subjectEl);
        wrap.appendChild(subjectEl);
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pll-scan-btn";
    btn.innerHTML = `<span class="pll-scan-btn__icon">${PLL_ICON.shield}</span><span class="pll-scan-btn__label">${escapeHTML(t("scan_button"))}</span>`;
    btn.title = t("scan_button_title");
    wrap.appendChild(btn);

    btn.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        runScan(emailView, btn);
    });
}

// ---------------------------------------------------------------------
// Extract email data + run /analyse
// ---------------------------------------------------------------------
// In a conversation, several messages can be expanded at once. The one
// to scan is the last expanded message (the newest one Gmail opened);
// body, sender, links and auth rows are all read from that message so
// they cannot come from two different emails.
function currentMessage(emailView) {
    const msgs = [...emailView.querySelectorAll(".adn")]
        .filter((m) => m.querySelector(BODY_SEL));
    return { msg: msgs.length ? msgs[msgs.length - 1] : emailView, count: msgs.length };
}

async function runScan(emailView, btn) {
    const { msg, count } = currentMessage(emailView);
    const bodyEl = msg.querySelector(BODY_SEL);
    const body   = textOf(bodyEl);
    const sender = msg.querySelector(SENDER_SEL) || emailView.querySelector(SENDER_SEL);
    const senderEmail = sender?.getAttribute("email") || "";
    const senderName  = sender?.textContent?.trim() || "";
    const subject = emailView.querySelector(SUBJECT_SEL)?.textContent?.trim() || "";
    const links   = linkTargetsOf(bodyEl);
    const hasAttachments = !!msg.querySelector(ATT_STRIP_SEL) || !!emailView.querySelector(ATT_STRIP_SEL);
    const attBtn = emailView.querySelector(".pll-scan-btn--all");
    const shortBody = !body || body.length < 20;

    if (shortBody && !links.length) {
        // No text and no links to score. Common case: an email that only
        // carries an attachment (itself a classic phishing lure). Scan the
        // attachments instead of giving up.
        if (hasAttachments) {
            showBanner(emailView, {
                verdict: "error",
                title: t("nothing_text_title"),
                error: attBtn ? t("nothing_text_lead_scanning") : t("nothing_text_lead"),
            });
            if (attBtn && !attBtn.disabled) attBtn.click();
        } else {
            showBanner(emailView, {
                verdict: "error",
                title: t("nothing_title"),
                error: t("nothing_lead"),
            });
        }
        return;
    }
    // Almost no text but some links (image-only emails): scan the links
    // and the sender; the backend leaves the text model out. Attachments,
    // if any, are scanned too.
    if (shortBody && hasAttachments && attBtn && !attBtn.disabled) attBtn.click();

    setBtnLoading(btn, true);
    try {
        // Gmail already ran SPF/DKIM/DMARC before delivering: surface its
        // verdict from the DOM so the backend can apply the crypto_verified
        // discount even when we only have raw_text (no Authentication-Results
        // header to parse).
        const gmailAuth = await extractGmailAuthSignals(emailView, msg);

        // Send the body as raw_text and the sender separately so the backend
        // can run the trusted-domain check.
        // The full original message (all headers: Received chain,
        // Authentication-Results, Reply-To...) when the setting is on and
        // Gmail serves it; otherwise the visible text as before.
        const original = PLL_OPTS.fullHeaders ? await fetchOriginalMessage(msg) : null;
        console.info(TAG, original ? `full headers: ${original.length} chars from Show original`
                                   : `full headers: not used (option ${PLL_OPTS.fullHeaders ? "on" : "off"})`);
        const payload = {
            // With the original: headers from it, but the text as the page
            // shows it (plain-text parts spell URLs out and skew the text
            // model). Without it: the page text, as before.
            ...(original
                ? { raw_email_b64: utf8ToB64(original), ...(shortBody ? {} : { raw_text: body.slice(0, 4000) }) }
                : { raw_text: (shortBody ? [subject, body].filter(Boolean).join("\n") || "(no text)" : body).slice(0, 4000) }),
            sender_email: senderEmail || null,
            sender_name: senderName || null,
            client_context: {
                origin: "gmail",
                subject,
                ...(original ? { headers_source: "gmail_show_original" } : {}),
                gmail_signed_by: gmailAuth.signedBy,
                gmail_mailed_by: gmailAuth.mailedBy,
                gmail_via:       gmailAuth.via,
                gmail_in_inbox:  gmailAuth.inInbox,
                // Real link targets: innerText only has the visible link
                // text ("Click here"), not where the link goes.
                link_urls:       links,
                thread_messages: count,
            },
        };

        const r = await chrome.runtime.sendMessage({
            type: "phishlens.analyse", payload,
        });
        if (!r?.ok) throw new Error(r?.error || t("unknown_error"));
        showBanner(emailView, { ...r.data, _threadMessages: count, _fullHeaders: !!original });

        // Persist this scan in the local history: background.js writes it
        // via the shared history module. We remember the returned id so we
        // can attach LIME tokens to the same entry when /explain resolves.
        const historyEntry = {
            source:  "gmail",
            subject: subject,
            sender:  senderEmail || senderName,
            verdict: r.data.verdict,
            score:   Number(r.data.fused_score) || 0,
            agents: {
                text:     Number(r.data.agents?.text?.phishing_probability)     || 0,
                url:      Number(r.data.agents?.url?.phishing_probability)      || 0,
                metadata: Number(r.data.agents?.metadata?.phishing_probability) || 0,
            },
            trusted: !!r.data.trusted_sender,
            lang:    r.data.language?.code,
        };
        const saveResp = await chrome.runtime.sendMessage({
            type: "phishlens.history.save", entry: historyEntry,
        }).catch(() => null);
        const savedId = saveResp?.id;
        pllAttachFeedback(emailView, r.data, { historyId: savedId, source: "gmail", subject, body, links });

        // Pre-fetch explanation in background; banner picks it up on demand.
        // Fast path: check the client-side LIME cache first. If we already
        // ran /explain on this exact payload (same email re-opened, same
        // backend), we skip the ~10 s server round-trip entirely.
        (async () => {
            // Too little text for the text model: no word-level explanation.
            if (r.data.text_agent_used === false) {
                const slot = emailView.querySelector(".pll-banner .pll-banner__tokens");
                if (slot) slot.textContent = t("almost_no_text");
                return;
            }
            let features = null;
            let cached = false;

            try {
                const backendBase = await PhishLensShared.getBackendBase();
                const hit = await window.PhishLensLimeCache?.get(backendBase, payload);
                if (hit) {
                    features = hit.features;
                    cached = true;
                }
            } catch {}

            if (!features) {
                const rr = await chrome.runtime.sendMessage({
                    type: "phishlens.explain", payload,
                }).catch(() => null);
                if (!rr?.ok) return;
                features = rr.data.features || [];
                // Persist to the LIME cache for the next scan of this email.
                try {
                    const backendBase = await PhishLensShared.getBackendBase();
                    window.PhishLensLimeCache?.put(backendBase, payload, features);
                } catch {}
            }

            attachExplanation(emailView, features, cached);
            if (savedId) {
                const tokens = features.slice(0, 5).map((f) => ({
                    token: f.token || f[0] || "",
                    weight: f.weight || f[1] || 0,
                }));
                chrome.runtime.sendMessage({
                    type: "phishlens.history.attachTokens",
                    id: savedId, tokens,
                }).catch(() => {});
            }
        })();
    } catch (e) {
        const errMsg = String(e?.message || e);
        // Friendlier message when the extension was reloaded while this Gmail
        // tab was already open: the only fix is a page refresh.
        const friendly = /context invalidated|message port closed/i.test(errMsg)
            ? t("reloaded")
            : errMsg;
        showBanner(emailView, { verdict: "error", error: friendly });
    } finally {
        setBtnLoading(btn, false);
    }
}


// Gmail's per-account token, needed by its own URLs. It is in an inline
// script of the page (var GLOBALS=[...], 10th value); content scripts
// cannot read page variables but can read script text.
let _pllIk = null;
function gmailIk() {
    if (_pllIk) return _pllIk;
    for (const sc of document.scripts) {
        const src = sc.textContent || "";
        const i = src.indexOf("var GLOBALS=[");
        if (i < 0) continue;
        const parts = src.slice(i + 13, i + 4000).split(",");
        const v = (parts[9] || "").trim().replace(/^"|"$/g, "");
        if (/^[0-9a-f]{6,20}$/.test(v)) { _pllIk = v; return v; }
    }
    return null;
}

function gmailAccountPath() {
    const m = location.pathname.match(/^\/mail\/u\/\d+/);
    return m ? m[0] : "/mail/u/0";
}

const _PLL_ENTITIES = { "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&amp;": "&" };

// Fetches the raw message behind "Show original" (headers and text
// parts; Gmail leaves attachment bodies out of this view). `ref` is the
// message element (.adn) or { thread: legacyThreadId }. Returns the raw
// text, or null when Gmail does not serve it (layout change, timeout).
async function fetchOriginalMessage(ref) {
    try {
        const ik = gmailIk();
        if (!ik) { console.info(TAG, "full headers: Gmail token not found, using the visible page"); return null; }
        let q;
        if (ref?.thread) {
            q = "th=" + encodeURIComponent(ref.thread);
        } else {
            // Gmail uses several id forms ("msg-f:123…", "msg-a:r123…");
            // the legacy hex id works too, as a thread/message reference.
            const perm = (ref?.getAttribute?.("data-message-id") || "").replace(/^#/, "");
            const legacy = ref?.getAttribute?.("data-legacy-message-id") || "";
            if (/^msg-[a-z]:[a-z]?-?\d+$/.test(perm)) q = "permmsgid=" + encodeURIComponent(perm);
            else if (/^[0-9a-f]{8,20}$/.test(legacy)) q = "th=" + legacy;
            else { console.info(TAG, "full headers: no message id, using the visible page"); return null; }
        }
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 5000);
        // Absolute URL: a relative one is not resolved against the page
        // in every content-script context.
        const resp = await fetch(`${location.origin}${gmailAccountPath()}/?ik=${ik}&view=om&${q}`,
            { credentials: "include", signal: ctrl.signal });
        clearTimeout(timer);
        if (!resp.ok) { console.info(TAG, `full headers: Gmail answered HTTP ${resp.status}`); return null; }
        const html = await resp.text();
        const start = html.indexOf('id="raw_message_text"');
        if (start < 0) { console.info(TAG, "full headers: unexpected page layout, using the visible page"); return null; }
        const open = html.indexOf(">", start);
        const close = html.indexOf("</pre>", open);
        if (open < 0 || close < 0) return null;
        const raw = html.slice(open + 1, close)
            .replace(/&(?:lt|gt|quot|#39|amp);/g, (e) => _PLL_ENTITIES[e]);
        // Sanity check: it must look like an RFC 822 message.
        if (!/^(?:from|received|delivered-to|return-path):/im.test(raw.slice(0, 20000))) {
            console.info(TAG, "full headers: content is not an email, using the visible page");
            return null;
        }
        // Messages you sent (or drafts) have no delivery headers: nothing
        // to verify, and they would look odd to the sender checks.
        const headerEnd = raw.search(/\r?\n\r?\n/);
        if (!/^Received:/im.test(raw.slice(0, headerEnd > 0 ? headerEnd : 20000))) {
            console.info(TAG, "full headers: no delivery headers (a message you sent?), using the visible page");
            return null;
        }
        return raw.slice(0, 2 * 1024 * 1024);
    } catch (e) {
        console.info(TAG, "full headers: fetch failed, using the visible page:", String(e?.message || e));
        return null;
    }
}

// ---------------------------------------------------------------------
// Gmail's own auth signals: mailed-by / signed-by / via / in-inbox.
// ---------------------------------------------------------------------
// Gmail runs its own SPF/DKIM/DMARC checks on every incoming message and
// exposes the results in the "expanded header" panel (the small ▾ next to
// the recipient). Even when that panel is collapsed, the DOM still contains
// the underlying rows, we just look them up by their visible labels
// ("mailed-by", "signed-by"). Also picks up the inline "via foo.com" hint
// that appears next to the sender when the SPF/return-path domain differs.
//
// Robust to Gmail's obfuscated class names, we match on visible text
// rather than a specific class, so this survives Gmail redesigns.
async function extractGmailAuthSignals(emailView, msg = null) {
    const out = { signedBy: null, mailedBy: null, via: null, inInbox: false };

    // 1. Detect "in inbox" by looking at the URL: Gmail routes inbox to
    //    "#inbox/<msg-id>". Spam / trash are also possible; we just care
    //    that it wasn't filtered.
    try {
        const hash = String(window.location.hash || "").toLowerCase();
        out.inInbox = !(hash.includes("spam") || hash.includes("trash"));
    } catch {}

    // 2. Scrape the whole document for mailed-by / signed-by rows. Gmail
    //    lazy-loads them behind a triangle button; if the user hasn't
    //    opened the details panel we won't find them, but that's fine:
    //    the backend has a soft-verification fallback when only
    //    gmail_in_inbox=true is available. Auto-clicking the toggle was
    //    tried but is visually intrusive (the panel visibly spawns every
    //    time the user hits Scan), so we don't do it anymore. If the user
    //    happens to have the details open, we'll catch it here.
    //    In a conversation, the rows of the scanned message are preferred
    //    so another message's details cannot be picked up.
    try {
        if (msg) _scrapeAuthRows(msg, out);
        if (!out.signedBy && !out.mailedBy) _scrapeAuthRows(document.body, out);
    } catch {}

    // 3. The inline "via <domain>" indicator shown when SPF path differs
    //    from From:. Structure varies but we can look for a span whose text
    //    is "via" followed by a text node with the domain.
    try {
        const viaCandidates = (msg || emailView).querySelectorAll("span");
        for (const el of viaCandidates) {
            const txt = (el.textContent || "").trim().toLowerCase();
            const m = txt.match(/^via\s+([a-z0-9.-]+\.[a-z]{2,})$/i);
            if (m) { out.via = m[1]; break; }
        }
    } catch {}

    return out;
}

// --- helpers for the DOM scrape ---
// The labels of the details panel in the languages of the Gmail interface
// PhishLens supports (lower case, without the final colon). Only a
// fallback: with "Full headers" on, the real Authentication-Results
// header is read instead, whatever the interface language.
const GMAIL_MAILED_BY = new Set([
    "mailed-by", "envoyé par", "enviado por", "gesendet von", "inviato da", "verzonden door",
]);
const GMAIL_SIGNED_BY = new Set([
    "signed-by", "signé par", "firmado por", "assinado por", "signiert von", "firmato da",
    "ondertekend door",
]);

function _authLabel(text) {
    return text.trim().toLowerCase().replace(/\s*:$/, "");
}

function _scrapeAuthRows(emailView, out) {
    const nodes = emailView.querySelectorAll("td, span, div");
    for (const el of nodes) {
        const raw = el.textContent || "";
        if (!raw || raw.length > 40) continue;
        const label = _authLabel(raw);
        const kind = GMAIL_MAILED_BY.has(label) ? "mailedBy" : GMAIL_SIGNED_BY.has(label) ? "signedBy" : null;
        if (!kind) continue;
        const val = el.nextElementSibling?.textContent?.trim();
        if (val && /\./.test(val) && !/\s/.test(val)) out[kind] = val;
    }
}
