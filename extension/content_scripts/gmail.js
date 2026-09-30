// =====================================================================
// PhishLens content script: Gmail.
// =====================================================================
// Gmail is a single-page app whose DOM constantly changes. We:
//   1. Observe document.body for the appearance of an open email.
//   2. Inject a "Scan with PhishLens" button next to the subject.
//   3. On click, extract the visible message body + sender, send to the
//      background worker which calls the local backend, and render a
//      verdict banner above the email.
// =====================================================================

const TAG = "[PhishLens]";

// Inline SVG icons (no emoji: they render differently on every OS).
const PLL_ICON = {
    shield: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"/></svg>',
    shieldCheck: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>',
    alert: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>',
    clip: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 11l-8.6 8.6a5 5 0 01-7-7L14 4a3.5 3.5 0 015 5l-8.6 8.6a2 2 0 01-2.8-2.8L15 7.5"/></svg>',
    close: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>',
    spinner: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a9 9 0 109 9"/></svg>',
};

// ---------------------------------------------------------------------
// Theme: read the popup's saved choice and apply to injected UI.
// The popup writes to chrome.storage.local under key "theme".
// ---------------------------------------------------------------------
function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
        document.documentElement.setAttribute("data-phishlens-theme", theme);
    } else {
        document.documentElement.removeAttribute("data-phishlens-theme");
    }
}
chrome.storage?.local?.get(["theme"], (s) => applyTheme(s.theme));
chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area === "local" && changes.theme) applyTheme(changes.theme.newValue);
});

// ---------------------------------------------------------------------
// Detection: which DOM nodes mean "an email view is open"?
// ---------------------------------------------------------------------
// Gmail wraps each open email view in <h2 class="hP">Subject text</h2>.
// We watch for those.
const SUBJECT_SEL  = "h2.hP";
const BODY_SEL     = ".a3s.aiL";          // the message body container
const SENDER_SEL   = ".gD[email]";        // <span class="gD" email="...">Name</span>
const HEADER_BAR   = ".aeF";              // bar at the top of the email view

const PROCESSED = new WeakSet();

// ---------------------------------------------------------------------
// MutationObserver entry point
// ---------------------------------------------------------------------
const obs = new MutationObserver(() => scheduleScan());
obs.observe(document.body, { childList: true, subtree: true });

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
    if (subjectEl.dataset.pllHooked) return;
    subjectEl.dataset.pllHooked = "1";

    const wrap = document.createElement("div");
    wrap.className = "pll-subject-wrap";
    subjectEl.parentNode.insertBefore(wrap, subjectEl);
    wrap.appendChild(subjectEl);

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pll-scan-btn";
    btn.innerHTML = `<span class="pll-scan-btn__icon">${PLL_ICON.shield}</span><span class="pll-scan-btn__label">Scan with PhishLens</span>`;
    btn.title = "Check this email for phishing";
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
async function runScan(emailView, btn) {
    const body   = textOf(emailView.querySelector(BODY_SEL));
    const sender = emailView.querySelector(SENDER_SEL);
    const senderEmail = sender?.getAttribute("email") || "";
    const senderName  = sender?.textContent?.trim() || "";
    const subject = emailView.querySelector(SUBJECT_SEL)?.textContent?.trim() || "";

    if (!body || body.length < 20) {
        // No text to score. Common case: an email that only carries an
        // attachment (an attachment-only email is also a classic phishing
        // lure). Scan the attachments instead of giving up.
        const hasAttachments = !!emailView.querySelector(ATT_STRIP_SEL);
        const attBtn = emailView.querySelector(".pll-scan-btn--all");
        if (hasAttachments) {
            showBanner(emailView, {
                verdict: "error",
                title: "This email has no text, only attachments",
                error: (attBtn ? "PhishLens is scanning the attachments instead: see the results below. "
                               : "See the attachment results below. ") +
                       "Attachment-only emails are a common phishing trick: open the file only if you were expecting it.",
            });
            if (attBtn && !attBtn.disabled) attBtn.click();
        } else {
            showBanner(emailView, {
                verdict: "error",
                title: "Nothing to scan in this email",
                error: "The body is empty or too short to analyse. If the email is still loading, open it fully and scan again.",
            });
        }
        return;
    }

    setBtnLoading(btn, true);
    try {
        // Gmail already ran SPF/DKIM/DMARC before delivering: surface its
        // verdict from the DOM so the backend can apply the crypto_verified
        // discount even when we only have raw_text (no Authentication-Results
        // header to parse). Gmail lazy-loads the mailed-by / signed-by rows,
        // so we have to programmatically toggle the "details" panel to get
        // them into the DOM before scraping.
        const gmailAuth = await extractGmailAuthSignals(emailView);

        // Send the body as raw_text and the sender separately so the backend
        // can run the trusted-domain check.
        const payload = {
            raw_text: body.slice(0, 4000),
            sender_email: senderEmail || null,
            client_context: {
                origin: "gmail",
                gmail_signed_by: gmailAuth.signedBy,
                gmail_mailed_by: gmailAuth.mailedBy,
                gmail_via:       gmailAuth.via,
                gmail_in_inbox:  gmailAuth.inInbox,
                // Real link targets: innerText only has the visible link
                // text ("Click here"), not where the link goes.
                link_urls:       linkTargetsOf(emailView.querySelector(BODY_SEL)),
            },
        };

        const r = await chrome.runtime.sendMessage({
            type: "phishlens.analyse", payload,
        });
        if (!r?.ok) throw new Error(r?.error || "Unknown error");
        showBanner(emailView, r.data);

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
        };
        const saveResp = await chrome.runtime.sendMessage({
            type: "phishlens.history.save", entry: historyEntry,
        }).catch(() => null);
        const savedId = saveResp?.id;

        // Pre-fetch explanation in background; banner picks it up on demand.
        // Fast path: check the client-side LIME cache first. If we already
        // ran /explain on this exact payload (same email re-opened, same
        // backend), we skip the ~10 s server round-trip entirely.
        (async () => {
            let features = null;
            let cached = false;

            try {
                const backendBase = await _getBackendBase();
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
                    const backendBase = await _getBackendBase();
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
        const msg = String(e?.message || e);
        // Friendlier message when the extension was reloaded while this Gmail
        // tab was already open: the only fix is a page refresh.
        const friendly = /context invalidated|message port closed/i.test(msg)
            ? "PhishLens was just reloaded: please refresh this Gmail tab to reconnect."
            : msg;
        showBanner(emailView, { verdict: "error", error: friendly });
    } finally {
        setBtnLoading(btn, false);
    }
}

function setBtnLoading(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("pll-scan-btn--loading", on);
    btn.querySelector(".pll-scan-btn__icon").innerHTML = on ? PLL_ICON.spinner : PLL_ICON.shield;
    btn.querySelector(".pll-scan-btn__label").textContent =
        on ? "Scanning…" : "Scan again";
}

// Plain-language line under the title. When the verdict is safe but some
// agent scored high, say why the high score did not count, otherwise the
// red meters under a "looks safe" title read as a contradiction.
function bannerLead(data, phishing) {
    if (phishing) {
        return "Don't click its links, open its attachments or reply until you have checked the sender another way.";
    }
    const high = ["text", "url", "metadata"].some((k) => (data.agents?.[k]?.phishing_probability || 0) >= 0.7);
    if (high) {
        if (data.trust_path === "trusted_sender" || data.trusted_sender) {
            return "Some wording or links resemble phishing, but the sender is on the trusted list, so they weigh less.";
        }
        if (data.trust_path === "crypto_verified") {
            return "Some wording or links resemble phishing, but the sender is proven by DKIM, so they weigh less.";
        }
        if (data.trust_path === "gmail_inbox_soft") {
            return "Some wording or links resemble phishing, but Gmail verified the sender before delivery, so they weigh less.";
        }
        return "One signal looks suspicious, but not enough overall. Stay careful with this one.";
    }
    return "No strong phishing signals. Stay careful with unexpected requests for money or passwords.";
}

// One compact meter per agent: label, bar, percentage.
function pllMeter(label, value) {
    const p = Math.max(0, Math.min(100, Number(value) || 0));
    const level = p >= 70 ? "high" : p >= 40 ? "mid" : "low";
    return `<div class="pll-meter" title="${escapeHTML(label)}: ${p}% phishing">
        <span class="pll-meter__l">${escapeHTML(label)}</span>
        <span class="pll-meter__track"><span class="pll-meter__fill pll-meter__fill--${level}" style="width:${p}%"></span></span>
        <span class="pll-meter__v">${p}%</span>
    </div>`;
}

// ---------------------------------------------------------------------
// Render the verdict banner above the email body
// ---------------------------------------------------------------------
function showBanner(emailView, data) {
    let banner = emailView.querySelector(":scope > .pll-banner") ||
                 emailView.querySelector(".pll-banner");
    if (banner) banner.remove();

    banner = document.createElement("div");
    banner.className = "pll-banner";

    if (data.verdict === "error") {
        banner.classList.add("pll-banner--error");
        banner.innerHTML = `
            <span class="pll-banner__icon">${PLL_ICON.alert}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__title">${escapeHTML(data.title || "PhishLens could not scan this email")}</div>
              <div class="pll-banner__lead">${escapeHTML(data.error || "")}</div>
            </div>
            <button type="button" class="pll-banner__close" title="Dismiss" aria-label="Dismiss">${PLL_ICON.close}</button>`;
    } else {
        const phishing = data.verdict === "phishing";
        banner.classList.add(phishing ? "pll-banner--danger" : "pll-banner--safe");
        const text   = pct(data.agents?.text?.phishing_probability);
        const url    = pct(data.agents?.url?.phishing_probability);
        const meta   = pct(data.agents?.metadata?.phishing_probability);
        // Trust pill: allowlist > DKIM alignment > Gmail-inbox-soft > nothing.
        const cryptoVerified   = !!data.sender_auth?.cryptographically_verified;
        const gmailSoftVerified = !!data.sender_auth?.gmail_inbox_soft_verified;
        let trustedBadge = "";
        if (data.trusted_sender) {
            trustedBadge = `<span class="pll-trusted" title="Sender domain is in the verified allowlist (${escapeHTML(data.sender_domain || "")})">Trusted sender</span>`;
        } else if (cryptoVerified) {
            const spf = data.sender_auth?.spf || "none";
            const dkim = data.sender_auth?.dkim || "none";
            const dmarc = data.sender_auth?.dmarc || "none";
            trustedBadge = `<span class="pll-trusted" title="DKIM signature aligned with From: ${escapeHTML(data.sender_domain || "")}, SPF=${escapeHTML(spf)} DKIM=${escapeHTML(dkim)} DMARC=${escapeHTML(dmarc)}">DKIM verified</span>`;
        } else if (gmailSoftVerified) {
            trustedBadge = `<span class="pll-trusted" title="Gmail delivered this to Inbox, so its own SPF/DKIM/DMARC verification passed. Softer signal than a full crypto verification.">Delivered by Gmail</span>`;
        }

        // v1.6: threat-intel signals under the score line.
        const signalChips = renderBannerSignals(data);
        banner.innerHTML = `
            <span class="pll-banner__icon">${phishing ? PLL_ICON.alert : PLL_ICON.shieldCheck}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__head">
                <span class="pll-banner__title">${phishing ? "This email looks like phishing" : "This email looks safe"}</span>
                ${trustedBadge}
              </div>
              <div class="pll-banner__lead">${bannerLead(data, phishing)}</div>
              <div class="pll-meters">
                ${pllMeter("Wording", text)}
                ${pllMeter("Links", url)}
                ${pllMeter("Sender", meta)}
              </div>
              ${signalChips}
              <details class="pll-banner__why">
                <summary>Why this verdict?</summary>
                <p class="pll-banner__hint">Words that pushed the text model the most. Stronger colour means stronger influence; orange points to phishing, green to safe.</p>
                <div class="pll-banner__tokens"><span class="pll-banner__loading">Computing the explanation…</span></div>
              </details>
            </div>
            <button type="button" class="pll-banner__close" title="Dismiss" aria-label="Dismiss">${PLL_ICON.close}</button>`;
    }

    const headerBar = emailView.querySelector(HEADER_BAR);
    if (headerBar && headerBar.parentNode) {
        headerBar.parentNode.insertBefore(banner, headerBar);
    } else {
        const bodyEl = emailView.querySelector(BODY_SEL);
        bodyEl?.parentNode?.insertBefore(banner, bodyEl);
    }

    banner.querySelector(".pll-banner__close")?.addEventListener("click", () => banner.remove());
}

function attachExplanation(emailView, features, cached = false) {
    const slot = emailView.querySelector(".pll-banner .pll-banner__tokens");
    if (!slot) return;
    if (!features.length) {
        slot.textContent = "No salient tokens returned.";
        return;
    }
    // LIME weights are tiny (often < 0.01), so printing them shows "0.00".
    // Show relative influence instead: colour strength scales with the
    // token's weight compared with the strongest one.
    // Single characters and bare numbers ("1", "t") carry no meaning for
    // a reader; keep them out of the display (they stay in the history).
    const shown = features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
    if (!shown.length) { slot.textContent = "No meaningful words to show for this email."; return; }
    const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
    const chips = shown.map((f) => {
        const w = Number(f.weight) || 0;
        const rel = Math.abs(w) / max;
        const cls = f.supports === "phishing" ? "pll-tok--phishing" : "pll-tok--safe";
        return `<span class="pll-tok ${cls}" style="--pll-a:${(0.10 + rel * 0.35).toFixed(2)}" ` +
               `title="Pushes toward ${escapeHTML(f.supports)} (${Math.round(rel * 100)}% of the strongest word)">${escapeHTML(f.token)}</span>`;
    }).join("");
    slot.innerHTML = cached
        ? chips + '<span class="pll-cache-hint" title="Explanation served from the local cache, no server call">cached</span>'
        : chips;
}

// ---------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------
function textOf(el) {
    if (!el) return "";
    return el.innerText.replace(/\s+\n/g, "\n").trim();
}
// http(s) targets of the links in the message body, deduplicated, max 50.
function linkTargetsOf(el) {
    if (!el) return [];
    const out = new Set();
    for (const a of el.querySelectorAll("a[href]")) {
        const href = a.href || "";
        if (/^https?:\/\//i.test(href) && href.length <= 2048) out.add(href);
        if (out.size >= 50) break;
    }
    return [...out];
}
function pct(p) { return p == null ? "n/a" : Math.round(p * 100); }

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
async function extractGmailAuthSignals(emailView) {
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
    try {
        _scrapeAuthRows(document.body, out);
    } catch {}

    // 3. The inline "via <domain>" indicator shown when SPF path differs
    //    from From:. Structure varies but we can look for a span whose text
    //    is "via" followed by a text node with the domain.
    try {
        const viaCandidates = emailView.querySelectorAll("span");
        for (const el of viaCandidates) {
            const t = (el.textContent || "").trim().toLowerCase();
            const m = t.match(/^via\s+([a-z0-9.-]+\.[a-z]{2,})$/i);
            if (m) { out.via = m[1]; break; }
        }
    } catch {}

    return out;
}

// --- helpers for the DOM scrape ---
function _scrapeAuthRows(emailView, out) {
    const nodes = emailView.querySelectorAll("td, span, div");
    for (const el of nodes) {
        const t = (el.textContent || "").trim().toLowerCase();
        if (!t) continue;
        if (t === "mailed-by:" || t === "envoyé par :" || t === "envoyé par:") {
            const val = el.nextElementSibling?.textContent?.trim();
            if (val && /\./.test(val)) out.mailedBy = val;
        } else if (t === "signed-by:" || t === "signé par :" || t === "signé par:") {
            const val = el.nextElementSibling?.textContent?.trim();
            if (val && /\./.test(val)) out.signedBy = val;
        }
    }
}

// Resolve the currently-selected backend URL: needed for the LIME cache
// key. Mirrors the resolution logic in background.js so the two agree.
const _BACKEND_PRESETS = {
    local: "http://127.0.0.1:8000",
    cloud: "https://anzouk.duckdns.org",
};
async function _getBackendBase() {
    try {
        const s = await new Promise((r) =>
            chrome.storage.local.get(["backend", "backend_custom_url"], r));
        const choice = s.backend || "local";
        if (choice === "custom") return (s.backend_custom_url || "").replace(/\/$/, "");
        return _BACKEND_PRESETS[choice] || _BACKEND_PRESETS.local;
    } catch {
        return _BACKEND_PRESETS.local;
    }
}

// ---------------------------------------------------------------------
// v1.6: threat-intel signal chips inside the Gmail banner.
// ---------------------------------------------------------------------
const _SOURCE_LABEL_GMAIL = {
    google_safe_browsing: "Google Safe Browsing",
    phishtank:            "PhishTank",
    urlhaus:              "URLhaus",
    spamhaus_dbl:         "Spamhaus DBL",
};

function renderBannerSignals(data) {
    const chips = [];
    const rep = data.url_reputation || {};
    const auth = data.sender_auth || {};

    // URL reputation chips: one per intel source that flagged.
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL_GMAIL[src] || src;
            chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(label)} flagged ${rep.malicious_count} URL(s)">Flagged by ${escapeHTML(label)}</span>`);
        }
    } else if (rep.checked > 0) {
        chips.push(`<span class="pll-chip pll-chip--good" title="Every link was checked against the threat-intelligence sources">Links checked, none flagged</span>`);
    }

    // Sender-auth failures worth surfacing prominently.
    if (auth.dmarc === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DMARC check failed: the From: domain does not authorise this sender">DMARC fail</span>`);
    } else if (auth.dkim === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DKIM signature invalid or missing">DKIM fail</span>`);
    } else if (auth.spf === "fail") {
        chips.push(`<span class="pll-chip pll-chip--warn" title="SPF check failed: sender IP not authorised">SPF fail</span>`);
    }

    if (auth.spamhaus_dbl_listed) {
        chips.push(`<span class="pll-chip pll-chip--bad" title="Sender domain is on the Spamhaus block list">Sender on Spamhaus list</span>`);
    }

    if (!chips.length) return "";
    return `<div class="pll-signals">${chips.join(" ")}</div>`;
}
function escapeHTML(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
                    .replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

// =====================================================================
// v1.8: attachment scanning (PDF, HTML for Phase 1).
// =====================================================================
// Gmail renders each attachment as an anchor with a download attribute
// pointing to its per-attachment fetch URL. Since we run in the Gmail
// page context, a same-origin fetch on that URL sends the session
// cookies automatically, no need to shuttle through the background
// service worker just to authenticate.
//
// UX:
//   - one "Scan" pill per supported attachment, injected next to the
//     download control
//   - if the mail has >1 supported attachment we ALSO inject a header
//     button that scans all of them sequentially
//   - each scan produces a mini-banner right below the attachment tile,
//     using the same colour language as the main verdict banner
// =====================================================================

const ATT_MAX          = 15;                   // hard limit per mail
const ATT_MAX_SIZE_MB  = 10;
// v1.12: images (OCR + QR) and Office documents (macros, links) too.
const ATT_SUPPORTED    = new Set(["pdf", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "docx", "docm", "doc", "xlsx", "xlsm", "xls", "pptx", "pptm", "ppt"]);
// Longest extensions first so "html" wins over "htm" in the regex.
const ATT_EXT_RE       = new RegExp(
    "([\\w \\-.()]+\\.(" + [...ATT_SUPPORTED].sort((a, b) => b.length - a.length).join("|") + "))",
    "i");
const ATT_HOOKED       = new WeakSet();

// Gmail attachment strip container. Everything below must be scoped
// to an .aQH (or .aQe / .hq in older layouts): the strip is the ONLY
// place attachments live, so scanning outside of it is what caused
// orphan "Scan" buttons to appear over random spans in the message body
// or sidebar.
const ATT_STRIP_SEL = '.aQH, .aQe, .hq';

// Tile-level selectors: must all be scoped to a strip when queried.
const ATT_TILE_HINT_SELECTORS_IN_STRIP = [
    'a[download]',
    'div[data-attachmentid]',
    'div[data-tooltip*="oad"]',              // 'Download' / 'Télécharger le fichier'
    'div[role="listitem"]',
    '.aZo',                                   // classic Gmail attachment tile
];

// A dedicated debounced observer for attachment tiles; they can
// appear AFTER the email opens (Gmail lazy-loads them) so we can't
// rely on the main injectIfNeeded() pass. Re-scans every open email
// view whenever the DOM settles.
let _attScanQueued = false;
const _attObs = new MutationObserver(() => {
    if (_attScanQueued) return;
    _attScanQueued = true;
    setTimeout(() => {
        _attScanQueued = false;
        document.querySelectorAll('div[role="main"]').forEach((view) => {
            try { installAttachmentButtons(view); } catch (e) {
                console.warn(TAG, "attachment scan failed:", e);
            }
        });
    }, 400);
});
_attObs.observe(document.body, { childList: true, subtree: true });

function installAttachmentButtons(emailView) {
    if (!emailView) return;

    // Attachments only live inside an attachment strip. Everything else
    // is out of bounds; this is what prevented orphan "Scan" buttons
    // from appearing over random spans in the message body / sidebar.
    const strips = emailView.querySelectorAll(ATT_STRIP_SEL);
    if (!strips.length) return;

    const candidates = new Set();
    strips.forEach((strip) => {
        // Try each tile-shape hint inside this strip.
        for (const sel of ATT_TILE_HINT_SELECTORS_IN_STRIP) {
            strip.querySelectorAll(sel).forEach((el) => candidates.add(el));
        }
        // Fallback: any element inside the strip whose text ends with
        // a supported extension (Gmail sometimes doesn't use any of
        // the classes above in newer redesigns).
        strip.querySelectorAll("span, div").forEach((el) => {
            const t = (el.textContent || "").trim();
            if (t.length > 3 && t.length < 260) {
                const ext = (t.split(".").pop() || "").toLowerCase();
                if (ATT_SUPPORTED.has(ext)) candidates.add(el);
            }
        });
    });

    const found = [];
    const seenTiles = new Set();
    candidates.forEach((el) => {
        // Constrain the tile walk to the enclosing strip, otherwise
        // .closest('[role="listitem"]') can escape past .aQH and match
        // the whole-message container that Gmail also marks as
        // role="listitem" in the thread view. That's what caused the
        // orphan "Scan" button below the attachment banners.
        const strip = el.closest(ATT_STRIP_SEL);
        if (!strip) return;

        const tile = _findAttachmentTile(el, strip);
        if (!tile || ATT_HOOKED.has(tile) || seenTiles.has(tile)) return;
        // Belt & braces: reject anything that ended up outside the strip
        // or already scanned (attachment banner is now the source of truth).
        if (!strip.contains(tile)) return;
        if (tile.dataset.pllScanned === "1") return;
        seenTiles.add(tile);

        // Sanity check: a real Gmail attachment tile is between roughly
        // 100x80 and 350x280 px. Anything smaller is a stray hit and
        // anything much bigger is a container we shouldn't hook.
        const r = tile.getBoundingClientRect();
        if (r.width < 80 || r.height < 60 || r.width > 400 || r.height > 400) return;

        const info = _extractAttachmentInfo(tile);
        if (!info) return;
        if (!ATT_SUPPORTED.has(info.ext)) return;
        ATT_HOOKED.add(tile);
        found.push({ tile, ...info, emailView });
    });

    if (!found.length) return;

    // Single central button, no per-tile pills. Way cleaner visually,
    // no alignment mismatch between the tile row and the banner grid.
    installScanAllButton(emailView, found);
}

// Walk up from a node until we hit something that looks like an
// attachment tile boundary, but NEVER past `strip` (the .aQH container).
// Without the strip clamp, closest() would happily walk out of the
// attachment area and grab a whole-message row (which Gmail also marks
// as role="listitem" in thread view).
function _findAttachmentTile(node, strip) {
    const selector = '.aZo, [data-attachmentid], .aQw';   // strong tile hints only
    let cur = node;
    while (cur && cur !== strip && cur !== document.body) {
        if (cur.matches?.(selector)) return cur;
        cur = cur.parentElement;
    }
    // No strong match: walk up again looking for role="listitem" but
    // stop at the strip boundary.
    cur = node;
    while (cur && cur !== strip && cur !== document.body) {
        if (cur.matches?.('[role="listitem"]')) return cur;
        cur = cur.parentElement;
    }
    // Last resort: the node itself (if it's not the strip)
    return (node !== strip) ? node : null;
}

// Given a tile, extract the filename, extension, and best downloadable
// anchor. Returns null when the tile doesn't look like a supported
// attachment.
function _extractAttachmentInfo(tile) {
    // 1. Filename: prefer an `a[download]` value, else fall back to the
    //    first .aV3-ish span, else the tile's visible text.
    let filename = "";
    const dlAnchor = tile.querySelector("a[download]");
    if (dlAnchor && dlAnchor.getAttribute("download")) {
        filename = dlAnchor.getAttribute("download").trim();
    }
    if (!filename) {
        const nameSpan = tile.querySelector(".aV3, .aQw, .aQA, .a1V");
        if (nameSpan) filename = (nameSpan.textContent || "").trim();
    }
    if (!filename) {
        // last resort: the tile's own text (short first line)
        const txt = (tile.textContent || "").trim().split("\n")[0].trim();
        if (txt.length < 260) filename = txt;
    }
    if (!filename || filename.length > 260) return null;

    // Strip trailing size text: Gmail sometimes suffixes tile text with
    // "Checklist.pdf 320 KB". Keep only the first .ext-ending chunk.
    const extMatch = filename.match(ATT_EXT_RE);
    if (extMatch) filename = extMatch[1].trim();

    const ext = (filename.split(".").pop() || "").toLowerCase();
    if (!ATT_SUPPORTED.has(ext)) return null;

    // 2. Anchor: anything inside the tile with an href we can fetch.
    const anchor = dlAnchor
        || tile.querySelector('a[href*="&view=att"], a[href*="ui=2"]')
        || tile.querySelector("a[href]");

    return { filename, ext, anchor };
}

function installScanAllButton(emailView, targets) {
    // Idempotent: install once per email view. If a previous pass
    // already installed the button with a different attachment count
    // (Gmail lazy-loaded more tiles), update the label instead of
    // duplicating.
    const existing = emailView.querySelector(".pll-scan-btn--all");
    if (existing) {
        const label = existing.querySelector(".pll-scan-btn__label");
        if (label && !existing.disabled) {
            label.textContent = targets.length > 1
                ? `Scan ${targets.length} attachments`
                : "Scan attachment";
        }
        existing._pllTargets = targets;
        return;
    }

    const subjectEl = emailView.querySelector(SUBJECT_SEL);
    const wrap = subjectEl?.parentElement;
    if (!wrap) return;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pll-scan-btn pll-scan-btn--all";
    btn._pllTargets = targets;
    btn.innerHTML = `<span class="pll-scan-btn__icon">${PLL_ICON.clip}</span>` +
                    `<span class="pll-scan-btn__label">${
                        targets.length > 1
                            ? `Scan ${targets.length} attachments`
                            : "Scan attachment"
                    }</span>`;
    btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();

        // Use the latest target list (may have been updated by a later
        // MutationObserver pass if more tiles lazy-loaded).
        const currentTargets = btn._pllTargets || targets;

        if (currentTargets.length >= 5 &&
            !confirm(`This will scan ${currentTargets.length} attachments one at a time. ` +
                     `On a CPU-only backend that can take 30–60 seconds total. Continue?`)) {
            return;
        }
        if (currentTargets.length > ATT_MAX) {
            alert(`Too many attachments (${currentTargets.length}). Max ${ATT_MAX} per email.`);
            return;
        }
        btn.disabled = true;
        const labelEl = btn.querySelector(".pll-scan-btn__label");
        for (let i = 0; i < currentTargets.length; i++) {
            labelEl.textContent = currentTargets.length > 1
                ? `Scanning ${i + 1} / ${currentTargets.length}…`
                : "Scanning…";
            try { await scanOneAttachment(currentTargets[i]); } catch {}
        }
        labelEl.textContent = "Attachments scanned";
        setTimeout(() => btn.remove(), 2500);
    });
    wrap.appendChild(btn);
}

// Fetch the attachment, base64-encode it, POST to /analyse_attachment
// via the background service worker (CSP-bypass proxy).
async function scanOneAttachment({ anchor, filename, ext, tile, emailView, btn }) {
    // Banner placement: Gmail's attachment tiles have their own font
    // scaling and flex layout that mangle anything appended inside. We
    // instead find (or create) a dedicated stack container placed AFTER
    // the whole attachment strip, and put one banner per attachment
    // in there.
    const stack = _getAttachmentBannerStack(tile, emailView);
    const bannerId = "pll-att-" + _fileKey(filename);
    let banner = stack.querySelector(`#${CSS.escape(bannerId)}`);
    if (!banner) {
        banner = document.createElement("div");
        banner.id = bannerId;
        banner.className = "pll-att-banner pll-att-banner--loading";
        stack.appendChild(banner);
    }
    banner.className = "pll-att-banner pll-att-banner--loading";
    banner.innerHTML = `<div class="pll-att-banner__row"><span class="pll-att-banner__icon pll-spin">${PLL_ICON.spinner}</span>` +
        `<div class="pll-att-banner__main"><div class="pll-att-banner__title">Scanning…</div>` +
        `<div class="pll-att-banner__file">${escapeHTML(filename)}</div></div></div>`;
    // Drop the Scan pill immediately when the loading banner shows:
    // the banner itself is the ongoing feedback. On error we'll offer
    // a Retry inside the banner rather than resurrect the pill.
    if (tile) {
        tile.querySelectorAll(".pll-att-btn").forEach((el) => el.remove());
    } else if (btn && btn.isConnected) {
        btn.remove();
    }

    try {
        // Resolve a download URL. Gmail lazy-loads the download anchor
        // on hover, so if we don't have one, dispatch a mouseover to
        // reveal it, wait a beat, then re-scan the tile.
        let url = anchor?.href || "";
        if (!url && tile) {
            tile.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
            await new Promise((r) => setTimeout(r, 200));
            const late = tile.querySelector("a[download], a[href*='view=att']");
            if (late) url = late.href;
        }
        if (!url) throw new Error("Could not find the attachment download URL: try refreshing Gmail");

        // Same-origin fetch: Gmail's session cookie is sent automatically.
        const resp = await fetch(url, { credentials: "include" });
        if (!resp.ok) throw new Error(`Download failed (HTTP ${resp.status})`);
        const buf = await resp.arrayBuffer();
        if (buf.byteLength > ATT_MAX_SIZE_MB * 1024 * 1024) {
            throw new Error(`File too large (${(buf.byteLength / 1024 / 1024).toFixed(1)} MB, max ${ATT_MAX_SIZE_MB} MB)`);
        }
        const b64 = arrayBufferToBase64(buf);

        // Route through background for CSP-bypass + backend selection.
        const senderEl = emailView.querySelector(SENDER_SEL);
        const r = await chrome.runtime.sendMessage({
            type: "phishlens.analyse_attachment",
            payload: {
                content_b64: b64,
                filename,
                // The backend sniffs the real type from the bytes; the
                // extension only sends the filename-based hint.
                mime_type: null,
                parent_email: {
                    sender_email:    senderEl?.getAttribute("email") || null,
                    subject:         emailView.querySelector(SUBJECT_SEL)?.textContent?.trim() || null,
                    // The mail is currently open in this Gmail account's
                    // Inbox: SPF/DKIM/DMARC already passed on Google's
                    // side, otherwise it would have landed in Spam.
                    // We forward this to the backend so the attachment
                    // scoring inherits the parent's trust context
                    // (softer weights, higher threshold).
                    gmail_delivered: !window.location.hash.toLowerCase().includes("spam"),
                },
            },
        });
        if (!r?.ok) throw new Error(r?.error || "backend error");
        renderAttachmentBanner(banner, r.data, filename);
        // Mark the tile as scanned so the MutationObserver doesn't
        // resurrect a Scan pill on the next DOM tick.
        if (tile) tile.dataset.pllScanned = "1";

        // Attachment scans go to the local history too, like email scans.
        chrome.runtime.sendMessage({
            type: "phishlens.history.save",
            entry: {
                source:  "gmail-attachment",
                subject: filename,
                sender:  senderEl?.getAttribute("email") || senderEl?.textContent?.trim() || "",
                verdict: r.data.verdict,
                score:   Number(r.data.fused_score) || 0,
                agents: {
                    text: Number(r.data.agents?.text?.phishing_probability) || 0,
                    url:  Number(r.data.agents?.url?.phishing_probability)  || 0,
                    metadata: 0,
                },
                trusted: !!r.data.parent_trusted,
            },
        }).catch(() => {});
    } catch (e) {
        banner.className = "pll-att-banner pll-att-banner--error";
        banner.innerHTML = `
            <div class="pll-att-banner__row"><span class="pll-att-banner__icon">${PLL_ICON.alert}</span>
            <div class="pll-att-banner__main"><div class="pll-att-banner__title">Could not scan</div>
            <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div></div></div>
            <div class="pll-att-banner__sub">${escapeHTML(e.message || String(e))}</div>
            <button type="button" class="pll-att-btn">Retry</button>
        `;
        banner.querySelector("button")?.addEventListener("click", () => {
            scanOneAttachment({ anchor, filename, ext, tile, emailView });
        });
    }
}

function renderAttachmentBanner(banner, data, filename) {
    const bad = data.verdict === "phishing";
    banner.className = "pll-att-banner " + (bad ? "pll-att-banner--danger" : "pll-att-banner--safe");
    const pct = (v) => Math.round((Number(v) || 0) * 100);
    const chips = [];
    if (data.parent_trusted) {
        chips.push(`<span class="pll-att-chip pll-att-chip--good" title="Parent email is Gmail-delivered: softer weights applied">Trusted email</span>`);
    }
    (data.attachment?.notable_features || []).forEach((f) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--warn">${escapeHTML(f.replace(/_/g, " "))}</span>`);
    });
    (data.url_reputation?.sources_hit || []).forEach((s) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--bad">${escapeHTML(_SOURCE_LABEL_GMAIL[s] || s)}</span>`);
    });
    const a = data.attachment || {};
    const meta = [
        a.kind ? a.kind.toUpperCase() : "",
        a.size_bytes ? `${(a.size_bytes / 1024).toFixed(0)} KB` : "",
        a.page_count ? `${a.pages_read || a.page_count} / ${a.page_count} pages` : "",
        a.extracted_urls_count ? `${a.extracted_urls_count} URL${a.extracted_urls_count > 1 ? "s" : ""}` : "",
    ].filter(Boolean).join(" · ");

    banner.innerHTML = `
        <div class="pll-att-banner__row">
            <span class="pll-att-banner__icon">${bad ? PLL_ICON.alert : PLL_ICON.shieldCheck}</span>
            <div class="pll-att-banner__main">
                <div class="pll-att-banner__title" title="${escapeHTML(filename)}">
                    ${bad ? "Looks like phishing" : "Looks safe"}
                </div>
                <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div>
            </div>
        </div>
        <div class="pll-att-banner__sub">
            ${meta ? `${escapeHTML(meta)}<br>` : ""}
            Wording <strong>${pct(data.agents?.text?.phishing_probability)}%</strong> ·
            Links <strong>${pct(data.agents?.url?.phishing_probability)}%</strong>
        </div>
        ${chips.length ? `<div class="pll-att-banner__chips">${chips.join("")}</div>` : ""}
    `;
}

// Find or create a container to stack attachment banners. Instead of
// walking the DOM looking for a "nice" parent (fragile: Gmail changes
// its layout constantly), we anchor to the strip and rely on CSS to
// force the stack to full width regardless of the parent's display
// mode (flex row / grid / whatever). See .pll-att-stack in banner.css.
function _getAttachmentBannerStack(tile, emailView) {
    const strip = (tile && tile.closest(ATT_STRIP_SEL))
               || emailView.querySelector(ATT_STRIP_SEL);
    const anchor = strip || emailView.querySelector(BODY_SEL) || emailView;
    const parent = anchor.parentElement || emailView;

    let stack = parent.querySelector(":scope > .pll-att-stack");
    if (!stack) {
        stack = document.createElement("div");
        stack.className = "pll-att-stack";
        anchor.insertAdjacentElement("afterend", stack);
    }
    return stack;
}

// Deterministic short id from the filename so the same attachment
// updates its own banner instead of appending duplicates on re-scan.
function _fileKey(name) {
    return String(name || "").replace(/[^a-z0-9]+/gi, "-").slice(0, 60).toLowerCase();
}

// Fast base64 encoding of a raw ArrayBuffer without blowing the stack
// on large files.
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunk = 0x8000;
    let binary = "";
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

console.log(TAG, "Gmail content script loaded.");
