// =====================================================================
// PhishLens content script — Gmail.
// =====================================================================
// Gmail is a single-page app whose DOM constantly changes. We:
//   1. Observe document.body for the appearance of an open email.
//   2. Inject a floating "🛡 Scan with PhishLens" button next to the subject.
//   3. On click, extract the visible message body + sender, send to the
//      background worker which calls the local backend, and render a
//      verdict banner above the email.
// =====================================================================

const TAG = "[PhishLens]";

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
    }, 250);                   // debounce — Gmail mutates a LOT
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
    btn.innerHTML = `<span class="pll-scan-btn__icon">🛡</span><span class="pll-scan-btn__label">Scan with PhishLens</span>`;
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
        showBanner(emailView, {
            verdict: "error",
            error: "Could not read the email body — try opening the email fully.",
        });
        return;
    }

    setBtnLoading(btn, true);
    try {
        // Gmail already ran SPF/DKIM/DMARC before delivering — surface its
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
            },
        };

        const r = await chrome.runtime.sendMessage({
            type: "phishlens.analyse", payload,
        });
        if (!r?.ok) throw new Error(r?.error || "Unknown error");
        showBanner(emailView, r.data);

        // Persist this scan in the local history — background.js writes it
        // via the shared history module. We remember the returned id so we
        // can attach LIME tokens to the same entry when /explain resolves.
        const historyEntry = {
            source:  "gmail",
            subject: subject,
            sender:  senderEmail || senderName,
            verdict: r.data.verdict,
            score:   Number(r.data.agents?.text?.phishing_probability) || 0,
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
        // tab was already open — the only fix is a page refresh.
        const friendly = /context invalidated|message port closed/i.test(msg)
            ? "PhishLens was just reloaded — please refresh this Gmail tab to reconnect."
            : msg;
        showBanner(emailView, { verdict: "error", error: friendly });
    } finally {
        setBtnLoading(btn, false);
    }
}

function setBtnLoading(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("pll-scan-btn--loading", on);
    btn.querySelector(".pll-scan-btn__label").textContent =
        on ? "Analyzing…" : "Scan with PhishLens";
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
            <span class="pll-banner__icon">⚠</span>
            <div class="pll-banner__main">
              <div class="pll-banner__title">PhishLens could not scan this email</div>
              <div class="pll-banner__sub">${escapeHTML(data.error || "")}</div>
            </div>`;
    } else {
        const phishing = data.verdict === "phishing";
        banner.classList.add(phishing ? "pll-banner--danger" : "pll-banner--safe");
        const text   = pct(data.agents?.text?.phishing_probability);
        const url    = pct(data.agents?.url?.phishing_probability);
        const meta   = pct(data.agents?.metadata?.phishing_probability);
        // Trust pill — allowlist > DKIM alignment > Gmail-inbox-soft > nothing.
        const cryptoVerified   = !!data.sender_auth?.cryptographically_verified;
        const gmailSoftVerified = !!data.sender_auth?.gmail_inbox_soft_verified;
        let trustedBadge = "";
        if (data.trusted_sender) {
            trustedBadge = `<span class="pll-trusted" title="Sender domain is in the verified allowlist (${escapeHTML(data.sender_domain || "")})">✓ Verified sender</span>`;
        } else if (cryptoVerified) {
            const spf = data.sender_auth?.spf || "none";
            const dkim = data.sender_auth?.dkim || "none";
            const dmarc = data.sender_auth?.dmarc || "none";
            trustedBadge = `<span class="pll-trusted" title="DKIM signature aligned with From: ${escapeHTML(data.sender_domain || "")} — SPF=${escapeHTML(spf)} DKIM=${escapeHTML(dkim)} DMARC=${escapeHTML(dmarc)}">🛡 DKIM verified</span>`;
        } else if (gmailSoftVerified) {
            trustedBadge = `<span class="pll-trusted" title="Gmail delivered this to Inbox — its own SPF/DKIM/DMARC verification passed. Softer signal than a full crypto verification.">📬 Gmail-delivered</span>`;
        }

        // v1.6 — threat-intel signals under the score line.
        const signalChips = renderBannerSignals(data);
        banner.innerHTML = `
            <span class="pll-banner__icon">${phishing ? "⚠" : "✓"}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__title">
                ${phishing ? "This email looks like phishing" : "This email looks safe"}
                ${trustedBadge}
              </div>
              <div class="pll-banner__sub">
                Content <strong>${text}%</strong> &nbsp;·&nbsp;
                Links <strong>${url}%</strong> &nbsp;·&nbsp;
                Sender <strong>${meta}%</strong>
              </div>
              ${signalChips}
              <details class="pll-banner__why">
                <summary>Why?</summary>
                <div class="pll-banner__tokens">Loading LIME explanation…</div>
              </details>
            </div>
            <button type="button" class="pll-banner__close" title="Dismiss">×</button>`;
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
    const chips = features.map((f) => {
        const cls = f.supports === "phishing" ? "pll-tok--phishing" : "pll-tok--safe";
        const w = Math.abs(f.weight).toFixed(2);
        return `<span class="pll-tok ${cls}" title="${f.supports}: ${w}">${escapeHTML(f.token)}<span class="pll-tok__w">${w}</span></span>`;
    }).join("");
    slot.innerHTML = cached
        ? chips + '<span class="pll-cache-hint" title="Explanation served from local cache — no server call needed">⚡ cached</span>'
        : chips;
}

// ---------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------
function textOf(el) {
    if (!el) return "";
    return el.innerText.replace(/\s+\n/g, "\n").trim();
}
function pct(p) { return p == null ? "—" : Math.round(p * 100); }

// ---------------------------------------------------------------------
// Gmail's own auth signals — mailed-by / signed-by / via / in-inbox.
// ---------------------------------------------------------------------
// Gmail runs its own SPF/DKIM/DMARC checks on every incoming message and
// exposes the results in the "expanded header" panel (the small ▾ next to
// the recipient). Even when that panel is collapsed, the DOM still contains
// the underlying rows — we just look them up by their visible labels
// ("mailed-by", "signed-by"). Also picks up the inline "via foo.com" hint
// that appears next to the sender when the SPF/return-path domain differs.
//
// Robust to Gmail's obfuscated class names — we match on visible text
// rather than a specific class, so this survives Gmail redesigns.
async function extractGmailAuthSignals(emailView) {
    const out = { signedBy: null, mailedBy: null, via: null, inInbox: false };

    // 1. Detect "in inbox" by looking at the URL — Gmail routes inbox to
    //    "#inbox/<msg-id>". Spam / trash are also possible; we just care
    //    that it wasn't filtered.
    try {
        const hash = String(window.location.hash || "").toLowerCase();
        out.inInbox = !(hash.includes("spam") || hash.includes("trash"));
    } catch {}

    // 2. Scrape the whole document for mailed-by / signed-by rows. Gmail
    //    lazy-loads them behind a triangle button; if the user hasn't
    //    opened the details panel we won't find them, but that's fine —
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
// Gmail marks the details toggle with aria-label text that varies by locale.
// We match on a set of known labels rather than the (obfuscated) class name.
function _findDetailsToggle(emailView, preferClosed = false) {
    const labels = [
        "show details", "hide details",
        "afficher les détails", "masquer les détails",
        "afficher les informations", "masquer les informations",
        "detalles", "ocultar detalles",
        "detalhes", "mostrar detalhes",
    ];
    // Strategy 1 — aria-label match (works in most locales / Gmail versions)
    let nodes = emailView.querySelectorAll("[aria-label]");
    for (const n of nodes) {
        const al = (n.getAttribute("aria-label") || "").toLowerCase();
        if (labels.some((l) => al.includes(l))) return n;
    }
    // Strategy 2 — Gmail's stable class for the details triangle. It's a
    // <img> or <span> inside a container with class "ajz" / "ajB" / "aju"
    // depending on the version. We fall back to any of these.
    nodes = emailView.querySelectorAll(".ajz, .ajB, .aju, img.ajz, [role='button'] img");
    for (const n of nodes) {
        const rect = n.getBoundingClientRect();
        // Discard huge nodes (avoid clicking a wrong button)
        if (rect.width > 32 || rect.height > 32) continue;
        return n;
    }
    // Strategy 3 — semantic. The details toggle usually sits in the same
    // row as the recipient. Fall back to any clickable child of the
    // sender header that has a triangle-ish icon.
    return null;
}

// Find any Authentication-Results row already in the DOM (either mailed-by
// or signed-by or the localized equivalent). Used to skip the toggle click
// when the info is already accessible.
function _findAuthRow(emailView) {
    const nodes = emailView.querySelectorAll("td, span, div");
    for (const el of nodes) {
        const t = (el.textContent || "").trim().toLowerCase();
        if (t === "mailed-by:" || t === "signed-by:" ||
            t === "envoyé par :" || t === "envoyé par:" ||
            t === "signé par :" || t === "signé par:") {
            return el;
        }
    }
    return null;
}

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

function _nextTick(ms = 0) {
    return new Promise((r) => setTimeout(r, ms));
}

// Resolve the currently-selected backend URL — needed for the LIME cache
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
// v1.6 — threat-intel signal chips inside the Gmail banner.
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

    // URL reputation chips — one per intel source that flagged.
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL_GMAIL[src] || src;
            chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(label)} flagged ${rep.malicious_count} URL(s)">🔴 ${escapeHTML(label)}</span>`);
        }
    } else if (rep.checked > 0) {
        chips.push(`<span class="pll-chip pll-chip--good" title="URL reputation cascade returned clean">✓ Links checked</span>`);
    }

    // Sender-auth failures worth surfacing prominently.
    if (auth.dmarc === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DMARC check failed — the From: domain does not authorise this sender">DMARC fail</span>`);
    } else if (auth.dkim === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DKIM signature invalid or missing">DKIM fail</span>`);
    } else if (auth.spf === "fail") {
        chips.push(`<span class="pll-chip pll-chip--warn" title="SPF check failed — sender IP not authorised">SPF fail</span>`);
    }

    if (auth.spamhaus_dbl_listed) {
        chips.push(`<span class="pll-chip pll-chip--bad" title="Sender domain is on the Spamhaus block list">🔴 Spamhaus listed</span>`);
    }

    if (!chips.length) return "";
    return `<div class="pll-signals">${chips.join(" ")}</div>`;
}
function escapeHTML(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
                    .replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

console.log(TAG, "Gmail content script loaded.");
