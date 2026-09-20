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

// =====================================================================
// v1.8 — attachment scanning (PDF, HTML for Phase 1).
// =====================================================================
// Gmail renders each attachment as an anchor with a download attribute
// pointing to its per-attachment fetch URL. Since we run in the Gmail
// page context, a same-origin fetch on that URL sends the session
// cookies automatically — no need to shuttle through the background
// service worker just to authenticate.
//
// UX:
//   - one "🛡 Scan" pill per supported attachment, injected next to the
//     download control
//   - if the mail has >1 supported attachment we ALSO inject a header
//     button that scans all of them sequentially
//   - each scan produces a mini-banner right below the attachment tile,
//     using the same colour language as the main verdict banner
// =====================================================================

const ATT_MAX          = 15;                   // hard limit per mail
const ATT_MAX_SIZE_MB  = 10;
const ATT_SUPPORTED    = new Set(["pdf", "html", "htm"]);
const ATT_HOOKED       = new WeakSet();

// Gmail attachment strip container. Everything below must be scoped
// to an .aQH (or .aQe / .hq in older layouts) — the strip is the ONLY
// place attachments live, so scanning outside of it is what caused
// orphan "Scan" buttons to appear over random spans in the message body
// or sidebar.
const ATT_STRIP_SEL = '.aQH, .aQe, .hq';

// Tile-level selectors — must all be scoped to a strip when queried.
const ATT_TILE_HINT_SELECTORS_IN_STRIP = [
    'a[download]',
    'div[data-attachmentid]',
    'div[data-tooltip*="oad"]',              // 'Download' / 'Télécharger le fichier'
    'div[role="listitem"]',
    '.aZo',                                   // classic Gmail attachment tile
];

// A dedicated debounced observer for attachment tiles — they can
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
    // is out of bounds — this is what prevented orphan "Scan" buttons
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
        // Constrain the tile walk to the enclosing strip — otherwise
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

        // Sanity check — a real Gmail attachment tile is between roughly
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

    // Single central button — no per-tile pills. Way cleaner visually,
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
    // No strong match — walk up again looking for role="listitem" but
    // stop at the strip boundary.
    cur = node;
    while (cur && cur !== strip && cur !== document.body) {
        if (cur.matches?.('[role="listitem"]')) return cur;
        cur = cur.parentElement;
    }
    // Last resort — the node itself (if it's not the strip)
    return (node !== strip) ? node : null;
}

// Given a tile, extract the filename, extension, and best downloadable
// anchor. Returns null when the tile doesn't look like a supported
// attachment.
function _extractAttachmentInfo(tile) {
    // 1. Filename — prefer an `a[download]` value, else fall back to the
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

    // Strip trailing size text — Gmail sometimes suffixes tile text with
    // "Checklist.pdf 320 KB". Keep only the first .ext-ending chunk.
    const extMatch = filename.match(/([\w \-\.\(\)]+\.(pdf|html?|htm))/i);
    if (extMatch) filename = extMatch[1].trim();

    const ext = (filename.split(".").pop() || "").toLowerCase();
    if (!ATT_SUPPORTED.has(ext)) return null;

    // 2. Anchor — anything inside the tile with an href we can fetch.
    const anchor = dlAnchor
        || tile.querySelector('a[href*="&view=att"], a[href*="ui=2"]')
        || tile.querySelector("a[href]");

    return { filename, ext, anchor };
}

function installScanAllButton(emailView, targets) {
    // Idempotent — install once per email view. If a previous pass
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
    btn.innerHTML = `<span class="pll-scan-btn__icon">📎</span>` +
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
        labelEl.textContent = "✓ Scanned";
        setTimeout(() => btn.remove(), 2500);
    });
    wrap.appendChild(btn);
}

// Fetch the attachment, base64-encode it, POST to /analyse_attachment
// via the background service worker (CSP-bypass proxy).
async function scanOneAttachment({ anchor, filename, ext, tile, emailView, btn }) {
    // Banner placement — Gmail's attachment tiles have their own font
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
    banner.innerHTML = `<span>⏳ Downloading and analyzing <strong>${escapeHTML(filename)}</strong>…</span>`;
    // Drop the Scan pill immediately when the loading banner shows —
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
        if (!url) throw new Error("Could not find the attachment download URL — try refreshing Gmail");

        // Same-origin fetch — Gmail's session cookie is sent automatically.
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
                mime_type: (ext === "pdf") ? "application/pdf"
                         : (ext === "html" || ext === "htm") ? "text/html"
                         : null,
                parent_email: {
                    sender_email:    senderEl?.getAttribute("email") || null,
                    subject:         emailView.querySelector(SUBJECT_SEL)?.textContent?.trim() || null,
                    // The mail is currently open in this Gmail account's
                    // Inbox — SPF/DKIM/DMARC already passed on Google's
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
    } catch (e) {
        banner.className = "pll-att-banner pll-att-banner--error";
        banner.innerHTML = `
            <span>❌ ${escapeHTML(filename)}: ${escapeHTML(e.message || String(e))}</span>
            <button type="button" class="pll-att-btn" style="margin-left:8px">Retry</button>
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
        chips.push(`<span class="pll-att-chip pll-att-chip--good" title="Parent email is Gmail-delivered — softer weights applied">📬 Parent trusted</span>`);
    }
    (data.attachment?.notable_features || []).forEach((f) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--warn">${escapeHTML(f.replace(/_/g, " "))}</span>`);
    });
    (data.url_reputation?.sources_hit || []).forEach((s) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--bad">🔴 ${escapeHTML(s)}</span>`);
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
            <span class="pll-att-banner__icon">${bad ? "⚠" : "✓"}</span>
            <div class="pll-att-banner__main">
                <div class="pll-att-banner__title" title="${escapeHTML(filename)}">
                    ${bad ? "Phishing" : "Safe"}
                </div>
                <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div>
            </div>
        </div>
        <div class="pll-att-banner__sub">
            ${meta ? `${escapeHTML(meta)}<br>` : ""}
            Content <strong>${pct(data.agents?.text?.phishing_probability)}%</strong> ·
            Links <strong>${pct(data.agents?.url?.phishing_probability)}%</strong>
        </div>
        ${chips.length ? `<div class="pll-att-banner__chips">${chips.join("")}</div>` : ""}
    `;
}

// Find or create a container to stack attachment banners. Instead of
// walking the DOM looking for a "nice" parent (fragile — Gmail changes
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
