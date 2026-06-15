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

    if (!body || body.length < 20) {
        showBanner(emailView, {
            verdict: "error",
            error: "Could not read the email body — try opening the email fully.",
        });
        return;
    }

    setBtnLoading(btn, true);
    try {
        // Send the body as raw_text and the sender separately so the backend
        // can run the trusted-domain check.
        const payload = {
            raw_text: body.slice(0, 4000),
            sender_email: senderEmail || null,
        };

        const r = await chrome.runtime.sendMessage({
            type: "phishlens.analyse", payload,
        });
        if (!r?.ok) throw new Error(r?.error || "Unknown error");
        showBanner(emailView, r.data);
        // pre-fetch explanation in background; banner will pick it up on demand
        chrome.runtime.sendMessage({ type: "phishlens.explain", payload })
            .then((rr) => {
                if (rr?.ok) attachExplanation(emailView, rr.data.features || []);
            });
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
        const trustedBadge = data.trusted_sender
            ? `<span class="pll-trusted" title="Sender domain is in the verified allowlist (${escapeHTML(data.sender_domain || "")})">✓ Verified sender</span>`
            : "";
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

function attachExplanation(emailView, features) {
    const slot = emailView.querySelector(".pll-banner .pll-banner__tokens");
    if (!slot) return;
    if (!features.length) {
        slot.textContent = "No salient tokens returned.";
        return;
    }
    slot.innerHTML = features.map((f) => {
        const cls = f.supports === "phishing" ? "pll-tok--phishing" : "pll-tok--safe";
        const w = Math.abs(f.weight).toFixed(2);
        return `<span class="pll-tok ${cls}" title="${f.supports}: ${w}">${escapeHTML(f.token)}<span class="pll-tok__w">${w}</span></span>`;
    }).join("");
}

// ---------------------------------------------------------------------
// utils
// ---------------------------------------------------------------------
function textOf(el) {
    if (!el) return "";
    return el.innerText.replace(/\s+\n/g, "\n").trim();
}
function pct(p) { return p == null ? "—" : Math.round(p * 100); }
function escapeHTML(s) {
    return String(s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
                    .replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

console.log(TAG, "Gmail content script loaded.");
