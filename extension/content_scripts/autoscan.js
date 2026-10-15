// =====================================================================
// PhishLens content script: Gmail, automatic scanning of new emails.
// =====================================================================
// Opt-in (popup Settings).
// =====================================================================

// =====================================================================
// Automatic scanning of new emails (opt-in, popup Settings)
// =====================================================================
// When the inbox list is on screen, unread emails PhishLens has not seen
// yet are fetched through Gmail's "Show original" (no need to open them)
// and sent to /analyse one at a time. A phishing verdict puts a red
// "Phishing?" pill on the row and raises a desktop notification. Results
// are cached by thread id, so an email is scanned once.
// The version changes with the scoring (v4: multilingual text model):
// verdicts from an earlier version are not reused.
const AUTO_CACHE_KEY = "autoScanCache.v4";
const AUTO_CACHE_MAX = 500;
const AUTO_MAX_PER_PASS = 10;     // stays well under the backend rate limit
const AUTO_DELAY_MS = 1500;       // between two emails
let _autoRunning = false;
let _autoTimer = null;

function scheduleAutoScan() {
    if (!PLL_IS_GMAIL || !PLL_OPTS.autoScan || _autoTimer) return;
    _autoTimer = setTimeout(() => { _autoTimer = null; runAutoScan(); }, 3000);
}

function _autoCacheGet() {
    return new Promise((r) => {
        try { chrome.storage.local.get([AUTO_CACHE_KEY], (s) => r(s?.[AUTO_CACHE_KEY] || {})); }
        catch { r({}); }
    });
}
async function _autoCachePut(id, entry) {
    const cache = await _autoCacheGet();
    cache[id] = entry;
    const ids = Object.keys(cache);
    if (ids.length > AUTO_CACHE_MAX) {
        ids.sort((a, b) => cache[a].ts - cache[b].ts)
           .slice(0, ids.length - AUTO_CACHE_MAX).forEach((k) => delete cache[k]);
    }
    await new Promise((r) => chrome.storage.local.set({ [AUTO_CACHE_KEY]: cache }, r));
    _autoCacheMem = cache;
}
let _autoCacheMem = null;

function _inboxRows() {
    // Only rows of the list on screen (Gmail keeps hidden copies of
    // other views in the DOM).
    return [...document.querySelectorAll("tr.zA")].filter((row) => row.offsetParent !== null).map((row) => ({
        row,
        id: row.querySelector("[data-legacy-thread-id]")?.getAttribute("data-legacy-thread-id") || "",
        unread: row.classList.contains("zE"),
        sender: row.querySelector("span[email]")?.getAttribute("email") || "",
        subject: (row.querySelector(".bog")?.textContent || "").trim(),
    })).filter((r) => /^[0-9a-f]{8,20}$/.test(r.id));
}

function paintAutoBadges() {
    if (!_autoCacheMem || !pllAlive()) return;
    for (const r of _inboxRows()) {
        const hit = _autoCacheMem[r.id];
        if (!hit || (hit.verdict !== "phishing" && hit.verdict !== "safe") || r.row.querySelector(".pll-row-badge")) continue;
        const cell = r.row.querySelector(".bog")?.parentElement;
        if (!cell) continue;
        const bad = hit.verdict === "phishing";
        const b = document.createElement("span");
        b.className = "pll-row-badge" + (bad ? "" : " pll-row-badge--safe");
        const pct = Math.round((hit.score || 0) * 100);
        b.textContent = bad ? t("row_phishing") : t("row_safe");
        b.title = bad ? t("row_phishing_title", { pct }) : t("row_safe_title", { pct });
        cell.prepend(b);
    }
}

// Small status toast, bottom left of Gmail, for the automatic scan.
function autoToast(text, kind = "info", hideAfterMs = 0) {
    let t = document.getElementById("pll-auto-toast");
    if (!t) {
        t = document.createElement("div");
        t.id = "pll-auto-toast";
        t.className = "pll-toast";
        t.setAttribute("role", "status");
        t.innerHTML = `<span class="pll-toast__icon">${PLL_ICON.shield}</span><span class="pll-toast__text"></span>` +
                      `<button type="button" class="pll-toast__close" aria-label="${escapeHTML(t("dismiss"))}">${PLL_ICON.close}</button>`;
        t.querySelector(".pll-toast__close").addEventListener("click", () => t.remove());
        document.body.appendChild(t);
    }
    t.className = `pll-toast pll-toast--${kind}`;
    t.querySelector(".pll-toast__text").textContent = text;
    clearTimeout(t._pllTimer);
    if (hideAfterMs) t._pllTimer = setTimeout(() => t.remove(), hideAfterMs);
}

async function runAutoScan() {
    if (_autoRunning || !PLL_OPTS.autoScan || !pllAlive()) return;
    _autoRunning = true;
    try {
        const cache = await _autoCacheGet();
        _autoCacheMem = cache;
        const todo = _inboxRows().filter((r) => r.unread && !cache[r.id]).slice(0, AUTO_MAX_PER_PASS);
        let done = 0, flagged = 0, failed = false;
        for (const r of todo) {
            if (!PLL_OPTS.autoScan) break;
            autoToast(todo.length > 1
                ? t("auto_checking_n", { i: done + 1, n: todo.length })
                : t("auto_checking_single"));
            const original = await fetchOriginalMessage({ thread: r.id });
            if (!original) { await _autoCachePut(r.id, { verdict: "skipped", ts: Date.now() }); continue; }
            const resp = await chrome.runtime.sendMessage({
                type: "phishlens.analyse",
                payload: {
                    raw_email_b64: utf8ToB64(original),
                    sender_email: r.sender || null,
                    client_context: {
                        origin: "gmail",
                        subject: r.subject,
                        headers_source: "gmail_show_original",
                        gmail_in_inbox: !/spam|trash/i.test(location.hash),
                        auto_scan: true,
                    },
                },
            }).catch(() => null);
            if (!resp?.ok) {
                // Backend down or rate-limited: stop this pass, retry later.
                failed = true;
                break;
            }
            done++;
            const d = resp.data;
            await _autoCachePut(r.id, { verdict: d.verdict, score: Number(d.fused_score) || 0, ts: Date.now() });
            chrome.runtime.sendMessage({
                type: "phishlens.history.save",
                entry: {
                    source: "gmail-auto", subject: r.subject, sender: r.sender,
                    verdict: d.verdict, score: Number(d.fused_score) || 0,
                    agents: {
                        text: Number(d.agents?.text?.phishing_probability) || 0,
                        url: Number(d.agents?.url?.phishing_probability) || 0,
                        metadata: Number(d.agents?.metadata?.phishing_probability) || 0,
                    },
                    trusted: !!d.trusted_sender,
                    lang: d.language?.code,
                },
            }).catch(() => {});
            paintAutoBadges();
            if (d.verdict === "phishing") {
                flagged++;
                chrome.runtime.sendMessage({
                    type: "phishlens.notify",
                    title: t("notify_title"),
                    message: `${r.sender || t("unknown_sender")}: ${r.subject || t("no_subject")}`,
                }).catch(() => {});
            }
            await new Promise((ok) => setTimeout(ok, AUTO_DELAY_MS));
        }
        if (failed) {
            autoToast(t("auto_unreachable"), "warn", 6000);
        } else if (done) {
            const what = tn("auto_done", done);
            if (flagged) autoToast(tn("auto_flagged", flagged, { what }), "danger", 8000);
            else autoToast(t("auto_clean", { what }), "safe", 4000);
        }
    } finally {
        _autoRunning = false;
    }
}
