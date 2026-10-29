// Gmail: automatic scanning of new emails (opt-in, popup Settings).
// While the message list is on screen, unread emails PhishLens has not
// seen are read through "Show original" (without opening them) and sent
// to /analyse one at a time. A phishing verdict puts a "Phishing?" pill
// on the row and raises a desktop notification. Verdicts are cached by
// thread id, so an email is scanned once.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t, tn } = PhishLensI18n;
const { h, icon } = PhishLensDom;
const { debug } = PhishLensShared;
const G = PhishLensGmail;

// The version changes with the scoring: older verdicts are not reused.
const CACHE_KEY = "autoScanCache.v4";
const CACHE_MAX = 500;
const MAX_PER_PASS = 10;     // well under the server's rate limit
const DELAY_MS = 1500;       // between two emails
let running = false;
let timer = null;
let cacheMem = null;

PL.scheduleAutoScan = function scheduleAutoScan() {
    if (!PL.isGmail || !PL.opts.autoScan || timer) return;
    timer = setTimeout(() => { timer = null; runAutoScan(); }, 3000);
};

function cacheGet() {
    return new Promise((resolve) => {
        try {
            chrome.storage.local.get([CACHE_KEY], (s) => resolve(s?.[CACHE_KEY] || {}));
        } catch (e) {
            debug("automatic scan cache", e);
            resolve({});
        }
    });
}

async function cachePut(id, entry) {
    const cache = await cacheGet();
    cache[id] = entry;
    const ids = Object.keys(cache);
    if (ids.length > CACHE_MAX) {
        ids.sort((a, b) => cache[a].ts - cache[b].ts).slice(0, ids.length - CACHE_MAX).forEach((k) => delete cache[k]);
    }
    await new Promise((resolve) => chrome.storage.local.set({ [CACHE_KEY]: cache }, resolve));
    cacheMem = cache;
}

// Rows of the list on screen (Gmail keeps hidden copies of other views).
function inboxRows() {
    const { SEL } = G;
    return [...document.querySelectorAll(SEL.inboxRow)].filter((row) => row.offsetParent !== null).map((row) => ({
        row,
        id: row.querySelector(SEL.rowThreadId)?.getAttribute("data-legacy-thread-id") || "",
        unread: row.classList.contains(SEL.unreadRowClass),
        sender: row.querySelector("span[email]")?.getAttribute("email") || "",
        senderName: row.querySelector("span[email]")?.getAttribute("name") || "",
        subject: (row.querySelector(SEL.rowSubject)?.textContent || "").trim(),
    })).filter((r) => /^[0-9a-f]{8,20}$/.test(r.id));
}

PL.paintAutoBadges = function paintAutoBadges() {
    if (!cacheMem || !PL.alive()) return;
    for (const r of inboxRows()) {
        const hit = cacheMem[r.id];
        if (!hit || (hit.verdict !== "phishing" && hit.verdict !== "safe") || r.row.querySelector(".pll-row-badge")) continue;
        const cell = r.row.querySelector(G.SEL.rowSubject)?.parentElement;
        if (!cell) continue;
        const bad = hit.verdict === "phishing";
        const pct = Math.round((hit.score || 0) * 100);
        cell.prepend(h(`span.pll-row-badge${bad ? "" : ".pll-row-badge--safe"}`,
            { title: t(bad ? "row_phishing_title" : "row_safe_title", { pct }) },
            t(bad ? "row_phishing" : "row_safe")));
    }
};

PL.loadAutoCache = function loadAutoCache() {
    return cacheGet().then((c) => { cacheMem = c; PL.paintAutoBadges(); });
};

// Status toast, bottom left of Gmail.
function toast(text, kind = "info", hideAfterMs = 0) {
    let box = document.getElementById("pll-auto-toast");
    if (!box) {
        box = h("div.pll-toast", { id: "pll-auto-toast", role: "status" },
            h("span.pll-toast__icon", null, icon("shield")),
            h("span.pll-toast__text"),
            h("button.pll-toast__close", { type: "button", "aria-label": t("dismiss"), onclick: () => box.remove() }, icon("close")));
        document.body.appendChild(box);
    }
    box.className = `pll-toast pll-toast--${kind}`;
    box.querySelector(".pll-toast__text").textContent = text;
    clearTimeout(box._pllTimer);
    if (hideAfterMs) box._pllTimer = setTimeout(() => box.remove(), hideAfterMs);
}

async function scanRow(r) {
    const original = await PL.fetchOriginalMessage({ thread: r.id });
    if (!original) {
        await cachePut(r.id, { verdict: "skipped", ts: Date.now() });
        return null;
    }
    const data = await PhishLensApi.analyse({
        raw_email_b64: PL.utf8ToB64(original),
        sender_email: r.sender || null,
        sender_name: r.senderName || null,
        client_context: {
            origin: "gmail",
            subject: r.subject,
            headers_source: "gmail_show_original",
            gmail_in_inbox: G.inInbox(location.hash),
            auto_scan: true,
        },
    });
    await cachePut(r.id, { verdict: data.verdict, score: Number(data.fused_score) || 0, ts: Date.now() });
    PL.saveScan(data, { source: "gmail-auto", subject: r.subject, sender: r.sender });
    PL.paintAutoBadges();
    if (data.verdict === "phishing") {
        PhishLensApi.notify(t("notify_title"), `${r.sender || t("unknown_sender")}: ${r.subject || t("no_subject")}`)
            .catch((e) => debug("notification", e));
    }
    return data;
}

async function runAutoScan() {
    if (running || !PL.opts.autoScan || !PL.alive()) return;
    running = true;
    try {
        // No automatic scan before the privacy notice was seen (it is shown
        // in the popup, where the option is turned on, and before the
        // first manual scan).
        const notice = await new Promise((r) => chrome.storage.local.get(["privacy_notice_seen", "backend"], (v) => r(v || {})));
        if (!notice.privacy_notice_seen && (!notice.backend || notice.backend === "cloud")) return;
        const cache = await cacheGet();
        cacheMem = cache;
        const todo = inboxRows().filter((r) => r.unread && !cache[r.id]).slice(0, MAX_PER_PASS);
        let done = 0, flagged = 0;
        for (const r of todo) {
            if (!PL.opts.autoScan) break;
            toast(todo.length > 1 ? t("auto_checking_n", { i: done + 1, n: todo.length }) : t("auto_checking_single"));
            let data;
            try {
                data = await scanRow(r);
            } catch (e) {
                // Server down or rate-limited: stop this pass, retry on the next one.
                debug("automatic scan stopped", e);
                toast(t("auto_unreachable"), "warn", 6000);
                return;
            }
            if (!data) continue;
            done++;
            if (data.verdict === "phishing") flagged++;
            await new Promise((ok) => setTimeout(ok, DELAY_MS));
        }
        if (done) {
            const what = tn("auto_done", done);
            if (flagged) toast(tn("auto_flagged", flagged, { what }), "danger", 8000);
            else toast(t("auto_clean", { what }), "safe", 4000);
        }
    } finally {
        running = false;
    }
}
})();
