// Gmail: automatic scanning of new emails (opt-in, popup Settings).
// While the message list is on screen, unread emails PhishLens has not
// seen are read through "Show original" (without opening them) and sent
// to /analyse one at a time. A phishing verdict puts a "Phishing?" pill
// on the row and raises a desktop notification. Verdicts are cached by
// thread id with a fingerprint of the row. A new reply changes the row,
// so the thread is scanned again and the old pill is removed. An email
// Gmail would not serve is retried later, three times at most.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t, tn } = PhishLensI18n;
const { h, icon } = PhishLensDom;
const { debug } = PhishLensShared;
const G = PhishLensGmail;

// Bumped when the scoring changes so older verdicts are not reused.
const CACHE_KEY = "autoScanCache.v5";
const RETRY_MS = 30 * 60 * 1000;   // a skipped email is tried again after 30 min
const MAX_TRIES = 3;
const CACHE_MAX = 500;
const MAX_PER_PASS = 10;     // well under the server's rate limit
const DELAY_MS = 1500;       // between two emails
let running = false;
let timer = null;
let cacheMem = null;
let noticeToastShown = false;

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

// Text of a row element without our own pill. The pill is removed by
// element rather than by its words, since a sender called "SafeBank"
// contains the word "Safe".
function textWithoutPill(node) {
    if (!node) return "";
    if (node.nodeType === 3) return node.data;
    if (node.classList?.contains("pll-row-badge")) return "";
    return [...node.childNodes].map(textWithoutPill).join("");
}

// Short fingerprint of a row (senders, subject, snippet) that changes
// when a reply arrives in the thread. The date is left out because Gmail
// rewrites it on its own ("10:32", then "21 Nov" the next day).
function rowPrint(row) {
    const { SEL } = G;
    const senders = [...row.querySelectorAll(SEL.rowSender)]
        .map((s) => `${s.getAttribute("email") || ""} ${s.getAttribute("name") || ""}`);
    const fields = [textWithoutPill(row.querySelector(SEL.rowSubject)), textWithoutPill(row.querySelector(SEL.rowSnippet))];
    // Fallback if Gmail renames those classes: the whole row, still
    // without the pill.
    if (!fields.join("").trim()) fields.push(textWithoutPill(row));
    const text = [...senders, ...fields].join("\n");
    let hash = 5381;
    for (let i = 0; i < text.length; i++) hash = ((hash * 33) ^ text.charCodeAt(i)) >>> 0;
    return hash.toString(36);
}
PL.autoRowPrint = rowPrint;

// A row needs a scan if it was never seen, has changed since, or was
// skipped and its wait is over.
function needsScan(r, hit, now = Date.now()) {
    if (!hit || hit.print !== r.print) return true;
    return hit.verdict === "skipped" && (hit.tries || 1) < MAX_TRIES && now - hit.ts > RETRY_MS;
}
PL.autoScanNeeds = needsScan;

// Rows of the list on screen (Gmail keeps hidden copies of other views).
function inboxRows() {
    const { SEL } = G;
    return [...document.querySelectorAll(SEL.inboxRow)].filter((row) => row.offsetParent !== null).map((row) => ({
        row,
        id: row.querySelector(SEL.rowThreadId)?.getAttribute("data-legacy-thread-id") || "",
        unread: row.classList.contains(SEL.unreadRowClass),
        sender: row.querySelector(SEL.rowSender)?.getAttribute("email") || "",
        senderName: row.querySelector(SEL.rowSender)?.getAttribute("name") || "",
        subject: (row.querySelector(SEL.rowSubject)?.textContent || "").trim(),
        print: rowPrint(row),
    })).filter((r) => /^[0-9a-f]{8,20}$/.test(r.id));
}

PL.paintAutoBadges = function paintAutoBadges() {
    if (!cacheMem || !PL.alive()) return;
    for (const r of inboxRows()) {
        const hit = cacheMem[r.id];
        const old = r.row.querySelector(".pll-row-badge");
        // Show a pill only for the exact row that was scanned. After a new
        // reply the old verdict no longer applies.
        const current = hit && hit.print === r.print && (hit.verdict === "phishing" || hit.verdict === "safe");
        if (old && !current) old.remove();
        if (!current || old) continue;
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

function skip(r) {
    const tries = cacheMem?.[r.id]?.print === r.print ? (cacheMem[r.id].tries || 1) + 1 : 1;
    return cachePut(r.id, { verdict: "skipped", print: r.print, tries, ts: Date.now() });
}

async function scanRow(r) {
    const original = await PL.fetchOriginalMessage({ thread: r.id });
    if (!original) {
        await skip(r);
        return null;
    }
    const data = await PhishLensApi.analyse({
        raw_email_b64: PL.utf8ToB64(original),
        sender_email: r.sender?.slice(0, 512) || null,
        sender_name: PL.senderName(r.senderName),
        client_context: {
            origin: "gmail",
            subject: r.subject,
            headers_source: "gmail_show_original",
            gmail_in_inbox: G.inInbox(location.hash),
            auto_scan: true,
        },
    });
    await cachePut(r.id, { verdict: data.verdict, score: Number(data.fused_score) || 0, print: r.print, ts: Date.now() });
    PL.saveScan(data, { source: "gmail-auto", subject: r.subject, sender: r.sender });
    PL.paintAutoBadges();
    if (data.verdict === "phishing") {
        // Sender only, since a notification can show on a locked screen.
        PhishLensApi.notify(t("notify_title"), r.sender || t("unknown_sender"))
            .catch((e) => debug("notification", e));
    }
    return data;
}

async function runAutoScan() {
    if (running || !PL.opts.autoScan || !PL.alive()) return;
    running = true;
    try {
        // No automatic scan before the privacy notice has been seen. It is
        // shown in the popup, where the option is turned on, and before
        // the first manual scan.
        const notice = await new Promise((r) => chrome.storage.local.get(["privacy_notice_seen", "backend"], (v) => r(v || {})));
        if (!notice.privacy_notice_seen && (!notice.backend || notice.backend === "cloud")) {
            // Tell the user once per page instead of waiting silently.
            if (!noticeToastShown) toast(t("auto_waiting_notice"), "warn", 10000);
            noticeToastShown = true;
            return;
        }
        const cache = await cacheGet();
        cacheMem = cache;
        const todo = inboxRows().filter((r) => r.unread && needsScan(r, cache[r.id])).slice(0, MAX_PER_PASS);
        let done = 0, flagged = 0;
        for (const r of todo) {
            if (!PL.opts.autoScan) break;
            toast(todo.length > 1 ? t("auto_checking_n", { i: done + 1, n: todo.length }) : t("auto_checking_single"));
            let data;
            try {
                data = await scanRow(r);
            } catch (e) {
                // A 4xx other than 429 refuses this email only, so it is
                // skipped and the pass goes on.
                if (e?.status >= 400 && e.status < 500 && e.status !== 429) {
                    debug("automatic scan skipped an email", e);
                    await skip(r);
                    continue;
                }
                // Server down or rate-limited. Stop this pass and retry on
                // the next one.
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
