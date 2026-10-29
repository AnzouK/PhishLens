// The local scan history and its statistics, in chrome.storage.local.
// Nothing here leaves the browser unless the user shares it (statsRows)
// or reports one scan.
//
// "scanHistory": ScanEntry[], newest first, at most MAX_ENTRIES.
// "reportDrafts": { [scan id]: { text, ts } }, the redacted text of recent
//   Gmail and Outlook scans, so a wrong verdict can still be reported
//   from Insights. Kept DRAFT_DAYS days, DRAFT_MAX at most.

/**
 * @typedef {Object} ScanEntry
 * @property {string} id
 * @property {number} ts          Date.now() of the scan
 * @property {string} source      "gmail" | "gmail-attachment" | "gmail-auto" | "outlook" | "file" | "attachment" | "paste"
 * @property {string} subject     at most 120 characters (the file name for a file)
 * @property {string} sender      address or domain, when known
 * @property {"phishing"|"safe"} verdict
 * @property {number} score       fused probability, 0 to 1
 * @property {{text: number, url: number, metadata: number}} agents
 * @property {boolean} trusted    the server's trusted_sender flag
 * @property {{token: string, weight: number}[]} tokens   top 5 words of the explanation
 * @property {"correct"|"wrong"} [label]   the user's review
 * @property {string} [lang]      language detected by the server ("und" when unclear)
 * @property {string} [lang_user] the user's answer: the same code, another one, or "other"
 * @property {string} [reported]  reference of a report the user sent
 */

(function () {
"use strict";

const STORAGE_KEY = "scanHistory";
// Function words carry no meaning in "Top phishing tokens" even when
// LIME weights them; they stay in the stored history.
const STOPWORDS = new Set(("the and for are but not you your yours our ours this that these those with from have has had " +
    "was were will would can could should been being into onto than then them they their there here what when where " +
    "which who whom why how all any each few more most other some such only own same too very just also its it's " +
    "about above after again against before below between during over under until while off out once does did doing " +
    "dear good hello thanks thank regards please").split(" "));
const MAX_ENTRIES = 500;   // ~50 KB, well below the 5 MB chrome.storage cap
const DRAFTS_KEY = "reportDrafts";
const DRAFT_MAX = 50;
const DRAFT_DAYS = 7;
const LANG_RE = /^(?:[a-z]{2,3}|und|other)$/;

function _get(key) {
    return new Promise((resolve) => {
        chrome.storage.local.get([key], (s) => resolve(s[key]));
    });
}
function _set(key, value) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, resolve);
    });
}

// Every change reads the list, edits it and writes it back: two changes
// at once (two scans finishing together) would lose one. They run one
// after the other instead.
let _queue = Promise.resolve();
function serial(fn) {
    return (...args) => {
        const run = _queue.then(() => fn(...args));
        _queue = run.catch(() => {});
        return run;
    };
}

// The history entry for an /analyse or /analyse_attachment answer.
function entryFrom(data, { source, subject = "", sender = "" }) {
    const p = (agent) => Number(data?.agents?.[agent]?.phishing_probability) || 0;
    return {
        source, subject, sender,
        verdict: data?.verdict,
        score: Number(data?.fused_score) || 0,
        agents: { text: p("text"), url: p("url"), metadata: data?.attachment ? 0 : p("metadata") },
        trusted: !!(data?.trusted_sender || data?.parent_trusted),
        lang: data?.language?.code,
    };
}

const saveScan = serial(async function saveScan(entry) {
    if (!entry || typeof entry !== "object") return;
    const list = (await _get(STORAGE_KEY)) || [];
    const clean = {
        id:       entry.id      || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        ts:       entry.ts      || Date.now(),
        source:   entry.source  || "unknown",
        subject:  (entry.subject || "").slice(0, 120),
        sender:   (entry.sender  || "").slice(0, 120),
        verdict:  entry.verdict === "phishing" ? "phishing" : "safe",
        score:    Number.isFinite(entry.score) ? +entry.score : 0,
        agents:   entry.agents  || { text: 0, url: 0, metadata: 0 },
        trusted:  !!entry.trusted,
        tokens:   Array.isArray(entry.tokens) ? entry.tokens.slice(0, 5) : [],
    };
    if (entry.label === "correct" || entry.label === "wrong") clean.label = entry.label;
    if (LANG_RE.test(entry.lang || "")) clean.lang = entry.lang;
    list.unshift(clean);
    if (list.length > MAX_ENTRIES) list.length = MAX_ENTRIES;
    await _set(STORAGE_KEY, list);
    return clean.id;
});

// The top words of the explanation, once /explain has answered.
const attachTokens = serial(async function attachTokens(id, tokens) {
    if (!id || !Array.isArray(tokens)) return;
    const list = (await _get(STORAGE_KEY)) || [];
    const idx = list.findIndex((e) => e.id === id);
    if (idx < 0) return;
    list[idx].tokens = tokens.slice(0, 5);
    await _set(STORAGE_KEY, list);
});

// The user says whether a verdict was right. Unknown labels clear it.
const setLabel = serial(async function setLabel(id, label) {
    const list = (await _get(STORAGE_KEY)) || [];
    const e = list.find((x) => x.id === id);
    if (!e) return;
    if (label === "correct" || label === "wrong") e.label = label;
    else delete e.label;
    await _set(STORAGE_KEY, list);
});

// The user's answers about a scan: the language, a report sent.
const updateScan = serial(async function updateScan(id, patch = {}) {
    const list = (await _get(STORAGE_KEY)) || [];
    const e = list.find((x) => x.id === id);
    if (!e) return false;
    if (LANG_RE.test(patch.lang_user || "")) e.lang_user = patch.lang_user;
    if (typeof patch.reported === "string" && /^[a-f0-9]{6,32}$/.test(patch.reported)) e.reported = patch.reported;
    if (patch.label === "correct" || patch.label === "wrong") e.label = patch.label;
    await _set(STORAGE_KEY, list);
    return true;
});

async function _drafts() {
    const all = (await _get(DRAFTS_KEY)) || {};
    const cutoff = Date.now() - DRAFT_DAYS * 86400e3;
    const kept = Object.entries(all).filter(([, d]) => d && d.ts >= cutoff)
        .sort((a, b) => b[1].ts - a[1].ts).slice(0, DRAFT_MAX);
    return Object.fromEntries(kept);
}

// Text already redacted by the caller (lib/redact.js).
const saveDraft = serial(async function saveDraft(id, text) {
    if (!id || !text) return;
    const drafts = await _drafts();
    drafts[id] = { text: String(text).slice(0, 20000), ts: Date.now() };
    await _set(DRAFTS_KEY, await _trimDrafts(drafts));
});

async function _trimDrafts(drafts) {
    const kept = Object.entries(drafts).sort((a, b) => b[1].ts - a[1].ts).slice(0, DRAFT_MAX);
    return Object.fromEntries(kept);
}

async function getDraft(id) {
    return (await _drafts())[id]?.text || "";
}

// Reviewed history for sharing: no subject, sender or text.
function statsRows(list) {
    const day = (ts) => new Date(ts).toISOString().slice(0, 10);
    const n = (v) => Math.min(1, Math.max(0, Number(v) || 0));
    return list.slice(0, MAX_ENTRIES).map((e) => ({
        day: day(e.ts),
        source: String(e.source || "unknown").slice(0, 30),
        verdict: e.verdict === "phishing" ? "phishing" : "safe",
        score: n(e.score),
        agents: { text: n(e.agents?.text), url: n(e.agents?.url), metadata: n(e.agents?.metadata) },
        trusted: !!e.trusted,
        label: e.label === "correct" || e.label === "wrong" ? e.label : null,
        lang: LANG_RE.test(e.lang || "") ? e.lang : null,
        lang_user: LANG_RE.test(e.lang_user || "") ? e.lang_user : null,
    }));
}

// Live evaluation from the reviewed scans. Ground truth: a "correct"
// phishing verdict is a true positive, a "wrong" one a false positive;
// a "correct" safe verdict is a true negative, a "wrong" one a missed
// phishing email (false negative).
function liveEvaluation(list) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const e of list) {
        if (e.label !== "correct" && e.label !== "wrong") continue;
        const ph = e.verdict === "phishing";
        if (ph && e.label === "correct") tp++;
        else if (ph) fp++;
        else if (e.label === "correct") tn++;
        else fn++;
    }
    const n = tp + fp + tn + fn;
    const rate = (a, b) => (b ? a / b : null);
    return {
        reviewed: n, tp, fp, tn, fn,
        accuracy:  rate(tp + tn, n),
        precision: rate(tp, tp + fp),
        recall:    rate(tp, tp + fn),
        falsePositiveRate: rate(fp, fp + tn),
    };
}

async function getHistory() {
    return (await _get(STORAGE_KEY)) || [];
}

const clearHistory = serial(async function clearHistory() {
    await _set(STORAGE_KEY, []);
    await _set(DRAFTS_KEY, {});
});

const deleteScan = serial(async function deleteScan(id) {
    const list = (await _get(STORAGE_KEY)) || [];
    const next = list.filter((e) => e.id !== id);
    await _set(STORAGE_KEY, next);
    const drafts = await _drafts();
    delete drafts[id];
    await _set(DRAFTS_KEY, drafts);
});

// Aggregates for the Insights view.
async function getStats() {
    const list = await getHistory();
    const total = list.length;
    const phishing = list.filter((e) => e.verdict === "phishing").length;
    const safe = total - phishing;

    // last 30 days daily buckets, keyed by LOCAL date. toISOString() is
    // UTC: east of Greenwich it shifted every bucket one day back, and the
    // chart showed nothing for today's scans.
    const dayKey = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    const now = new Date();
    const days = [];
    for (let i = 29; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(now.getDate() - i);
        d.setHours(0, 0, 0, 0);
        days.push({ date: dayKey(d), phishing: 0, safe: 0 });
    }
    const bucketByDate = Object.fromEntries(days.map((d) => [d.date, d]));
    for (const e of list) {
        const key = dayKey(new Date(e.ts));
        const b = bucketByDate[key];
        if (b) b[e.verdict]++;
    }

    // Top LIME tokens from phishing scans
    const tokenCounts = {};
    for (const e of list) {
        if (e.verdict !== "phishing") continue;
        for (const t of e.tokens || []) {
            const key = (t.token || "").toLowerCase();
            // Same filter as the Gmail banner, plus CSS-looking tokens
            // ("25px", "0px") that leak from HTML emails.
            if (key.length < 3 || /^\d+$/.test(key) || /^\d+(px|em|pt|%)$/.test(key) || STOPWORDS.has(key)) continue;
            tokenCounts[key] = (tokenCounts[key] || 0) + Math.abs(t.weight || 0);
        }
    }
    const topTokens = Object.entries(tokenCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([token, weight]) => ({ token, weight }));

    // By source breakdown
    const bySource = { gmail: 0, "gmail-attachment": 0, "gmail-auto": 0, outlook: 0, file: 0, attachment: 0, paste: 0, unknown: 0 };
    for (const e of list) bySource[e.source] = (bySource[e.source] || 0) + 1;

    // Average score
    const avgScore = total
        ? list.reduce((s, e) => s + (e.score || 0), 0) / total
        : 0;

    return {
        total,
        phishing,
        safe,
        phishingPct: total ? Math.round((phishing * 100) / total) : 0,
        safePct:     total ? Math.round((safe * 100) / total)     : 0,
        avgScore,
        days,
        topTokens,
        bySource,
        live: liveEvaluation(list),
        firstScanTs: list.length ? list[list.length - 1].ts : null,
        lastScanTs:  list.length ? list[0].ts               : null,
    };
}

async function exportJSON() {
    const list = await getHistory();
    return JSON.stringify(list, null, 2);
}

async function exportCSV() {
    const list = await getHistory();
    const cols = ["ts", "source", "verdict", "score", "sender", "subject",
                  "agent_text", "agent_url", "agent_metadata", "trusted", "top_tokens", "label",
                  "lang", "lang_user"];
    const esc = (v) => {
        let s = v === null || v === undefined ? "" : String(v);
        // CSV formula injection: subjects and senders come from attacker
        // emails. A cell starting with = + - @ (or a tab / CR) would be
        // run as a formula when the export is opened in Excel or Sheets,
        // so it is prefixed with a quote to force plain text.
        if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
        return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = [cols.join(",")];
    for (const e of list) {
        rows.push([
            new Date(e.ts).toISOString(),
            e.source,
            e.verdict,
            e.score?.toFixed(4),
            e.sender,
            e.subject,
            e.agents?.text?.toFixed(4),
            e.agents?.url?.toFixed(4),
            e.agents?.metadata?.toFixed(4),
            e.trusted ? "yes" : "no",
            (e.tokens || []).map((t) => t.token).join("|"),
            e.label || "",
            e.lang || "",
            e.lang_user || "",
        ].map(esc).join(","));
    }
    return rows.join("\n");
}

const PhishLensHistory = {
    saveScan, entryFrom, attachTokens, setLabel, updateScan, saveDraft, getDraft, statsRows,
    liveEvaluation, getHistory, getStats, clearHistory, deleteScan, exportJSON, exportCSV,
    STORAGE_KEY, DRAFTS_KEY, MAX_ENTRIES,
};
globalThis.PhishLensHistory = PhishLensHistory;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensHistory;
})();
