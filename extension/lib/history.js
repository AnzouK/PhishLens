// =====================================================================
// PhishLens: scan history & analytics module.
// =====================================================================
// Single source of truth for the local scan history. Used by:
//   • popup.js        : saves file / paste scans
//   • gmail.js        : saves Gmail-injected scans (via background message)
//   • background.js   : bridges gmail.js -> chrome.storage
//   • popup views     : read the history for the History & Analytics tabs
//
// Storage design
//   Key:   "scanHistory"  in chrome.storage.local
//   Value: Array of entries, newest first. Capped at MAX_ENTRIES.
//   Entry: {
//     id:        string       // uuid-ish
//     ts:        number       // Date.now()
//     source:    "gmail" | "gmail-attachment" | "gmail-auto" | "file" | "attachment" | "paste"
//     subject:   string       // truncated to 120 chars
//     sender:    string       // sender email/domain when available
//     verdict:   "phishing" | "safe"
//     score:     number       // fused probability 0..1
//     agents:    { text: number, url: number, metadata: number }
//     trusted:   boolean      // trusted_sender flag from backend
//     tokens:    [{token, weight}]   // top 5 LIME features (populated later)
//     label:     "correct" | "wrong" | undefined   // v1.15: user review
//   }
// =====================================================================

const STORAGE_KEY = "scanHistory";
// Function words carry no meaning in "Top phishing tokens" even when
// LIME weights them; they stay in the stored history.
const STOPWORDS = new Set(("the and for are but not you your yours our ours this that these those with from have has had " +
    "was were will would can could should been being into onto than then them they their there here what when where " +
    "which who whom why how all any each few more most other some such only own same too very just also its it's " +
    "about above after again against before below between during over under until while off out once does did doing " +
    "dear good hello thanks thank regards please").split(" "));
const MAX_ENTRIES = 500;   // ~50 KB, well below the 5 MB chrome.storage cap

// ---------------------------------------------------------------------
// Chrome storage helpers: Promise-based wrappers so we can await them.
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// Core CRUD
// ---------------------------------------------------------------------
async function saveScan(entry) {
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
    list.unshift(clean);
    if (list.length > MAX_ENTRIES) list.length = MAX_ENTRIES;
    await _set(STORAGE_KEY, list);
    return clean.id;
}

// Attach LIME tokens to an already-saved scan (called when /explain returns).
async function attachTokens(id, tokens) {
    if (!id || !Array.isArray(tokens)) return;
    const list = (await _get(STORAGE_KEY)) || [];
    const idx = list.findIndex((e) => e.id === id);
    if (idx < 0) return;
    list[idx].tokens = tokens.slice(0, 5);
    await _set(STORAGE_KEY, list);
}

// v1.15: the user says whether a verdict was right. Unknown labels clear it.
async function setLabel(id, label) {
    const list = (await _get(STORAGE_KEY)) || [];
    const e = list.find((x) => x.id === id);
    if (!e) return;
    if (label === "correct" || label === "wrong") e.label = label;
    else delete e.label;
    await _set(STORAGE_KEY, list);
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

async function clearHistory() {
    await _set(STORAGE_KEY, []);
}

async function deleteScan(id) {
    const list = (await _get(STORAGE_KEY)) || [];
    const next = list.filter((e) => e.id !== id);
    await _set(STORAGE_KEY, next);
}

// ---------------------------------------------------------------------
// Analytics: aggregated stats for the dashboard view.
// ---------------------------------------------------------------------
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

// ---------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------
async function exportJSON() {
    const list = await getHistory();
    return JSON.stringify(list, null, 2);
}

async function exportCSV() {
    const list = await getHistory();
    const cols = ["ts", "source", "verdict", "score", "sender", "subject",
                  "agent_text", "agent_url", "agent_metadata", "trusted", "top_tokens", "label"];
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
        ].map(esc).join(","));
    }
    return rows.join("\n");
}

// ---------------------------------------------------------------------
// Global export: works in popup, content scripts, service worker.
// ---------------------------------------------------------------------
const PhishLensHistory = {
    saveScan, attachTokens, setLabel, liveEvaluation, getHistory, getStats,
    clearHistory, deleteScan, exportJSON, exportCSV,
    STORAGE_KEY, MAX_ENTRIES,
};

// Support both non-module (popup <script>, content script, service worker) and
// ES-module (popup.js has type="module") consumers.
if (typeof globalThis !== "undefined") globalThis.PhishLensHistory = PhishLensHistory;
if (typeof window     !== "undefined") window.PhishLensHistory     = PhishLensHistory;
if (typeof self       !== "undefined") self.PhishLensHistory       = PhishLensHistory;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensHistory;
