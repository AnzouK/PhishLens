// =====================================================================
// PhishLens — scan history & analytics module.
// =====================================================================
// Single source of truth for the local scan history. Used by:
//   • popup.js         — saves file / paste scans
//   • gmail.js         — saves Gmail-injected scans (via background message)
//   • background.js    — bridges gmail.js -> chrome.storage
//   • popup views      — read the history for the History & Analytics tabs
//
// Storage design
//   Key:   "scanHistory"  in chrome.storage.local
//   Value: Array of entries, newest first. Capped at MAX_ENTRIES.
//   Entry: {
//     id:        string       // uuid-ish
//     ts:        number       // Date.now()
//     source:    "gmail" | "file" | "paste"
//     subject:   string       // truncated to 120 chars
//     sender:    string       // sender email/domain when available
//     verdict:   "phishing" | "safe"
//     score:     number       // fused probability 0..1
//     agents:    { text: number, url: number, metadata: number }
//     trusted:   boolean      // trusted_sender flag from backend
//     tokens:    [{token, weight}]   // top 5 LIME features (populated later)
//   }
// =====================================================================

const STORAGE_KEY = "scanHistory";
const MAX_ENTRIES = 500;   // ~50 KB, well below the 5 MB chrome.storage cap

// ---------------------------------------------------------------------
// Chrome storage helpers — Promise-based wrappers so we can await them.
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
// Analytics — aggregated stats for the dashboard view.
// ---------------------------------------------------------------------
async function getStats() {
    const list = await getHistory();
    const total = list.length;
    const phishing = list.filter((e) => e.verdict === "phishing").length;
    const safe = total - phishing;

    // last 30 days daily buckets
    const now = new Date();
    const days = [];
    for (let i = 29; i >= 0; i--) {
        const d = new Date(now);
        d.setDate(now.getDate() - i);
        d.setHours(0, 0, 0, 0);
        days.push({ date: d.toISOString().slice(0, 10), phishing: 0, safe: 0 });
    }
    const bucketByDate = Object.fromEntries(days.map((d) => [d.date, d]));
    for (const e of list) {
        const key = new Date(e.ts).toISOString().slice(0, 10);
        const b = bucketByDate[key];
        if (b) b[e.verdict]++;
    }

    // Top LIME tokens from phishing scans
    const tokenCounts = {};
    for (const e of list) {
        if (e.verdict !== "phishing") continue;
        for (const t of e.tokens || []) {
            const key = (t.token || "").toLowerCase();
            if (!key) continue;
            tokenCounts[key] = (tokenCounts[key] || 0) + Math.abs(t.weight || 0);
        }
    }
    const topTokens = Object.entries(tokenCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
        .map(([token, weight]) => ({ token, weight }));

    // By source breakdown
    const bySource = { gmail: 0, file: 0, paste: 0, unknown: 0 };
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
                  "agent_text", "agent_url", "agent_metadata", "trusted", "top_tokens"];
    const esc = (v) => {
        const s = v === null || v === undefined ? "" : String(v);
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
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
        ].map(esc).join(","));
    }
    return rows.join("\n");
}

// ---------------------------------------------------------------------
// Global export — works in popup, content scripts, service worker.
// ---------------------------------------------------------------------
const PhishLensHistory = {
    saveScan, attachTokens, getHistory, getStats,
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
