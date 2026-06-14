// =====================================================================
// PhishLens background service worker.
// =====================================================================
// Two jobs:
//   1. Log install/update events.
//   2. Proxy fetch() calls to the local backend on behalf of the Gmail
//      content script. Gmail's CSP would block direct localhost fetches
//      from the page context, so the content script messages us instead.
// =====================================================================

const API_BASE = "http://127.0.0.1:8000";

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishLens installed.");
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type !== "phishlens.analyse" && msg?.type !== "phishlens.explain")
        return false;

    const endpoint = msg.type === "phishlens.analyse" ? "/analyse" : "/explain";
    const payload  = msg.payload || {};

    fetch(`${API_BASE}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    })
    .then(async (r) => {
        let data;
        try { data = await r.json(); } catch { data = null; }
        if (!r.ok) {
            sendResponse({ ok: false, error: data?.detail || `HTTP ${r.status}` });
        } else {
            sendResponse({ ok: true, data });
        }
    })
    .catch((e) => {
        sendResponse({
            ok: false,
            error: String(e?.message || e).startsWith("Failed to fetch")
                ? "Backend unreachable. Is uvicorn running on port 8000?"
                : String(e?.message || e),
        });
    });

    return true;        // keep the message channel open for the async response
});
