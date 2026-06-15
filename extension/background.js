// =====================================================================
// PhishLens background service worker.
// =====================================================================
// Two jobs:
//   1. Log install/update events.
//   2. Proxy fetch() calls to the configured backend on behalf of the
//      Gmail content script. Gmail's CSP would block direct fetches from
//      the page context, so the content script messages us instead.
// =====================================================================

const BACKEND_PRESETS = {
    local: "http://127.0.0.1:8000",
    cloud: "https://sonje03-phishlens-backend.hf.space",
};

async function getApiBase() {
    const s = await new Promise((r) =>
        chrome.storage.local.get(["backend", "backend_custom_url"], r));
    const choice = s.backend || "local";
    if (choice === "custom") return (s.backend_custom_url || "").replace(/\/$/, "");
    return BACKEND_PRESETS[choice] || BACKEND_PRESETS.local;
}

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishLens installed.");
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg?.type !== "phishlens.analyse" && msg?.type !== "phishlens.explain")
        return false;

    const endpoint = msg.type === "phishlens.analyse" ? "/analyse" : "/explain";
    const payload  = msg.payload || {};

    (async () => {
        const base = await getApiBase();
        if (!base) {
            sendResponse({ ok: false,
                error: "No backend URL configured. Open PhishLens settings (⚙)." });
            return;
        }
        try {
            const r = await fetch(`${base}${endpoint}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            let data;
            try { data = await r.json(); } catch { data = null; }
            if (!r.ok) {
                sendResponse({ ok: false, error: data?.detail || `HTTP ${r.status}` });
            } else {
                sendResponse({ ok: true, data });
            }
        } catch (e) {
            sendResponse({
                ok: false,
                error: String(e?.message || e).startsWith("Failed to fetch")
                    ? "Backend unreachable. Check PhishLens settings (⚙)."
                    : String(e?.message || e),
            });
        }
    })();

    return true;        // keep the message channel open for the async response
});
