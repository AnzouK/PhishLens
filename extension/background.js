// =====================================================================
// PhishLens background service worker.
// =====================================================================
// Three jobs:
//   1. Log install/update events.
//   2. Proxy fetch() calls to the configured backend on behalf of the
//      Gmail content script. Gmail's CSP would block direct fetches from
//      the page context, so the content script messages us instead.
//   3. Warm-up ping — ping the cloud backend on Chrome startup, on install,
//      and every 10 min. Originally introduced to mitigate the 30-60 s
//      cold-start latency of the previous Hugging Face Space / Render.com
//      deployments. The current Oracle Cloud VM runs continuously so cold
//      starts no longer occur, but the ping is kept as an inexpensive
//      liveness check.
// =====================================================================

const BACKEND_PRESETS = {
    local: "http://127.0.0.1:8000",
    cloud: "http://130.61.146.213",
};

async function getApiBase() {
    const s = await new Promise((r) =>
        chrome.storage.local.get(["backend", "backend_custom_url"], r));
    const choice = s.backend || "local";
    if (choice === "custom") return (s.backend_custom_url || "").replace(/\/$/, "");
    return BACKEND_PRESETS[choice] || BACKEND_PRESETS.local;
}

// ---------------------------------------------------------------------
// Warm-up ping.
// ---------------------------------------------------------------------
// Fires a lightweight GET /health to the configured backend so that a
// sleeping HuggingFace Space container wakes up in the background. The
// user then sees a warm backend when they open the popup or click the
// Gmail "Scan" button.
//
// - Skipped when backend is "local" (no cold-start there).
// - Silent — failures are expected during a cold start (first request
//   times out while the container is booting); we only need to trigger
//   the wake-up, we don't need to wait for the response body.
// - Uses AbortController to cap wall-time at 3 s.
async function warmBackend(reason) {
    try {
        const s = await new Promise((r) =>
            chrome.storage.local.get(["backend", "backend_custom_url"], r));
        const choice = s.backend || "local";
        // Local Docker never sleeps — nothing to warm up.
        if (choice === "local") return;
        const base =
            choice === "custom"
                ? (s.backend_custom_url || "").replace(/\/$/, "")
                : BACKEND_PRESETS[choice];
        if (!base) return;

        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 3000);
        await fetch(`${base}/health`, {
            method: "GET",
            cache: "no-store",
            signal: ctrl.signal,
        });
        clearTimeout(timer);
        console.log(`[PhishLens] Backend warmed (${reason}).`);
    } catch (_) {
        // Expected during cold start — the container has still received
        // the request and is booting. Silent.
        console.log(`[PhishLens] Warm-up ping fired (${reason}); response not awaited.`);
    }
}

// 1. Fire when Chrome first launches with the extension installed.
chrome.runtime.onStartup.addListener(() => warmBackend("startup"));

// 2. Fire on install / update (also keeps the original install log).
chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishLens installed.");
    warmBackend("install");
});

// 3. Keep-alive alarm — pings every 10 min while Chrome is running.
//    Chrome's alarms API guarantees a minimum interval of 30 s in prod,
//    so 10 min is comfortably well within limits and gentle on the HF
//    free tier.
chrome.alarms.create("phishlens-keepalive", { periodInMinutes: 10 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "phishlens-keepalive") warmBackend("keepalive");
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
