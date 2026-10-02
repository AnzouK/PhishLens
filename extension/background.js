// =====================================================================
// PhishLens background service worker.
// =====================================================================
// Four jobs:
//   1. Log install/update events.
//   2. Proxy fetch() calls to the configured backend on behalf of the
//      Gmail content script. Gmail's CSP would block direct fetches from
//      the page context, so the content script messages us instead.
//   3. Warm-up ping: ping the cloud backend on Chrome startup, on install,
//      and every 10 min. Originally introduced to mitigate the cold-start
//      latency of the previous Hugging Face Space / Render.com deployments.
//      The current Oracle Cloud VM runs continuously so cold starts no
//      longer occur, but the ping is kept as an inexpensive liveness check.
//   4. Persist scan history: receive save messages from the Gmail content
//      script (which can't easily reach chrome.storage in some flows) and
//      write them via the shared history module.
// =====================================================================

// Load the shared history module into the service worker so we can call
// PhishLensHistory.saveScan(...) and .attachTokens(...) when the Gmail
// content script asks us to persist a scan.
try { importScripts("lib/history.js"); }
catch (e) { console.warn("[PhishLens] history module not loaded:", e); }

const BACKEND_PRESETS = {
    local: "http://127.0.0.1:8000",
    cloud: "https://anzouk.duckdns.org",
};

async function getApiBase() {
    const s = await new Promise((r) =>
        chrome.storage.local.get(["backend", "backend_custom_url"], r));
    const choice = s.backend || "cloud";
    if (choice === "custom") return (s.backend_custom_url || "").replace(/\/$/, "");
    return BACKEND_PRESETS[choice] || BACKEND_PRESETS.cloud;
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
// - Silent: failures are expected during a cold start (first request
//   times out while the container is booting); we only need to trigger
//   the wake-up, we don't need to wait for the response body.
// - Uses AbortController to cap wall-time at 3 s.
async function warmBackend(reason) {
    try {
        const s = await new Promise((r) =>
            chrome.storage.local.get(["backend", "backend_custom_url"], r));
        const choice = s.backend || "cloud";
        // Local Docker never sleeps; nothing to warm up.
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
        // Expected during cold start: the container has still received
        // the request and is booting. Silent.
        console.log(`[PhishLens] Warm-up ping fired (${reason}); response not awaited.`);
    }
}

// 1. Fire when Chrome first launches with the extension installed.
chrome.runtime.onStartup.addListener(() => warmBackend("startup"));

// 2. Fire on install / update (also keeps the original install log).
chrome.runtime.onInstalled.addListener((details) => {
    console.log("PhishLens installed.");
    warmBackend("install");
    // Only when this extension itself was installed or updated (a reload
    // counts as an update). A Chrome update keeps the scripts alive, and
    // injecting a second copy into the same page would clash.
    if (details?.reason === "install" || details?.reason === "update") reinjectIntoOpenTabs();
});

// After an install, an update or a reload, Chrome does not inject content
// scripts into tabs that are already open: the old copy stays there, cut
// off from the extension, and the user would have to refresh Gmail. So
// the new copy is injected into open Gmail / Outlook tabs here; it
// replaces the old buttons (see PLL_INSTANCE in gmail.js).
async function reinjectIntoOpenTabs() {
    if (!chrome.scripting) return;
    const groups = chrome.runtime.getManifest().content_scripts || [];
    for (const cs of groups) {
        let tabs = [];
        try { tabs = await chrome.tabs.query({ url: cs.matches }); } catch { continue; }
        for (const tab of tabs) {
            if (tab.id == null || tab.discarded) continue;
            try {
                if (cs.css?.length) await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: cs.css });
                await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: cs.js });
            } catch (e) {
                console.warn("PhishLens: could not refresh the script in tab", tab.id, String(e?.message || e));
            }
        }
    }
}

// 3. Keep-alive alarm: pings every 10 min while Chrome is running.
//    Chrome's alarms API guarantees a minimum interval of 30 s in prod,
//    so 10 min is comfortably well within limits and gentle on the HF
//    free tier.
chrome.alarms.create("phishlens-keepalive", { periodInMinutes: 10 });
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "phishlens-keepalive") warmBackend("keepalive");
});

const _pllNotifTabs = new Map();
chrome.notifications?.onClicked?.addListener((id) => {
    const t = _pllNotifTabs.get(id);
    if (!t) return;
    chrome.tabs.update(t.tabId, { active: true }).catch(() => {});
    chrome.windows.update(t.windowId, { focused: true }).catch(() => {});
    chrome.notifications.clear(id);
    _pllNotifTabs.delete(id);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // History persistence: content scripts (Gmail) delegate storage to us.
    if (msg?.type === "phishlens.history.save") {
        (async () => {
            try {
                const id = await self.PhishLensHistory?.saveScan(msg.entry);
                sendResponse({ ok: true, id });
            } catch (e) {
                sendResponse({ ok: false, error: String(e?.message || e) });
            }
        })();
        return true;
    }
    // v1.15: desktop notification for a phishing email found by the
    // automatic scan. Clicking it focuses the Gmail tab that found it.
    if (msg?.type === "phishlens.notify") {
        const tabId = sender?.tab?.id;
        const id = "pll-" + Date.now();
        try {
            chrome.notifications?.create(id, {
                type: "basic",
                iconUrl: "icons/128.png",
                title: String(msg.title || "PhishLens").slice(0, 120),
                message: String(msg.message || "").slice(0, 300),
                priority: 2,
            });
            if (tabId != null) _pllNotifTabs.set(id, { tabId, windowId: sender.tab.windowId });
        } catch {}
        sendResponse({ ok: true });
        return false;
    }
    if (msg?.type === "phishlens.history.attachTokens") {
        (async () => {
            try {
                await self.PhishLensHistory?.attachTokens(msg.id, msg.tokens);
                sendResponse({ ok: true });
            } catch (e) {
                sendResponse({ ok: false, error: String(e?.message || e) });
            }
        })();
        return true;
    }

    const ENDPOINT_MAP = {
        "phishlens.analyse":            "/analyse",
        "phishlens.explain":            "/explain",
        "phishlens.analyse_attachment": "/analyse_attachment",
    };
    if (!(msg?.type in ENDPOINT_MAP)) return false;

    const endpoint = ENDPOINT_MAP[msg.type];
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
