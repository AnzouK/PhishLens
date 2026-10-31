// PhishLens service worker: makes every request to the PhishLens server
// (lib/api.js sends them here), keeps the local history for the content
// scripts, shows the automatic scan's notifications, and refreshes the
// content scripts of open mail tabs after an install or an update.
// The server is only contacted when a scan or a report is requested.

// Chrome runs this file as a service worker, which loads the libraries
// here. Firefox runs it as an event page whose manifest lists the same
// files before it (scripts/build_extension.py reads this list).
if (typeof importScripts === "function") {
    try {
        importScripts(
            "lib/locales/en.js", "lib/locales/fr.js", "lib/locales/pt.js", "lib/locales/es.js",
            "lib/locales/de.js", "lib/locales/it.js", "lib/locales/nl.js", "lib/locales/ha.js",
            "lib/i18n.js", "lib/shared.js", "lib/history.js", "lib/lime_cache.js");
    } catch (e) {
        console.warn("[PhishLens] shared modules not loaded:", e);
    }
}
self.PhishLensI18n?.init();

const text = (key, vars) => self.PhishLensI18n?.t(key, vars) ?? key;
const { debug } = self.PhishLensShared;

chrome.runtime.onInstalled.addListener((details) => {
    // Only for this extension (a reload counts as an update). After a
    // Chrome update the scripts in open tabs are still alive.
    if (details?.reason === "install" || details?.reason === "update") reinjectIntoOpenTabs();
});

// Chrome does not inject content scripts into tabs that were open before
// an install or an update: without this the user would have to reload
// Gmail. The new copy replaces the old one's buttons (core.js).
async function reinjectIntoOpenTabs() {
    if (!chrome.scripting) return;
    for (const cs of chrome.runtime.getManifest().content_scripts || []) {
        let tabs = [];
        try {
            tabs = await chrome.tabs.query({ url: cs.matches });
        } catch (e) {
            debug("tab query", e);
            continue;
        }
        for (const tab of tabs) {
            if (tab.id == null || tab.discarded) continue;
            try {
                if (cs.css?.length) await chrome.scripting.insertCSS({ target: { tabId: tab.id }, files: cs.css });
                await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: cs.js });
            } catch (e) {
                console.warn("[PhishLens] could not refresh the script in tab", tab.id, String(e?.message || e));
            }
        }
    }
}

// A click on a notification brings back the Gmail tab that raised it.
const notificationTabs = new Map();
chrome.notifications?.onClicked?.addListener((id) => {
    const tab = notificationTabs.get(id);
    if (!tab) return;
    chrome.tabs.update(tab.tabId, { active: true }).catch((e) => debug("focus tab", e));
    chrome.windows.update(tab.windowId, { focused: true }).catch((e) => debug("focus window", e));
    chrome.notifications.clear(id);
    notificationTabs.delete(id);
});

function notify(msg, sender) {
    const id = "pll-" + Date.now();
    chrome.notifications?.create(id, {
        type: "basic",
        iconUrl: "icons/128.png",
        title: String(msg.title || "PhishLens").slice(0, 120),
        message: String(msg.message || "").slice(0, 300),
        priority: 2,
    });
    if (sender?.tab?.id != null) notificationTabs.set(id, { tabId: sender.tab.id, windowId: sender.tab.windowId });
}

// One POST to the server; resolves to the JSON answer or throws an Error
// with a message for the user.
// An answer that takes longer is treated as no answer: an explanation
// can take seconds on a busy server, a scan far less.
const TIMEOUT_MS = 60_000;

function networkError(e, key) {
    if (e?.name === "TimeoutError" || e?.name === "AbortError") return new Error(text(key));
    const message = String(e?.message || e);
    return new Error(message.startsWith("Failed to fetch") || message.includes("NetworkError") ? text(key) : message);
}

async function post(base, endpoint, payload) {
    let resp;
    try {
        resp = await fetch(`${base}${endpoint}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload || {}),
            signal: AbortSignal.timeout(TIMEOUT_MS),
        });
    } catch (e) {
        throw networkError(e, "bg_unreachable");
    }
    const data = await resp.json().catch(() => null);
    if (!resp.ok) {
        const err = new Error(self.PhishLensShared.apiErrorMessage(data, resp.status));
        err.status = resp.status;
        throw err;
    }
    return data;
}

async function serverBase() {
    const base = await self.PhishLensShared.getBackendBase();
    if (!base) throw new Error(text("no_server"));
    if (!/^https?:\/\//.test(base)) throw new Error(text("url_scheme"));
    return base;
}

// LIME takes seconds on the server: an explanation already computed for
// this text on this server is served from the local cache.
async function explain(payload) {
    const base = await serverBase();
    const hit = await self.PhishLensLimeCache.get(base, payload);
    if (hit) return { features: hit.features, cached: true };
    const data = await post(base, "/explain", payload);
    const features = data?.features || [];
    await self.PhishLensLimeCache.put(base, payload, features);
    return { features, cached: false };
}

async function health() {
    const base = await serverBase();
    let resp;
    try {
        resp = await fetch(`${base}/health`, { signal: AbortSignal.timeout(10_000) });
    } catch (e) {
        throw networkError(e, "server_unreachable");
    }
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return (await resp.json().catch(() => null)) || {};
}

const H = () => self.PhishLensHistory;

// Message type -> handler; each resolves to the `data` of the reply.
const HANDLERS = {
    "phishlens.analyse": async (msg) => post(await serverBase(), "/analyse", msg.payload),
    "phishlens.analyse_attachment": async (msg) => post(await serverBase(), "/analyse_attachment", msg.payload),
    "phishlens.explain": (msg) => explain(msg.payload),
    "phishlens.health": () => health(),
    // Reports always go to PhishLens Cloud, whatever server analyses the
    // mail: they are for improving PhishLens, and the user has seen and
    // confirmed what is sent.
    "phishlens.feedback": (msg) => post(self.PhishLensShared.BACKEND_PRESETS.cloud, "/feedback", msg.payload),
    "phishlens.history.save": (msg) => H().saveScan(msg.entry),
    "phishlens.history.update": (msg) => H().updateScan(msg.id, msg.patch),
    "phishlens.history.draft": (msg) => H().saveDraft(msg.id, msg.text),
    "phishlens.history.attachTokens": (msg) => H().attachTokens(msg.id, msg.tokens),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // Only this extension's own pages and scripts (no page can message it
    // without externally_connectable, but the check costs nothing).
    if (sender?.id !== chrome.runtime.id) return false;
    if (msg?.type === "phishlens.notify") {
        try { notify(msg, sender); } catch (e) { debug("notification", e); }
        sendResponse({ ok: true });
        return false;
    }
    const handler = HANDLERS[msg?.type];
    if (!handler) return false;
    Promise.resolve()
        .then(() => handler(msg))
        .then((data) => sendResponse({ ok: true, data }))
        .catch((e) => sendResponse({ ok: false, error: String(e?.message || e), status: e?.status || null }));
    return true;        // the reply is sent asynchronously
});
