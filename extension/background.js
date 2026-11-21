// PhishLens service worker: makes every request to the PhishLens server
// (lib/api.js sends them here), keeps the local history for the content
// scripts, shows the automatic scan's notifications, and refreshes the
// content scripts of open mail tabs after an install or an update.
// The server is only contacted when a scan or a report is requested.

// Chrome runs this file as a service worker, which loads the libraries
// here. Firefox runs it as an event page whose manifest lists the same
// files before it (scripts/build_extension.py reads this list).
// A missing file stops the worker with the browser's own error, shown on
// the extensions page, since nothing below works without these libraries.
if (typeof importScripts === "function") {
    importScripts(
        "lib/locales/en.js", "lib/locales/fr.js", "lib/locales/pt.js", "lib/locales/es.js",
        "lib/locales/de.js", "lib/locales/it.js", "lib/locales/nl.js", "lib/locales/ha.js",
        "lib/i18n.js", "lib/shared.js", "lib/history.js", "lib/lime_cache.js");
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
// an install or an update, so without this the user would have to reload
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

// A click on a notification brings back the Gmail tab that raised it. The
// tab and window are stored in the notification's id because an idle
// worker is stopped and loses its memory.
function notificationTab(id) {
    const m = /^pll-(\d+)-(\d+)-/.exec(String(id));
    return m ? { tabId: Number(m[1]), windowId: Number(m[2]) } : null;
}

chrome.notifications?.onClicked?.addListener((id) => {
    const tab = notificationTab(id);
    chrome.notifications.clear(id);
    if (!tab) return;
    chrome.tabs.update(tab.tabId, { active: true }).catch((e) => debug("focus tab", e));
    chrome.windows.update(tab.windowId, { focused: true }).catch((e) => debug("focus window", e));
});

function notify(msg, sender) {
    const tab = sender?.tab;
    const id = tab?.id != null ? `pll-${tab.id}-${tab.windowId ?? 0}-${Date.now()}` : `pll-x-${Date.now()}`;
    chrome.notifications?.create(id, {
        type: "basic",
        iconUrl: "icons/128.png",
        title: String(msg.title || "PhishLens").slice(0, 120),
        message: String(msg.message || "").slice(0, 300),
        priority: 2,
    });
}

// One POST to the server. Resolves to the JSON answer or throws an Error
// with a message for the user. The timeout is generous because an
// explanation can take seconds on a busy server; a scan takes far less.
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
    if (!/^https?:\/\//i.test(base)) throw new Error(text("url_scheme"));
    // Plain http:// over the internet is allowed only after the user has
    // confirmed that exact address in Settings.
    if (self.PhishLensShared.isPlainRemoteUrl(base)) {
        const ok = await new Promise((r) => chrome.storage.local.get(["backend_http_ok"], (s) => r(s?.backend_http_ok)));
        if (self.PhishLensShared.normalizeBaseUrl(ok) !== base) throw new Error(text("err_http_remote"));
    }
    return base;
}

// LIME takes seconds on the server, so an explanation already computed
// for this text on this server comes from the local cache.
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

// Message type to handler. Each resolves to the `data` of the reply.
const HANDLERS = {
    "phishlens.analyse": async (msg) => post(await serverBase(), "/analyse", msg.payload),
    "phishlens.analyse_attachment": async (msg) => post(await serverBase(), "/analyse_attachment", msg.payload),
    "phishlens.explain": (msg) => explain(msg.payload),
    "phishlens.health": () => health(),
    // Reports always go to PhishLens Cloud, whichever server analyses the
    // mail. They are used to improve PhishLens, and the user has seen and
    // confirmed what is sent.
    "phishlens.feedback": (msg) => post(self.PhishLensShared.BACKEND_PRESETS.cloud, "/feedback", msg.payload),
    "phishlens.history.save": (msg) => H().saveScan(msg.entry),
    "phishlens.history.update": (msg) => H().updateScan(msg.id, msg.patch),
    "phishlens.history.draft": (msg) => H().saveDraft(msg.id, msg.text),
    "phishlens.history.attachTokens": (msg) => H().attachTokens(msg.id, msg.tokens),
    "phishlens.history.label": (msg) => H().setLabel(msg.id, msg.label),
    "phishlens.history.remove": (msg) => H().deleteScan(msg.id),
    "phishlens.history.clear": () => H().clearHistory(),
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    // Accept only this extension's own pages and scripts. Without
    // externally_connectable no web page can send messages anyway, but the
    // check is cheap.
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
