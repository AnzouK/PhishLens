// =====================================================================
// PhishLens background service worker.
// =====================================================================
//   1. Proxies the API calls of the content scripts to the server chosen
//      in Settings (Gmail's page CSP blocks direct requests).
//   2. Saves scans to the local history for the content scripts.
//   3. Shows the desktop notification of the automatic scan.
//   4. After an install or update, refreshes the content scripts in the
//      Gmail / Outlook tabs that are already open.
// The server is only contacted when a scan is requested.
// =====================================================================

try { importScripts("lib/locales/en.js", "lib/locales/fr.js", "lib/locales/pt.js", "lib/locales/es.js", "lib/locales/de.js", "lib/locales/it.js", "lib/locales/nl.js", "lib/locales/ha.js", "lib/i18n.js", "lib/shared.js", "lib/history.js"); self.PhishLensI18n?.init(); }
catch (e) { console.warn("[PhishLens] shared modules not loaded:", e); }

chrome.runtime.onInstalled.addListener((details) => {
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
    // Desktop notification for a phishing email found by the automatic
    // scan. Clicking it focuses the Gmail tab that found it.
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
    if (msg?.type === "phishlens.history.update" || msg?.type === "phishlens.history.draft") {
        (async () => {
            try {
                const H = self.PhishLensHistory;
                if (msg.type === "phishlens.history.update") await H?.updateScan(msg.id, msg.patch);
                else await H?.saveDraft(msg.id, msg.text);
                sendResponse({ ok: true });
            } catch (e) {
                sendResponse({ ok: false, error: String(e?.message || e) });
            }
        })();
        return true;
    }
    // Reports always go to PhishLens Cloud, whatever server analyses the
    // mail: they are for improving PhishLens, and the user has seen and
    // confirmed what is sent.
    if (msg?.type === "phishlens.feedback") {
        (async () => {
            try {
                const resp = await fetch(`${self.PhishLensShared.BACKEND_PRESETS.cloud}/feedback`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(msg.payload || {}),
                });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) throw new Error(self.PhishLensShared.apiErrorMessage(data, resp.status));
                sendResponse({ ok: true, reference: data.reference });
            } catch (e) {
                sendResponse({ ok: false, error: String(e?.message || e) });
            }
        })();
        return true;
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
        const base = await self.PhishLensShared.getBackendBase();
        if (!base) {
            sendResponse({ ok: false,
                error: self.PhishLensI18n?.t("no_server") || "No server configured." });
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
                sendResponse({ ok: false, error: self.PhishLensShared.apiErrorMessage(data, r.status) });
            } else {
                sendResponse({ ok: true, data });
            }
        } catch (e) {
            sendResponse({
                ok: false,
                error: String(e?.message || e).startsWith("Failed to fetch")
                    ? (self.PhishLensI18n?.t("bg_unreachable") || "Server unreachable.")
                    : String(e?.message || e),
            });
        }
    })();

    return true;        // keep the message channel open for the async response
});
