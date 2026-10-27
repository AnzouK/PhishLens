// Small pieces every popup view uses: element lookup, view switching,
// the status line, and the shared libraries (classic scripts in lib/,
// loaded by popup.html before the modules).

export const I18N = window.PhishLensI18n;
export const { t, tn } = I18N;
export const { h, spriteIcon } = window.PhishLensDom;
export const STORAGE = chrome?.storage?.local;

export const $ = (id) => document.getElementById(id);

const VIEWS = ["upload", "loading", "result", "settings", "insights"];

export function showView(name) {
    for (const v of VIEWS) $(`view-${v}`).classList.toggle("view--active", v === name);
}

export function currentView() {
    return VIEWS.find((v) => $(`view-${v}`).classList.contains("view--active")) || "upload";
}

// Settings and Insights go back to the view they were opened from.
let previous = "upload";
export function openView(name) {
    const from = currentView();
    if (from !== "settings" && from !== "insights") previous = from;
    showView(name);
}
export function goBack() {
    showView(previous);
}

export function showStatus(msg, danger = true) {
    const status = $("status");
    status.textContent = msg;
    status.hidden = false;
    status.style.color = danger ? "" : "var(--text-mute)";
}

export function hideStatus() {
    const status = $("status");
    status.hidden = true;
    status.textContent = "";
}

// chrome.storage.local.get as a promise; {} when storage is unavailable.
export function storageGet(keys) {
    return new Promise((resolve) => {
        if (!STORAGE) return resolve({});
        STORAGE.get(keys, (s) => resolve(s || {}));
    });
}
