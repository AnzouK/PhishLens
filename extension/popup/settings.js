// The Settings view: server, language, Gmail options. Every choice is
// saved in chrome.storage.local at once; the service worker and the
// content scripts read it from there.
import { $, I18N, t, STORAGE, storageGet, openView, goBack } from "./ui.js";

const { DEFAULT_BACKEND } = window.PhishLensShared;
const BACKENDS = ["cloud", "local", "custom"];

export const backend = { choice: DEFAULT_BACKEND, customUrl: "" };

export async function loadBackend() {
    const s = await storageGet(["backend", "backend_custom_url"]);
    if (BACKENDS.includes(s.backend)) backend.choice = s.backend;
    if (typeof s.backend_custom_url === "string") backend.customUrl = s.backend_custom_url;
}

// http:// to a remote server would send emails in clear text. Local and
// private-network addresses are fine: nothing leaves the home network.
export function isPlainRemoteUrl(value) {
    let u;
    try {
        u = new URL(value);
    } catch {
        return false;            // not a URL yet (still being typed)
    }
    if (u.protocol !== "http:") return false;
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host === "::1") return false;
    const m = host.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
    if (m) {
        const a = Number(m[1]), b = Number(m[2]);
        if (a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)) return false;
    }
    return true;
}

const customUrlInput = $("custom-url");
const connStatus = $("conn-status");

function updateCustomUrlWarn() {
    $("custom-url-warn").hidden = !(backend.choice === "custom" && isPlainRemoteUrl(customUrlInput.value.trim()));
}

function render() {
    document.querySelectorAll('input[name="backend"]').forEach((r) => { r.checked = r.value === backend.choice; });
    customUrlInput.value = backend.customUrl;
    customUrlInput.disabled = backend.choice !== "custom";
    setConnStatus(null);
    updateCustomUrlWarn();
}

function setConnStatus(kind, text = "") {
    connStatus.hidden = !kind;
    connStatus.className = kind ? `conn-status conn-status--${kind}` : "conn-status";
    connStatus.textContent = text;
}

async function testConnection() {
    setConnStatus("info", t("testing"));
    try {
        const data = await window.PhishLensApi.health();
        // Servers before 1.15.5 report neither their version nor the model.
        setConnStatus("ok", data?.version
            ? t("connected", { version: data.version, model: data.text_model?.name || data.text_model?.source || t("unknown") })
            : t("connected_old"));
    } catch (e) {
        setConnStatus("err", e.message);
    }
}

function fillLanguageMenu(choice) {
    const select = $("ui-lang");
    select.replaceChildren(new Option(t("language_auto"), "auto"),
        ...Object.entries(I18N.LANGUAGES).map(([code, name]) => new Option(name, code)));
    select.value = choice || "auto";
}

export function initSettings() {
    $("settings-btn").addEventListener("click", () => { render(); openView("settings"); });
    $("settings-back").addEventListener("click", goBack);

    document.querySelectorAll('input[name="backend"]').forEach((r) => {
        r.addEventListener("change", () => {
            if (!r.checked) return;
            backend.choice = r.value;
            customUrlInput.disabled = backend.choice !== "custom";
            STORAGE?.set({ backend: backend.choice });
            if (backend.choice === "custom" && !customUrlInput.value) customUrlInput.focus();
            updateCustomUrlWarn();
        });
    });
    customUrlInput.addEventListener("input", () => {
        backend.customUrl = customUrlInput.value.trim();
        STORAGE?.set({ backend_custom_url: backend.customUrl });
        updateCustomUrlWarn();
    });
    $("test-conn-btn").addEventListener("click", testConnection);

    const fullHeaders = $("opt-full-headers");
    const autoScan = $("opt-auto-scan");
    storageGet(["opt_full_headers", "opt_auto_scan"]).then((s) => {
        fullHeaders.checked = s.opt_full_headers !== false;
        autoScan.checked = s.opt_auto_scan === true;
    });
    fullHeaders.addEventListener("change", () => STORAGE?.set({ opt_full_headers: fullHeaders.checked }));
    autoScan.addEventListener("change", () => STORAGE?.set({ opt_auto_scan: autoScan.checked }));

    // The static texts carry data-i18n attributes; the dynamic ones are
    // built with t() each time they are shown.
    const select = $("ui-lang");
    select.addEventListener("change", () => {
        STORAGE?.set({ [I18N.STORAGE_KEY]: select.value });
        I18N.setLanguage(select.value);
    });
    storageGet([I18N.STORAGE_KEY]).then((s) => fillLanguageMenu(s[I18N.STORAGE_KEY]));
    I18N.onChange(() => fillLanguageMenu(select.value));
}
