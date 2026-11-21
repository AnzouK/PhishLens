// The Settings view (server, language, Gmail options). Every choice is
// saved in chrome.storage.local at once, and the service worker and the
// content scripts read it from there.
import { $, I18N, t, STORAGE, storageGet, openView, goBack } from "./ui.js";

const { DEFAULT_BACKEND, normalizeBaseUrl, hostPattern } = window.PhishLensShared;
const BACKENDS = ["cloud", "local", "custom"];

export const backend = { choice: DEFAULT_BACKEND, customUrl: "" };

export async function loadBackend() {
    const s = await storageGet(["backend", "backend_custom_url"]);
    if (BACKENDS.includes(s.backend)) backend.choice = s.backend;
    if (typeof s.backend_custom_url === "string") backend.customUrl = s.backend_custom_url;
}

// The rule lives in lib/shared.js because the service worker applies it
// too.
export const isPlainRemoteUrl = window.PhishLensShared.isPlainRemoteUrl;

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
        const vars = { version: data?.version, model: data?.text_model?.name || data?.text_model?.source || t("unknown") };
        if (!data?.version) setConnStatus("ok", t("connected_old"));
        else if (data.text_model?.legacy) setConnStatus("warn", t("connected_legacy", vars));
        else setConnStatus("ok", t("connected", vars));
    } catch (e) {
        setConnStatus("err", e.message);
    }
}

// Optional host permissions, requested during a click. A refusal breaks
// nothing, since the server's CORS headers still apply.
function requestOrigins(origins) {
    origins = origins.filter(Boolean);
    if (!origins.length) return;
    try {
        chrome.permissions?.request({ origins })?.catch?.(() => {});
    } catch (e) {
        console.debug("[PhishLens] permission not requested:", e?.message || e);
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
            // The optional permission for a local server is requested
            // during the choice itself, which is a user gesture. Without it
            // the server's CORS headers still let the extension in.
            if (backend.choice === "local") requestOrigins(["http://127.0.0.1/*", "http://localhost/*"]);
            customUrlInput.disabled = backend.choice !== "custom";
            STORAGE?.set({ backend: backend.choice });
            if (backend.choice === "custom" && !customUrlInput.value) customUrlInput.focus();
            updateCustomUrlWarn();
        });
    });
    // Saved when the address is complete (Enter or leaving the field)
    // rather than at every key, so a half-typed address never becomes the
    // server. http:// over the internet needs a confirmation, remembered
    // for that address.
    customUrlInput.addEventListener("input", updateCustomUrlWarn);
    customUrlInput.addEventListener("change", () => {
        const url = normalizeBaseUrl(customUrlInput.value);
        if (url && !/^https?:\/\/[^/\s]+/i.test(url)) {
            setConnStatus("err", t("url_scheme"));
            return;
        }
        if (isPlainRemoteUrl(url)) {
            if (!confirm(t("custom_url_http_confirm"))) {
                customUrlInput.value = backend.customUrl;
                updateCustomUrlWarn();
                return;
            }
            STORAGE?.set({ backend_http_ok: url });
        }
        backend.customUrl = url;
        customUrlInput.value = url;
        STORAGE?.set({ backend_custom_url: url });
        if (url) requestOrigins([hostPattern(url)]);
        setConnStatus(null);
        updateCustomUrlWarn();
    });
    $("test-conn-btn").addEventListener("click", () => {
        // Not a URL yet, so there is no pattern and the test below says so.
        if (backend.choice === "custom") requestOrigins([hostPattern(backend.customUrl)]);
        testConnection();
    });

    const fullHeaders = $("opt-full-headers");
    const autoScan = $("opt-auto-scan");
    storageGet(["opt_full_headers", "opt_auto_scan"]).then((s) => {
        fullHeaders.checked = s.opt_full_headers !== false;
        autoScan.checked = s.opt_auto_scan === true;
    });
    fullHeaders.addEventListener("change", () => STORAGE?.set({ opt_full_headers: fullHeaders.checked }));
    autoScan.addEventListener("change", () => STORAGE?.set({ opt_auto_scan: autoScan.checked }));

    // The static texts carry data-i18n attributes. The dynamic ones are
    // built with t() each time they are shown.
    const select = $("ui-lang");
    select.addEventListener("change", () => {
        STORAGE?.set({ [I18N.STORAGE_KEY]: select.value });
        I18N.setLanguage(select.value);
    });
    storageGet([I18N.STORAGE_KEY]).then((s) => fillLanguageMenu(s[I18N.STORAGE_KEY]));
    I18N.onChange(() => fillLanguageMenu(select.value));
}
