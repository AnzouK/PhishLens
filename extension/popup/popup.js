// Popup entry point: theme, language, the first-run privacy notice, then
// each view (upload.js, result.js, insights.js, settings.js).
import { $, I18N, STORAGE, storageGet, showView } from "./ui.js";
import { initUpload } from "./upload.js";
import { initInsights } from "./insights.js";
import { initSettings, backend, loadBackend } from "./settings.js";

const PRIVACY_NOTICE_KEY = "privacy_notice_seen";

function privacyPolicyUrl(lang) {
    return `https://phishlens.dev/${lang && lang !== "en" ? lang + "/" : ""}privacy.html`;
}

// Says where emails go before the first scan, while PhishLens Cloud is
// the server; hidden for good once dismissed.
async function initPrivacyNotice() {
    const box = $("privacy-notice");
    if (!STORAGE) return;
    const seen = Boolean((await storageGet([PRIVACY_NOTICE_KEY]))[PRIVACY_NOTICE_KEY]);
    const link = $("privacy-notice-link");
    const setLink = () => { link.href = privacyPolicyUrl(I18N.language()); };
    setLink();
    I18N.onChange(setLink);
    box.hidden = seen || backend.choice !== "cloud";
    $("privacy-notice-ok").addEventListener("click", () => {
        box.hidden = true;
        STORAGE.set({ [PRIVACY_NOTICE_KEY]: true });
    });
}

async function initTheme() {
    const { theme } = await storageGet(["theme"]);
    if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
    $("theme-toggle").addEventListener("click", () => {
        const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        STORAGE?.set({ theme: next });
    });
}

function applyLanguage() {
    document.documentElement.lang = I18N.language();
    I18N.applyTo(document);
}

// Registered first: the views re-render after the static texts change.
I18N.onChange(applyLanguage);
$("app-version").textContent = chrome.runtime?.getManifest ? `v${chrome.runtime.getManifest().version}` : "";
initTheme();
initUpload();
initInsights();
initSettings();
loadBackend().then(initPrivacyNotice);
I18N.init().then(applyLanguage);
showView("upload");
