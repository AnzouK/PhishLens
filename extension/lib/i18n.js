// Interface translations. The texts live in lib/locales/<lang>.js.
// t("key", {name: value}) returns the text in the chosen language, then
// English, then the key; tn("key", count) picks "key_one" or "key_other".
// The language is the one chosen in Settings ("ui_lang"), or the
// browser's. PhishLens does not use chrome.i18n for this because Chrome
// does not support every language PhishLens has (Hausa).
(function () {
"use strict";

const LANGUAGES = Object.freeze({
    en: "English", fr: "Français", pt: "Português", es: "Español",
    de: "Deutsch", it: "Italiano", nl: "Nederlands", ha: "Hausa",
});
const STORAGE_KEY = "ui_lang";
let current = "en";
const listeners = [];

function dicts() { return globalThis.PhishLensLocales || {}; }

function browserLanguage() {
    const nav = (typeof navigator !== "undefined" && navigator.language) || "en";
    const code = String(nav).slice(0, 2).toLowerCase();
    return LANGUAGES[code] ? code : "en";
}

function resolve(choice) {
    return LANGUAGES[choice] ? choice : browserLanguage();
}

function setLanguage(choice) {
    const next = resolve(choice);
    if (next === current) return;
    current = next;
    listeners.forEach((fn) => {
        try {
            fn(current);
        } catch (e) {
            console.warn("[PhishLens] language change listener failed:", e);
        }
    });
}

function t(key, vars) {
    const d = dicts();
    let s = d[current]?.[key] ?? d.en?.[key] ?? key;
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
    return s;
}

function has(key) {
    return key in (dicts().en || {});
}

// Attachment features reported by the server ("contains_macros") and the
// reasons it gives for files inside an archive ("fake extension").
function flagLabel(flag) {
    return has(`flag_${flag}`) ? t(`flag_${flag}`) : String(flag).replace(/_/g, " ");
}
function reasonLabel(reason) {
    const key = "reason_" + String(reason).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
    return has(key) ? t(key) : String(reason);
}

function tn(key, count, vars) {
    return t(`${key}_${count === 1 ? "one" : "other"}`, { count, ...vars });
}

// Static HTML: data-i18n (text), data-i18n-html (markup from the
// dictionaries, rebuilt by lib/dom.js from an allowlist of tags),
// data-i18n-title, data-i18n-placeholder, data-i18n-aria-label.
function applyTo(root) {
    if (!root?.querySelectorAll) return;
    root.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    root.querySelectorAll("[data-i18n-html]").forEach((el) => globalThis.PhishLensDom.setMarkup(el, t(el.dataset.i18nHtml)));
    for (const attr of ["title", "placeholder", "aria-label"]) {
        const data = "i18n" + attr.replace(/(^|-)(\w)/g, (m, d, c) => c.toUpperCase());
        root.querySelectorAll(`[data-i18n-${attr}]`).forEach((el) => {
            el.setAttribute(attr, t(el.dataset[data]));
        });
    }
}

// Reads the saved choice and follows later changes. Resolves once the
// language is known; t() works before that (in the browser's language).
function init() {
    current = browserLanguage();
    return new Promise((done) => {
        try {
            chrome.storage.local.get([STORAGE_KEY], (s) => { setLanguage(s?.[STORAGE_KEY]); done(current); });
            chrome.storage.onChanged?.addListener((changes, area) => {
                if (area === "local" && changes[STORAGE_KEY]) setLanguage(changes[STORAGE_KEY].newValue);
            });
        } catch {
            done(current);
        }
    });
}

function onChange(fn) { listeners.push(fn); }

const PhishLensI18n = Object.freeze({
    LANGUAGES, STORAGE_KEY, t, tn, has, flagLabel, reasonLabel, init, setLanguage, applyTo, onChange,
    browserLanguage,
    language: () => current,
});
globalThis.PhishLensI18n = PhishLensI18n;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensI18n;
})();
