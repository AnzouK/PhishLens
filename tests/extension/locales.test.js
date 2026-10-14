// Every interface language has the same keys as English, the same
// {placeholders} and the same HTML tags, and every data-i18n key used in
// popup.html exists. A missing key would fall back to English silently.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.join(__dirname, "..", "..", "extension");
const ctx = { console };
ctx.globalThis = ctx;
vm.createContext(ctx);
for (const f of fs.readdirSync(path.join(EXT, "lib", "locales"))) {
    vm.runInContext(fs.readFileSync(path.join(EXT, "lib", "locales", f), "utf8"), ctx, { filename: f });
}
vm.runInContext(fs.readFileSync(path.join(EXT, "lib", "i18n.js"), "utf8"), ctx, { filename: "i18n.js" });
const LOCALES = ctx.PhishLensLocales;
const I18N = ctx.PhishLensI18n;
const en = LOCALES.en;

const placeholders = (s) => (s.match(/\{\w+\}/g) || []).sort();
const tags = (s) => (s.match(/<\/?\w+/g) || []).sort();

test("one locale file per declared language", () => {
    assert.deepEqual(Object.keys(LOCALES).sort(), Object.keys(I18N.LANGUAGES).sort());
});

for (const lang of Object.keys(LOCALES).filter((l) => l !== "en")) {
    test(`${lang}: same keys, placeholders and tags as en`, () => {
        const d = LOCALES[lang];
        assert.deepEqual(Object.keys(d).sort(), Object.keys(en).sort());
        for (const k of Object.keys(en)) {
            assert.equal(typeof d[k], "string", `${lang}.${k}`);
            assert.ok(d[k].trim(), `${lang}.${k} is empty`);
            assert.deepEqual(placeholders(d[k]), placeholders(en[k]), `${lang}.${k} placeholders`);
            assert.deepEqual(tags(d[k]), tags(en[k]), `${lang}.${k} tags`);
        }
    });
}

test("plural keys come in _one / _other pairs", () => {
    for (const k of Object.keys(en)) {
        if (k.endsWith("_one")) assert.ok(`${k.slice(0, -4)}_other` in en, k);
        if (k.endsWith("_other")) assert.ok(`${k.slice(0, -6)}_one` in en, k);
    }
});

test("popup.html only uses existing keys", () => {
    const html = fs.readFileSync(path.join(EXT, "popup", "popup.html"), "utf8");
    const used = [...html.matchAll(/data-i18n(?:-html|-title|-placeholder|-aria-label)?="([^"]+)"/g)].map((m) => m[1]);
    assert.ok(used.length > 20);
    for (const k of used) assert.ok(k in en, `popup.html uses unknown key ${k}`);
});

test("t() fills placeholders and falls back to English", () => {
    assert.equal(I18N.t("err_server", { status: 502 }), "Server error (HTTP 502).");
    assert.equal(I18N.t("no_such_key"), "no_such_key");
});

test("setLanguage switches the dictionary", () => {
    I18N.setLanguage("fr");
    assert.equal(I18N.t("verdict_safe"), LOCALES.fr.verdict_safe);
    assert.equal(I18N.tn("auto_done", 3), LOCALES.fr.auto_done_other.replace("{count}", "3"));
    I18N.setLanguage("en");
});

test("every t() / tn() key used in the code exists", () => {
    const files = ["background.js", "lib/shared.js", "popup/popup.js"]
        .concat(fs.readdirSync(path.join(EXT, "content_scripts")).map((f) => `content_scripts/${f}`));
    for (const f of files) {
        const src = fs.readFileSync(path.join(EXT, f), "utf8");
        for (const m of src.matchAll(/\bt\(\s*"([\w]+)"/g)) assert.ok(m[1] in en, `${f}: t("${m[1]}")`);
        for (const m of src.matchAll(/\btn\(\s*"([\w]+)"/g)) {
            assert.ok(`${m[1]}_one` in en && `${m[1]}_other` in en, `${f}: tn("${m[1]}")`);
        }
    }
});
