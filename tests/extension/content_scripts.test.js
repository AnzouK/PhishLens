// The content scripts of each manifest entry, loaded in their manifest
// order in a bare sandbox (stand-ins for the DOM and chrome.*): no error
// at load time, every cross-file function present, and the verdict
// banner renders. Catches a file missing from the manifest or loaded in
// the wrong order, which ESLint cannot see.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const EXT = path.join(__dirname, "..", "..", "extension");
const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

function anyElement() {
    return new Proxy(function () {}, {
        get: (t, k) => (k === Symbol.toPrimitive ? () => "" : k === "length" ? 0 : anyElement()),
        apply: () => anyElement(),
    });
}

function load(entry) {
    const host = new URL(entry.matches[0].replace("*", "")).hostname;
    const ctx = {
        console: { ...console, log() {}, info() {} },
        setTimeout, clearTimeout, URL, TextEncoder, btoa, atob, CSS: { escape: (s) => s },
        location: { hostname: host, hash: "#inbox", pathname: "/mail/u/0/", origin: "https://" + host },
        MutationObserver: class { observe() {} disconnect() {} },
        document: {
            body: {}, scripts: [],
            documentElement: { setAttribute() {}, removeAttribute() {} },
            querySelectorAll: () => [], querySelector: () => null,
            getElementById: () => null, createElement: () => anyElement(),
        },
        chrome: {
            runtime: { id: "test", sendMessage: async () => ({ ok: false }) },
            storage: { local: { get: (k, cb) => cb && cb({}), set: (o, cb) => cb && cb() }, onChanged: { addListener() {} } },
        },
        navigator: { language: "en-US" },
        addEventListener() {},
    };
    ctx.window = ctx;
    ctx.globalThis = ctx;
    ctx.self = ctx;
    vm.createContext(ctx);
    for (const file of entry.js) {
        vm.runInContext(fs.readFileSync(path.join(EXT, file), "utf8"), ctx, { filename: file });
    }
    return { ctx, host };
}

const SHARED = ["showBanner", "attachExplanation", "setBtnLoading", "textOf", "linkTargetsOf", "escapeHTML",
    "pllAttachFeedback"];
const GMAIL = ["scheduleScan", "runScan", "fetchOriginalMessage", "extractGmailAuthSignals",
    "installAttachmentButtons", "scanOneAttachment", "scheduleAutoScan", "runAutoScan", "paintAutoBadges"];

for (const entry of manifest.content_scripts) {
    test(`content scripts for ${entry.matches[0]} load and render`, () => {
        const { ctx, host } = load(entry);
        const want = SHARED.concat(host === "mail.google.com" ? GMAIL : ["olInject"]);
        const missing = want.filter((n) => vm.runInContext(`typeof ${n}`, ctx) !== "function");
        assert.deepEqual(missing, []);
        const showBanner = vm.runInContext("showBanner", ctx);
        showBanner({ querySelector: () => null }, {
            verdict: "phishing", agents: { text: { phishing_probability: 0.9 } },
            sender_auth: {}, url_reputation: { checked: 1 },
        });
    });
}
