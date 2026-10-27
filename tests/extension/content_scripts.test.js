// The content scripts of each manifest entry, loaded in their manifest
// order in a sandbox with a small fake DOM (fake_dom.js): no error at
// load time, no name leaked outside the PhishLens namespaces, every
// function the other files call is present, and the banners render text
// from emails as text. Catches a file missing from the manifest or
// loaded in the wrong order, which ESLint cannot see.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { Node, makeDocument } = require("./fake_dom");

const EXT = path.join(__dirname, "..", "..", "extension");
const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

function load(entry, { sendMessage } = {}) {
    const host = new URL(entry.matches[0].replaceAll("*", "")).hostname;
    const document = makeDocument();
    const ctx = {
        console: { ...console, log() {}, info() {}, debug() {} },
        setTimeout, clearTimeout, URL, TextEncoder, btoa, atob, Node, CSS: { escape: (s) => s },
        location: { hostname: host, hash: "#inbox", pathname: "/mail/u/0/", origin: "https://" + host },
        MutationObserver: class { observe() {} disconnect() {} },
        document,
        chrome: {
            runtime: { id: "test", sendMessage: sendMessage || (async () => ({ ok: false })), getManifest: () => ({ version: "test" }) },
            storage: { local: { get: (k, cb) => cb && cb({}), set: (o, cb) => cb && cb() }, onChanged: { addListener() {} } },
        },
        navigator: { language: "en-US" },
        addEventListener() {},
        getComputedStyle: () => ({ backgroundColor: "rgb(255, 255, 255)" }),
    };
    ctx.window = ctx;
    ctx.globalThis = ctx;
    ctx.self = ctx;
    vm.createContext(ctx);
    const before = new Set(Object.keys(ctx));
    for (const file of entry.js) {
        vm.runInContext(fs.readFileSync(path.join(EXT, file), "utf8"), ctx, { filename: file });
    }
    const added = Object.keys(ctx).filter((k) => !before.has(k));
    return { ctx, host, PL: ctx.PhishLensPage, added };
}

const SHARED = ["showBanner", "showError", "attachExplanation", "explainInBackground", "setBtnLoading", "scanButton",
    "textOf", "linkTargetsOf", "attachFeedback", "saveScan", "observe", "alive"];
const GMAIL = ["scheduleScan", "runScan", "fetchOriginalMessage", "extractGmailAuthSignals",
    "installAttachmentButtons", "scheduleAutoScan", "paintAutoBadges", "loadAutoCache"];

// An open email as the scripts find it: a view with a message body.
function mailView(document) {
    const view = document.createElement("div");
    const body = document.createElement("div");
    body.className = "a3s aiL";
    view.append(body);
    document.body.append(view);
    return view;
}

const PHISHING = {
    verdict: "phishing", agents: { text: { phishing_probability: 0.9 } },
    sender_auth: {}, url_reputation: { checked: 1 },
};

for (const entry of manifest.content_scripts) {
    test(`content scripts for ${entry.matches[0]} load and render`, () => {
        const { PL, host, added } = load(entry);
        const want = SHARED.concat(host === "mail.google.com" ? GMAIL : ["olInject"]);
        assert.deepEqual(want.filter((n) => typeof PL[n] !== "function"), []);
        // Each file keeps its names to itself: only the namespaces are global.
        assert.deepEqual(added.filter((k) => !/^PhishLens[A-Z]\w*$/.test(k)), []);
        const view = mailView(makeDocument());
        PL.showBanner(view, PHISHING);
        assert.equal(view.querySelectorAll(".pll-banner").length, 1);
    });
}

test("email text in a banner stays text", () => {
    const { PL, ctx } = load(manifest.content_scripts[0]);
    const view = mailView(ctx.document);
    const evil = '<img src=x onerror="alert(1)">';
    PL.showBanner(view, {
        ...PHISHING,
        forwarded: { detected: true, original_sender: evil },
        shared_links: { count: 1, services: [evil], urls: [evil] },
    });
    const banner = view.querySelector(".pll-banner");
    assert.ok(banner.textContent.includes(evil));
    assert.equal(banner.querySelectorAll("img").length, 0);
    PL.showError(view, new Error(evil));
    assert.equal(view.querySelectorAll(".pll-banner").length, 1);
    assert.ok(view.querySelector(".pll-banner").textContent.includes(evil));
});

test("the explanation words are shown with their relative weight", () => {
    const { PL, ctx } = load(manifest.content_scripts[0]);
    const view = mailView(ctx.document);
    PL.showBanner(view, PHISHING);
    PL.attachExplanation(view, [
        { token: "verify", weight: 0.02, supports: "phishing" },
        { token: "1", weight: 0.5, supports: "phishing" },
        { token: "<b>", weight: 0.01, supports: "safe" },
    ], true);
    const tokens = view.querySelectorAll(".pll-tok");
    assert.deepEqual(tokens.map((n) => n.textContent), ["verify", "<b>"]);
    assert.equal(tokens[0].style.getPropertyValue("--pll-a"), "0.45");
    assert.ok(view.querySelector(".pll-cache-hint"));
});

test("a failed explanation says so instead of waiting forever", async () => {
    const { PL, ctx } = load(manifest.content_scripts[0], {
        sendMessage: async () => ({ ok: false, error: "Server unreachable." }),
    });
    const view = mailView(ctx.document);
    PL.showBanner(view, PHISHING);
    await PL.explainInBackground(view, { raw_text: "x" }, PHISHING, null);
    assert.match(view.querySelector(".pll-banner__tokens").textContent, /Server unreachable/);
});

test("in automatic theme, the banner colours follow the mail page, not the system", () => {
    const { PL, ctx } = load(manifest.content_scripts[0]);
    const theme = () => ctx.document.documentElement.getAttribute("data-phishlens-theme");
    ctx.getComputedStyle = () => ({ backgroundColor: "rgb(32, 33, 36)" });
    PL.applyTheme("auto");
    assert.equal(theme(), "dark");
    ctx.getComputedStyle = () => ({ backgroundColor: "rgb(255, 255, 255)" });
    PL.applyTheme("auto");
    assert.equal(theme(), "light");
    PL.applyTheme("dark");
    assert.equal(theme(), "dark");
});
