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

test("before the first PhishLens Cloud scan, the page shows where the email goes", async () => {
    const { PL, ctx } = load(manifest.content_scripts[0]);
    const store = {};
    ctx.chrome.storage.local = {
        get: (keys, cb) => cb(Object.fromEntries(keys.filter((k) => k in store).map((k) => [k, store[k]]))),
        set: (obj) => Object.assign(store, obj),
    };
    const view = mailView(ctx.document);
    const answer = PL.confirmCloudUse(view);
    await new Promise((r) => setTimeout(r, 0));
    const banner = view.querySelector(".pll-banner");
    assert.match(banner.textContent, /PhishLens Cloud/);
    banner.querySelector(".pll-att-btn").dispatch("click");
    assert.equal(await answer, true);
    assert.equal(store.privacy_notice_seen, true);
    assert.equal(view.querySelectorAll(".pll-banner").length, 0);
    // Seen once: no notice any more, and none with a local server.
    assert.equal(await PL.confirmCloudUse(view), true);
    delete store.privacy_notice_seen;
    store.backend = "local";
    assert.equal(await PL.confirmCloudUse(view), true);
});

test("a signed-by line written in the email body is not taken for Gmail's", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const view = mailView(ctx.document);
    const row = (parent, label, value) => {
        const a = ctx.document.createElement("span");
        a.textContent = label;
        const b = ctx.document.createElement("span");
        b.textContent = value;
        parent.append(a, b);
    };
    row(view.querySelector(".a3s"), "signed-by:", "bank.example");
    assert.equal(PL.extractGmailAuthSignals(view, view).signedBy, null);
    row(view, "signed-by:", "real.example");
    assert.equal(PL.extractGmailAuthSignals(view, view).signedBy, "real.example");
});

test("hidden text and hidden links come after what the reader sees", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const hidden = doc.createElement("div");
    hidden.getClientRects = () => [];
    hidden.append("meeting notes nobody sees");
    const decoys = [];
    for (let i = 0; i < 60; i++) {
        const a = doc.createElement("a");
        a.href = `https://big.example/${i}`;
        decoys.push(a);
    }
    hidden.append(...decoys);
    const p = doc.createElement("p");
    p.append("Verify your account");
    const link = doc.createElement("a");
    link.href = "https://evil.example/login";
    link.append("Verify");
    body.append(hidden, p, link);
    assert.equal(PL.textOf(body), "Verify your accountVerify\nmeeting notes nobody sees");
    const links = PL.linkTargetsOf(body);
    assert.equal(links[0], "https://evil.example/login");
    assert.equal(links.length, 50);
});

test("hidden parts of one letter each are moved too", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    for (const letter of "abc") {
        const span = doc.createElement("span");
        span.getClientRects = () => [];
        span.append(letter);
        body.append(span);
    }
    const p = doc.createElement("p");
    p.append("Verify your account");
    body.append(p);
    assert.equal(PL.textOf(body), "Verify your account\na\nb\nc");
    // the marks are removed once the text is read
    assert.equal(body.dump().includes("data-pll-hidden"), false);
});

test("a display name is sent without invisible characters and cut at 200", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { PL } = load(entry);
    assert.equal(PL.senderName("​".repeat(300) + "PayPal"), "PayPal");
    assert.equal(PL.senderName("x".repeat(500)).length, 200);
    assert.equal(PL.senderName("  "), null);
});

test("the style sheet of a hidden part is not read as words", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const hidden = doc.createElement("div");
    hidden.getClientRects = () => [];
    const style = doc.createElement("style");
    style.append(".x { color: red }");
    hidden.append(style, "minutes of the meeting");
    const p = doc.createElement("p");
    p.append("Verify your account");
    body.append(hidden, p);
    assert.equal(PL.textOf(body), "Verify your account\nminutes of the meeting");
});

test("text drawn in a transparent colour counts as hidden", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const el = ctx.document.createElement("span");
    ctx.getComputedStyle = () => ({ color: "rgba(0, 0, 0, 0)", opacity: "1", fontSize: "14px" });
    assert.equal(PL.isHidden(el), true);
    ctx.getComputedStyle = () => ({ color: "rgb(0, 0, 0)", opacity: "1", fontSize: "14px", clipPath: "inset(100%)" });
    assert.equal(PL.isHidden(el), true);
    ctx.getComputedStyle = () => ({ color: "rgb(0, 0, 0)", opacity: "1", fontSize: "14px", clipPath: "none" });
    assert.equal(PL.isHidden(el), false);
});

// The same cases as backend/tests/test_bypasses.py: the server reads the
// inline style, the extension the computed one; both must agree.
const HIDDEN_CASES = require(path.join(__dirname, "..", "fixtures", "hidden_cases.json")).cases;
for (const c of HIDDEN_CASES) {
    test(`hidden style case: ${c.name}`, () => {
        const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
        const { ctx, PL } = load(entry);
        const parent = ctx.document.createElement("div");
        const el = ctx.document.createElement("div");
        parent.append(el);
        el.getClientRects = () => (c.rects === 0 ? [] : [{ width: 300, height: 20 }]);
        el.getBoundingClientRect = () => c.box || { width: 300, height: 20 };
        const parentStyle = { backgroundColor: c.parentBackground || "rgba(0, 0, 0, 0)", backgroundImage: "none" };
        ctx.getComputedStyle = (n) => (n === parent ? parentStyle : c.computed);
        assert.equal(PL.isHidden(el), c.hidden);
    });
}

test("visible and hidden links are sent apart, a second visible one first", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const link = (href) => {
        const a = doc.createElement("a");
        a.href = href;
        a.append("link");
        return a;
    };
    const hidden = doc.createElement("div");
    hidden.getClientRects = () => [];
    for (let i = 0; i < 60; i++) hidden.append(link(`https://d${i}.example/`));
    body.append(link("https://docs.google.com/a"), link("https://docs.google.com/phish"), hidden);
    const groups = PL.linkGroupsOf(body);
    assert.deepEqual([...groups.visible], ["https://docs.google.com/a", "https://docs.google.com/phish"]);
    assert.equal(groups.hidden.length, 48);
});

test("Outlook reads the sender's own address, not one in the display name", () => {
    const entry = manifest.content_scripts.find((e) => !e.matches[0].includes("mail.google.com"));
    const { PL } = load(entry);
    assert.equal(PL.senderAddress(['"support@gtbank.com" <scam@attacker.example>']), "scam@attacker.example");
    assert.equal(PL.senderAddress(["support@gtbank.com scam@attacker.example"]), "scam@attacker.example");
    assert.equal(PL.senderAddress(["Ana Silva"]), "");
});

test("thousands of anchors without an address do not hide the links after them", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    for (let i = 0; i < 2500; i++) {
        const a = doc.createElement("a");
        a.href = "#";
        body.append(a);
    }
    const real = doc.createElement("a");
    real.href = "https://evil.example/login";
    real.append("Verify");
    body.append(real);
    assert.deepEqual([...PL.linkGroupsOf(body).visible], ["https://evil.example/login"]);
});

test("Outlook takes the last address between angle brackets, over every part of the line", () => {
    const entry = manifest.content_scripts.find((e) => !e.matches[0].includes("mail.google.com"));
    const { PL } = load(entry);
    assert.equal(PL.senderAddress(['"PayPal <service@paypal.com>" <scam@attacker.example>']), "scam@attacker.example");
    assert.equal(PL.senderAddress(["support@gtbank.com", "Support", "scam@attacker.example"]), "scam@attacker.example");
});

test("a link whose only text is hidden counts as hidden", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const decoy = doc.createElement("a");
    decoy.href = "https://d0.example/";
    const span = doc.createElement("span");
    span.getClientRects = () => [];
    span.append("Click here");
    decoy.append(span);
    const empty = doc.createElement("a");
    empty.href = "https://d1.example/";
    const real = doc.createElement("a");
    real.href = "https://evil.example/login";
    real.append("Verify");
    body.append(decoy, empty, real);
    const groups = PL.linkGroupsOf(body);
    assert.deepEqual([...groups.visible], ["https://evil.example/login"]);
    assert.deepEqual([...groups.hidden], ["https://d0.example/", "https://d1.example/"]);
});

test("a dark section whose paragraphs are white stays visible; its own dark text does not", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const section = doc.createElement("div");
    const p = doc.createElement("p");
    p.append("Your statement is ready");
    section.append("filler", p);
    body.append(section);
    const styles = new Map([
        [section, { color: "rgb(0, 0, 0)", backgroundColor: "rgb(17, 17, 17)", opacity: "1", fontSize: "14px", visibility: "visible" }],
        [p, { color: "rgb(255, 255, 255)", backgroundColor: "rgba(0, 0, 0, 0)", opacity: "1", fontSize: "14px", visibility: "visible" }],
    ]);
    ctx.getComputedStyle = (n) => styles.get(n) || { color: "rgb(0, 0, 0)", backgroundColor: "rgba(0, 0, 0, 0)", opacity: "1", fontSize: "14px", visibility: "visible" };
    const hidden = PL.hiddenParts(body);
    assert.equal(hidden.boxes.length, 0);
    assert.deepEqual([...hidden.texts], [section]);
    assert.equal(PL.textOf(body, hidden), "Your statement is ready\nfiller");
});

test("a link whose only picture is invisible counts as hidden", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const doc = ctx.document;
    const body = mailView(doc).querySelector(".a3s");
    const decoy = doc.createElement("a");
    decoy.href = "https://d0.example/";
    const img = doc.createElement("img");
    decoy.append(img);
    const real = doc.createElement("a");
    real.href = "https://evil.example/login";
    real.append("Verify");
    body.append(decoy, real);
    const visible = { color: "rgb(0, 0, 0)", backgroundColor: "rgba(0, 0, 0, 0)", opacity: "1", fontSize: "14px", visibility: "visible" };
    ctx.getComputedStyle = (n) => (n === img ? { ...visible, visibility: "hidden" } : visible);
    assert.deepEqual([...PL.linkGroupsOf(body).visible], ["https://evil.example/login"]);
});

test("file names that reorder text are shown with the reordering mark visible", () => {
    const shared = require(path.join(EXT, "lib", "shared.js"));
    assert.equal(shared.safeName("invoice‮fdp.exe"), "invoice␠fdp.exe");
    assert.equal(shared.safeName("report.pdf"), "report.pdf");
});

test("words a style sheet writes with ::before are read", () => {
    const entry = manifest.content_scripts.find((e) => e.matches[0].includes("mail.google.com"));
    const { ctx, PL } = load(entry);
    const body = mailView(ctx.document).querySelector(".a3s");
    const p = ctx.document.createElement("p");
    p.append("Hello");
    body.append(p);
    const plain = { color: "rgb(0, 0, 0)", backgroundColor: "rgba(0, 0, 0, 0)", opacity: "1", fontSize: "14px", visibility: "visible", content: "normal" };
    ctx.getComputedStyle = (n, pseudo) => (n === p && pseudo === "::before" ? { ...plain, content: '"Verify your account now"' } : plain);
    assert.equal(PL.textOf(body), "Hello\nVerify your account now");
});
