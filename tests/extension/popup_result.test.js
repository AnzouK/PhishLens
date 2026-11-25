// The popup's Result view (popup/result.js) rendered in the small fake
// DOM: the caution line and its reason, the badges that explain it, and
// the agent cards coloured by the same levels as the banner's meters.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { Node, makeDocument } = require("./fake_dom");
const { installFakeChrome } = require("./helpers");

const EXT = path.join(__dirname, "..", "..", "extension");

// The elements of the Result view that result.js fills, by id.
function resultView(document) {
    const el = (tag, id, parent = document.body, cls = "") => {
        const node = document.createElement(tag);
        if (id) node.id = id;
        if (cls) node.className = cls;
        parent.append(node);
        return node;
    };
    for (const id of ["verdict-card", "verdict-icon", "verdict-label", "verdict-trusted", "verdict-sub", "archive-files"]) el("div", id);
    for (const prefix of ["text", "url", "meta"]) {
        const card = el("div", null, document.body, "agent");
        el("span", `${prefix}-score`, card);
        el("span", `${prefix}-bar`, card);
        el("div", `${prefix}-hint`, card);
        if (prefix !== "text") el("div", `${prefix}-badges`, card);
    }
    const panel = el("details", "explain-panel");
    el("div", "explain-tokens", panel);
    el("p", "explain-status", panel);
}

let renderResult;
let document;
test.before(async () => {
    installFakeChrome();
    document = makeDocument();
    Object.assign(globalThis, { document, Node, window: globalThis });
    for (const file of ["locales/en.js", "i18n.js", "shared.js", "constants.js", "dom.js"]) require(path.join(EXT, "lib", file));
    resultView(document);
    ({ renderResult } = await import(pathToFileURL(path.join(EXT, "popup", "result.js")).href));
});

const $ = (id) => document.getElementById(id);
const badges = (id) => $(id).children.map((b) => [b.className.replace("badge badge--", ""), b.textContent]);

function safe(extra = {}) {
    return {
        verdict: "safe",
        agents: {
            text: { phishing_probability: 0.1, verdict: "Safe" },
            url: { phishing_probability: 0.05, verdict: "Safe" },
            metadata: { phishing_probability: 0.2, verdict: "Safe" },
        },
        sender_auth: {}, url_reputation: { checked: 0, malicious_count: 0 },
        ...extra,
    };
}

test("a forwarded email in the caution style says why, with a warn badge", () => {
    renderResult(safe({ forwarded: { detected: true, original_sender: "boss@example.com" } }));
    assert.ok($("verdict-card").classList.contains("verdict-card--caution"));
    assert.equal($("verdict-sub").textContent,
        "Some signs are unusual. Look at the details before you click or reply. " +
        "Forwarded email: the forwarder's trust was not applied to the content.");
    assert.deepEqual(badges("meta-badges"), [["warn", "Forwarded: boss@example.com"]]);
    assert.equal($("meta-badges").hidden, false);
});

test("a shared file in the caution style says why, with a warn badge", () => {
    renderResult(safe({ shared_links: { count: 1, services: ["Google Drive"], urls: ["https://drive.google.com/x"] } }));
    assert.match($("verdict-sub").textContent, /^Some signs are unusual\. .* Links to a shared file or form \(Google Drive\)/);
    assert.deepEqual(badges("url-badges"), [["warn", "Shared file: Google Drive"]]);
    assert.equal($("url-badges").hidden, false);
});

test("a high score next to a DKIM-proven sender gives the DKIM reason", () => {
    const data = safe({ trust_path: "crypto_verified", sender_auth: { cryptographically_verified: true } });
    data.agents.text.phishing_probability = 0.8;
    renderResult(data);
    assert.match($("verdict-sub").textContent, /^Some signs are unusual\. .* Sender identity confirmed by DKIM signature\.$/);
});

test("agent cards use the meter levels: 60% is orange, not red, and not caution", () => {
    const data = safe();
    data.agents.text = { phishing_probability: 0.6, verdict: "Phishing" };
    renderResult(data);
    assert.ok(!$("verdict-card").classList.contains("verdict-card--caution"));
    assert.equal($("text-bar").closest(".agent").dataset.level, "mid");
    assert.equal($("meta-bar").closest(".agent").dataset.level, "low");
    // Red from 70%, as in the banner (and then shown with caution).
    data.agents.url.phishing_probability = 0.72;
    renderResult(data);
    assert.equal($("url-bar").closest(".agent").dataset.level, "high");
    assert.ok($("verdict-card").classList.contains("verdict-card--caution"));
});

test("a file in the caution style uses the file wording", () => {
    renderResult(safe({ attachment: { kind: "pdf", notable_features: ["contains_javascript"] } }));
    assert.ok($("verdict-card").classList.contains("verdict-card--caution"));
    assert.match($("verdict-sub").textContent, /^Some signs are unusual\. Look at the details before you open it\./);
});

test("SPF failing next to a DMARC pass stays safe, its badge is neutral", () => {
    renderResult(safe({ sender_auth: { spf: "fail", dkim: "pass", dmarc: "pass" } }));
    assert.ok(!$("verdict-card").classList.contains("verdict-card--caution"));
    assert.deepEqual(badges("meta-badges").map(([kind]) => kind), ["neutral", "good", "good"]);
});
