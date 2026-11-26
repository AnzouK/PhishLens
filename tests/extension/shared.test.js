"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { installFakeChrome, loadLib } = require("./helpers");

test("backend choice resolves to a URL without a trailing slash", async () => {
    const store = installFakeChrome();
    const S = loadLib("shared.js");
    assert.equal(await S.getBackendBase(), S.BACKEND_PRESETS.cloud);
    store.backend = "local";
    assert.equal(await S.getBackendBase(), "http://127.0.0.1:8000");
    store.backend = "custom";
    store.backend_custom_url = "https://phishlens.example.org/";
    assert.equal(await S.getBackendBase(), "https://phishlens.example.org");
    assert.equal(S.resolveBackend("unknown"), S.BACKEND_PRESETS.cloud);
});

test("API error messages are always readable text", () => {
    const S = loadLib("shared.js");
    assert.equal(S.apiErrorMessage({ detail: "Could not parse this email." }, 400), "Could not parse this email.");
    assert.match(S.apiErrorMessage({ detail: [{ loc: ["body"], msg: "too long" }] }, 422), /too large/);
    assert.match(S.apiErrorMessage(null, 429), /Too many/);
    assert.match(S.apiErrorMessage(null, 500), /HTTP 500/);
});

test("no manifest host pattern carries a port (Firefox)", () => {
    const manifest = require("../../extension/manifest.json");
    const patterns = [...manifest.host_permissions, ...manifest.optional_host_permissions,
        ...manifest.content_scripts.flatMap((c) => c.matches)];
    for (const p of patterns) assert.doesNotMatch(p, /^[a-z*]+:\/\/[^/]*:\d+\//, p);
});

test("addresses are normalized once, host patterns have no port", async () => {
    const store = installFakeChrome();
    const S = loadLib("shared.js");
    assert.equal(S.normalizeBaseUrl("  http://example.com:8080///  "), "http://example.com:8080");
    assert.equal(S.normalizeBaseUrl(undefined), "");
    assert.equal(S.normalizeBaseUrl(" HTTPS://Example.com/Path/ "), "https://Example.com/Path");
    assert.equal(S.normalizeBaseUrl("Http://example.com"), "http://example.com");
    store.backend = "custom";
    store.backend_custom_url = " http://example.com:8080/ ";
    assert.equal(await S.getBackendBase(), "http://example.com:8080");
    assert.equal(S.hostPattern("http://example.com:8080/"), "http://example.com/*");
    assert.equal(S.hostPattern("https://[fd12::1]:8443"), "https://[fd12::1]/*");
    assert.equal(S.hostPattern("not a url"), null);
    assert.equal(S.hostPattern("ftp://example.com"), null);
});

test("a confirmed http:// address with a trailing slash counts", async () => {
    const fs = require("node:fs");
    const path = require("node:path");
    const vm = require("node:vm");
    const store = installFakeChrome();
    let onMessage = null;
    const chrome = {
        ...globalThis.chrome,
        runtime: { id: "test", onInstalled: { addListener() {} }, onMessage: { addListener: (fn) => { onMessage = fn; } } },
    };
    const fetched = [];
    const ctx = {
        console, chrome, AbortSignal, structuredClone, URL,
        fetch: async (url) => { fetched.push(url); return { ok: true, json: async () => ({ version: "x" }) }; },
    };
    ctx.self = ctx;
    ctx.globalThis = ctx;
    vm.createContext(ctx);
    const ext = path.join(__dirname, "..", "..", "extension");
    for (const f of ["lib/shared.js", "background.js"]) {
        vm.runInContext(fs.readFileSync(path.join(ext, f), "utf8"), ctx, { filename: f });
    }
    store.backend = "custom";
    store.backend_custom_url = "http://example.com:8080/";
    store.backend_http_ok = "http://example.com:8080/";
    const reply = await new Promise((resolve) => onMessage({ type: "phishlens.health" }, { id: "test" }, resolve));
    assert.equal(reply.ok, true, reply.error);
    assert.deepEqual(fetched, ["http://example.com:8080/health"]);
    store.backend_custom_url = "HTTP://example.com:8080/";
    const upper = await new Promise((resolve) => onMessage({ type: "phishlens.health" }, { id: "test" }, resolve));
    assert.equal(upper.ok, true, upper.error);
    assert.equal(fetched.at(-1), "http://example.com:8080/health");
    store.backend_http_ok = "http://other.example/";
    const refused = await new Promise((resolve) => onMessage({ type: "phishlens.health" }, { id: "test" }, resolve));
    assert.equal(refused.ok, false);
});

test("SPF failing next to a DMARC pass is not an unusual sign", () => {
    const S = loadLib("shared.js");
    const safe = (auth) => ({
        verdict: "safe",
        agents: { text: { phishing_probability: 0.1 }, url: { phishing_probability: 0.05 }, metadata: { phishing_probability: 0.2 } },
        sender_auth: auth, url_reputation: { checked: 2, malicious_count: 0 },
    });
    // A mailing list: SPF fails on the list's server, DKIM and DMARC pass.
    assert.equal(S.displayVerdict(safe({ spf: "fail", dkim: "pass", dmarc: "pass" })), "safe");
    assert.deepEqual(S.unusualSigns(safe({ spf: "fail", dkim: "pass", dmarc: "pass" })), []);
    // Without a DMARC pass SPF still counts, and DKIM or DMARC failing always does.
    assert.equal(S.displayVerdict(safe({ spf: "fail", dkim: "pass", dmarc: "none" })), "caution");
    assert.equal(S.displayVerdict(safe({ spf: "pass", dkim: "fail", dmarc: "pass" })), "caution");
    assert.equal(S.displayVerdict(safe({ spf: "pass", dkim: "pass", dmarc: "fail" })), "caution");
});

test("the reason behind a safe verdict is shared by the banner and the popup", () => {
    const S = loadLib("shared.js");
    const base = { verdict: "safe", agents: { text: { phishing_probability: 0.1 } } };
    assert.equal(S.safeReason(base), null);
    assert.equal(S.safeReason({ ...base, forwarded: { detected: true } }), "forwarded");
    assert.equal(S.safeReason({ ...base, shared_links: { count: 1 } }), "shared");
    const high = { verdict: "safe", agents: { text: { phishing_probability: 0.8 } } };
    assert.equal(S.safeReason(high), "one_signal");
    assert.equal(S.safeReason({ ...high, trusted_sender: true }), "trusted");
    assert.equal(S.safeReason({ ...high, trust_path: "crypto_verified" }), "crypto");
    assert.equal(S.safeReason({ ...high, trust_path: "dmarc_verified" }), "dmarc");
});

test("caution display: a safe verdict with a red meter or an unusual sign", () => {
    const S = loadLib("shared.js");
    const safe = (extra = {}) => ({
        verdict: "safe",
        agents: { text: { phishing_probability: 0.1 }, url: { phishing_probability: 0.05 }, metadata: { phishing_probability: 0.2 } },
        sender_auth: {}, url_reputation: { checked: 2, malicious_count: 0 },
        ...extra,
    });
    // The meters turn red from 70% (rounded as shown).
    assert.equal(S.scoreLevel(0.695), "high");
    assert.equal(S.scoreLevel(0.69), "mid");
    assert.equal(S.scoreLevel(0.39), "low");
    assert.equal(S.displayVerdict(safe()), "safe");
    const highText = safe();
    highText.agents.text.phishing_probability = 0.76;
    assert.equal(S.displayVerdict(highText), "caution");
    // A score that is not shown does not count.
    assert.equal(S.displayVerdict({ ...highText, text_agent_used: false }), "safe");
    const highMeta = safe();
    highMeta.agents.metadata = { phishing_probability: 0.9, checked: false };
    assert.equal(S.displayVerdict(highMeta), "safe");
    // Orange or red chips.
    assert.equal(S.displayVerdict(safe({ forwarded: { detected: true } })), "caution");
    assert.equal(S.displayVerdict(safe({ shared_links: { count: 1, services: ["Google Drive"] } })), "caution");
    assert.equal(S.displayVerdict(safe({ sender_auth: { spf: "fail" } })), "caution");
    assert.equal(S.displayVerdict(safe({ sender_auth: { impersonation: { brand: "paypal" } } })), "caution");
    assert.equal(S.displayVerdict(safe({ url_reputation: { checked: 1, malicious_count: 1 } })), "caution");
    // Files: a file PhishLens could not read, or another warning flag.
    assert.equal(S.displayVerdict(safe({ attachment: { notable_features: ["encrypted_archive"] } })), "caution");
    assert.equal(S.displayVerdict(safe({ attachment: { notable_features: ["contains_macros"] } })), "caution");
    assert.equal(S.displayVerdict(safe({ attachment: { notable_features: ["text_from_ocr"] } })), "safe");
    // Phishing stays danger, whatever the scores.
    assert.equal(S.displayVerdict({ verdict: "phishing", agents: {} }), "danger");
    assert.equal(S.displayVerdict({ ...highText, verdict: "phishing" }), "danger");
});
