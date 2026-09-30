// Popup UI smoke tests. The popup is served over HTTP (ES modules do not
// load from file://), the chrome.* extension APIs are replaced by an
// in-memory stub, and every backend call is intercepted, so the tests
// check the real popup code end to end without a backend or a browser
// profile with the extension installed.
"use strict";
const { test, expect } = require("@playwright/test");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const EXT = path.resolve(__dirname, "..", "..", "extension");
const API = "http://127.0.0.1:8000";
const TYPES = {
    ".html": "text/html", ".js": "text/javascript", ".css": "text/css",
    ".png": "image/png", ".svg": "image/svg+xml", ".json": "application/json",
};

let server;
let base;

test.beforeAll(async () => {
    server = http.createServer((req, res) => {
        const rel = decodeURIComponent(new URL(req.url, "http://x").pathname);
        const file = path.join(EXT, rel);
        if (!file.startsWith(EXT)) { res.writeHead(403); return res.end(); }
        fs.readFile(file, (err, data) => {
            if (err) { res.writeHead(404); return res.end(); }
            res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream" });
            res.end(data);
        });
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(() => server.close());

function fakeChrome() {
    const store = {};
    window.chrome = {
        storage: {
            local: {
                get(keys, cb) {
                    const out = {};
                    for (const k of [].concat(keys || [])) if (k in store) out[k] = store[k];
                    if (cb) cb(out);
                    return Promise.resolve(out);
                },
                set(obj, cb) {
                    Object.assign(store, obj);
                    if (cb) cb();
                    return Promise.resolve();
                },
            },
        },
        runtime: {
            sendMessage: () => Promise.resolve({}),
            getManifest: () => ({ version: "test" }),
        },
    };
}

function analyseResponse(verdict) {
    const p = verdict === "phishing" ? 0.93 : 0.04;
    return {
        verdict,
        fused_score: p,
        high_confidence_override: verdict === "phishing",
        trust_path: "default",
        trusted_sender: false,
        sender_domain: null,
        sender_auth: {
            cryptographically_verified: false, gmail_inbox_soft_verified: false,
            spf: "none", dkim: "none", dmarc: "none", aligned: false,
            spamhaus_dbl_listed: false, reasons: [], score_delta: 0,
        },
        url_reputation: { checked: 0, malicious_count: 0, sources_hit: [], threat_types: [], verdicts: [] },
        agents: {
            text: { phishing_probability: p, verdict: verdict === "phishing" ? "Phishing" : "Safe" },
            url: { phishing_probability: 0.05, phishing_probability_raw: 0.05, verdict: "Safe" },
            metadata: { phishing_probability: 0.25, phishing_probability_raw: 0.25, verdict: "Safe" },
        },
    };
}

test.beforeEach(async ({ page }) => {
    await page.addInitScript(fakeChrome);
    await page.route(`${API}/explain`, (route) => route.fulfill({
        json: { features: [{ token: "verify", weight: 0.41, supports: "phishing" }] },
    }));
});

test("pasted text: phishing verdict and scores are rendered", async ({ page }) => {
    await page.route(`${API}/analyse`, (route) => route.fulfill({ json: analyseResponse("phishing") }));
    await page.goto(`${base}/popup/popup.html`);
    await page.click('.tab[data-tab="paste"]');
    await page.fill("#paste-input", "Your account is suspended. Verify your password now at http://x.tk/login");
    await page.click("#analyze-btn");
    await expect(page.locator("#verdict-label")).toHaveText("This email looks like phishing");
    await expect(page.locator("#text-score")).not.toHaveText("…");
});

test("pasted text: safe verdict", async ({ page }) => {
    await page.route(`${API}/analyse`, (route) => route.fulfill({ json: analyseResponse("safe") }));
    await page.goto(`${base}/popup/popup.html`);
    await page.click('.tab[data-tab="paste"]');
    await page.fill("#paste-input", "Hi team, the sprint review moved to Thursday at 3pm.");
    await page.click("#analyze-btn");
    await expect(page.locator("#verdict-label")).toHaveText("This email looks safe");
});

test("an Office attachment is sent to /analyse_attachment", async ({ page }) => {
    let sent = null;
    await page.route(`${API}/analyse_attachment`, async (route) => {
        sent = route.request().postDataJSON();
        const body = analyseResponse("phishing");
        body.attachment = {
            filename: "invoice.docm", kind: "docx", size_bytes: 12,
            notable_features: ["contains_macros"], feature_bonus: 0.45,
            extracted_urls_count: 0, qr_urls: [], ocr_used: false,
        };
        body.parent_trusted = false;
        await route.fulfill({ json: body });
    });
    await page.goto(`${base}/popup/popup.html`);
    await page.setInputFiles("#file-input", {
        name: "invoice.docm", mimeType: "application/octet-stream", buffer: Buffer.from("PK fake"),
    });
    await page.click("#analyze-btn");
    await expect(page.locator("#verdict-label")).toHaveText("This file looks like phishing");
    expect(sent.filename).toBe("invoice.docm");
    expect(typeof sent.content_b64).toBe("string");
});

test("the file picker accepts attachments after a first selection", async ({ page }) => {
    await page.goto(`${base}/popup/popup.html`);
    await page.setInputFiles("#file-input", { name: "a.eml", mimeType: "message/rfc822", buffer: Buffer.from("x") });
    const accept = await page.locator("#file-input").getAttribute("accept");
    for (const ext of [".eml", ".pdf", ".png", ".docx", ".xlsx", ".zip", ".ics"]) expect(accept).toContain(ext);
});

test("an encrypted archive gets a caution verdict, not \"looks safe\"", async ({ page }) => {
    await page.route(`${API}/analyse_attachment`, async (route) => {
        const body = analyseResponse("safe");
        body.attachment = {
            filename: "invoice.zip", kind: "archive", size_bytes: 12,
            notable_features: ["encrypted_archive"], feature_bonus: 0.35,
            extracted_urls_count: 0, entry_count: 1, encrypted: true,
        };
        await route.fulfill({ json: body });
    });
    await page.goto(`${base}/popup/popup.html`);
    await page.setInputFiles("#file-input", {
        name: "invoice.zip", mimeType: "application/zip", buffer: Buffer.from("PK fake"),
    });
    await page.click("#analyze-btn");
    await expect(page.locator("#verdict-label")).toHaveText("Could not look inside this file");
});
