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
const API = "https://anzouk.duckdns.org";   // PhishLens Cloud, the default backend (v1.15)
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
            sendMessage: (msg) => {
                window.__sent = (window.__sent || []).concat([msg]);
                return Promise.resolve(msg?.type === "phishlens.feedback" ? { ok: true, reference: "a1b2c3d4e5f6" } : {});
            },
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
        language: { code: "en", confidence: 0.9 },
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

test("pasted text: language confirmation and a redacted report", async ({ page }) => {
    await page.route(`${API}/analyse`, (route) => route.fulfill({ json: analyseResponse("phishing") }));
    await page.goto(`${base}/popup/popup.html`);
    await page.click('.tab[data-tab="paste"]');
    await page.fill("#paste-input", "Dear Kalinda, your account 12345678 is locked. Verify at https://x.tk/login?u=kalinda now please.");
    await page.click("#analyze-btn");
    await expect(page.locator(".plr-lang")).toContainText("Language detected: English");
    await page.click('.plr-lang button:has-text("Not this language")');
    await page.selectOption(".plr-lang select", "fr");
    await expect(page.locator(".plr-lang")).toContainText("Noted: French");
    await page.click(".plr-link");
    const text = await page.locator(".plr-report__text").inputValue();
    expect(text).not.toContain("Kalinda");
    expect(text).not.toContain("12345678");
    expect(text).toContain("<URL:x.tk>");
    await expect(page.locator(".plr-report .plr-btn--strong")).toBeDisabled();
    await page.check(".plr-report__check input");
    await page.click(".plr-report .plr-btn--strong");
    await expect(page.locator(".plr-report")).toContainText("a1b2c3d4e5f6");
    const sent = await page.evaluate(() => window.__sent.find((m) => m.type === "phishlens.feedback").payload);
    expect(sent.kind).toBe("false_positive");
    expect(sent.lang_user).toBe("fr");
    expect(sent.text).not.toContain("Kalinda");
});


test("a scanned file can be reported by pasting its text, redacted on paste", async ({ page }) => {
    await page.route(`${API}/analyse`, (route) => route.fulfill({ json: analyseResponse("phishing") }));
    await page.goto(`${base}/popup/popup.html`);
    await page.setInputFiles("#file-input", {
        name: "mail.eml", mimeType: "message/rfc822", buffer: Buffer.from("Subject: hi\r\n\r\nHello there"),
    });
    await page.click("#analyze-btn");
    await page.click(".plr-link");
    const area = page.locator(".plr-report__text");
    await expect(area).toHaveValue("");
    await page.evaluate(() => {
        const dt = new DataTransfer();
        dt.setData("text/plain", "Dear Kalinda, call +44 20 7946 0958 today to confirm the meeting.");
        const box = document.querySelector(".plr-report__text");
        box.focus();
        box.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }));
    });
    await expect(area).not.toHaveValue(/Kalinda|7946/);
    await expect(area).toHaveValue(/<PHONE>/);
    await page.check(".plr-report__check input");
    await page.click(".plr-report .plr-btn--strong");
    await expect(page.locator(".plr-report")).toContainText("a1b2c3d4e5f6");
    const sent = await page.evaluate(() => window.__sent.find((m) => m.type === "phishlens.feedback").payload);
    expect(sent.source).toBe("file");
});

test("insights: a scan marked wrong offers a report that stays open", async ({ page }) => {
    await page.goto(`${base}/popup/popup.html`);
    await page.evaluate(() => window.PhishLensHistory.saveScan({
        source: "gmail-auto", subject: "Invoice", verdict: "phishing", score: 0.9,
        agents: { text: 0.9, url: 0.1, metadata: 0.2 }, lang: "en",
    }));
    await page.click("#insights-btn");
    await page.click('.history-item .review-btn[data-label="wrong"]');
    await page.click(".history-item .review-report");
    const panel = page.locator(".history-item .plr-report");
    await expect(panel).toBeVisible();
    await page.waitForTimeout(300);
    await expect(panel).toBeVisible();
    await expect(page.locator('.history-item .review-btn[data-label="wrong"]')).toHaveClass(/review-btn--on/);
});
