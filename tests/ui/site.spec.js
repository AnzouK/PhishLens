// Website smoke tests: every language version loads, app.js speaks the
// page's language, the language menu links work and an English page
// offers the visitor's language. The site is served over HTTP and every
// call to PhishLens Cloud or GitHub is intercepted.
"use strict";
const { test, expect } = require("@playwright/test");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const SITE = path.resolve(__dirname, "..", "..", "site");
const API = "https://phishlens.dev";
const LANGS = ["en", "fr", "pt", "es", "de", "it", "nl", "ha"];
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" };

let server;
let base;

test.beforeAll(async () => {
    server = http.createServer((req, res) => {
        let rel = decodeURIComponent(new URL(req.url, "http://x").pathname);
        if (rel.endsWith("/")) rel += "index.html";
        const file = path.join(SITE, rel);
        if (!file.startsWith(SITE)) { res.writeHead(403); return res.end(); }
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

test.beforeEach(async ({ page }) => {
    await page.route(`${API}/health`, (r) => r.fulfill({ json: { status: "ok", version: "2.0.0" } }));
    await page.route(`${API}/reputation/stats`, (r) => r.fulfill({ json: { enabled: false } }));
    await page.route("https://api.github.com/**", (r) => r.fulfill({ json: { tag_name: "v2.0.0" } }));
    await page.route(`${API}/explain`, (r) => r.fulfill({
        json: { features: [{ token: "verify", weight: 0.4, supports: "phishing" }] },
    }));
});

function strings(lang) {
    const src = fs.readFileSync(path.join(SITE, "i18n", `${lang}.js`), "utf8");
    return JSON.parse(src.split("window.PhishLensSite = ")[1].trim().replace(/;$/, "")).t;
}

for (const lang of LANGS) {
    test(`home page in ${lang} loads and reports the server`, async ({ page }) => {
        const errors = [];
        page.on("pageerror", (e) => errors.push(e.message));
        await page.goto(`${base}/${lang === "en" ? "" : `${lang}/`}`);
        await expect(page.locator("html")).toHaveAttribute("lang", lang);
        await expect(page.locator("#status")).toContainText(strings(lang).js_online);
        await expect(page.locator("#version")).toContainText("2.0.0");
        expect(await page.content()).not.toContain("{{");
        expect(errors).toEqual([]);
    });
}

test("the French page shows a French verdict", async ({ page }) => {
    await page.route(`${API}/analyse`, (r) => r.fulfill({
        json: { verdict: "phishing", fused_score: 0.9, agents: { text: { phishing_probability: 0.9 } } },
    }));
    await page.goto(`${base}/fr/`);
    await page.click('[data-sample="phish"]');
    await page.click("#demo-submit");
    await expect(page.locator("#demo-result .verdict")).toHaveText("Ressemble à du phishing");
    await expect(page.locator("#demo-submit")).toHaveText("Vérifier cet e-mail");
});

test("the language menu leads to the same page in another language", async ({ page }) => {
    await page.goto(`${base}/privacy.html`);
    await page.click(".lang-menu summary");
    await page.click('.lang-menu a[hreflang="de"]');
    await expect(page).toHaveURL(`${base}/de/privacy.html`);
    await expect(page.locator("h1")).toHaveText("Datenschutzerklärung von PhishLens");
    await expect(page.locator(".legal-note a")).toHaveAttribute("href", "../privacy.html");
});

test.describe("a French browser on an English page", () => {
    test.use({ locale: "fr-FR" });
    test("is offered the French version", async ({ page }) => {
        await page.goto(`${base}/terms.html`);
        const link = page.locator(".lang-suggest a");
        await expect(link).toHaveText("Lire cette page en français");
        await expect(link).toHaveAttribute("href", "fr/terms.html");
    });
});

test("the header hides on scroll down, returns on scroll up, and the page has a way back to the top", async ({ page }) => {
    await page.goto(`${base}/fr/`);
    const head = page.locator(".site-head");
    const top = page.locator(".to-top");
    await expect(top).toBeHidden();
    await page.mouse.wheel(0, 2500);
    await expect(head).toHaveClass(/is-hidden/);
    await expect(top).toBeVisible();
    await expect(top).toHaveText("Haut de page");
    await page.mouse.wheel(0, -300);
    await expect(head).not.toHaveClass(/is-hidden/);
    await top.click();
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBe(0);
});

test("a result shows the detected language and sends a redacted report", async ({ page }) => {
    await page.route(`${API}/analyse`, (r) => r.fulfill({
        json: { verdict: "phishing", fused_score: 0.9, language: { code: "fr", confidence: 0.9 },
                agents: { text: { phishing_probability: 0.9 } } },
    }));
    let sent = null;
    await page.route(`${API}/feedback`, async (r) => {
        sent = r.request().postDataJSON();
        await r.fulfill({ json: { ok: true, reference: "a1b2c3d4e5f6" } });
    });
    await page.goto(`${base}/fr/`);
    await page.fill("#demo-text", "Bonjour Kalinda, votre compte 12345678 est bloqué, confirmez vos informations aujourd'hui.");
    await page.click("#demo-submit");
    await expect(page.locator(".fb__lang")).toContainText("Langue détectée : français");
    await page.click('.fb__lang button:has-text("C\'est juste")');
    await expect(page.locator(".fb__lang")).toContainText("Noté : français");
    await page.click(".fb-link");
    const text = await page.locator(".fb-report__text").inputValue();
    expect(text).not.toContain("Kalinda");
    expect(text).not.toContain("12345678");
    await expect(page.locator(".fb-btn--strong")).toBeDisabled();
    await page.check(".fb-report__check input");
    await page.click(".fb-btn--strong");
    await expect(page.locator(".fb")).toContainText("a1b2c3d4e5f6");
    await expect(page.locator(".fb-ref")).toHaveText("a1b2c3d4e5f6");
    await expect(page.locator('.fb button:has-text("Copier")')).toBeVisible();
    expect(sent.kind).toBe("false_positive");
    expect(sent.lang_user).toBe("fr");
    expect(sent.text).not.toContain("Kalinda");
});

test("a report of fewer than 3 words says why it cannot be sent", async ({ page }) => {
    await page.route(`${API}/analyse`, (r) => r.fulfill({
        json: { verdict: "safe", fused_score: 0.1, language: { code: "en", confidence: 0.9 },
                agents: { text: { phishing_probability: 0.1 } } },
    }));
    await page.goto(`${base}/`);
    await page.fill("#demo-text", "zzcacmxtapezzcacmxtapezzcacmxtapezzcacmxtapezzcacmxtape");
    await page.click("#demo-submit");
    await page.click(".fb-link");
    await page.check(".fb-report__check input");
    await expect(page.locator(".fb-btn--strong")).toBeDisabled();
    await expect(page.locator(".fb-report")).toContainText("at least 3 words");
    await page.fill(".fb-report__text", "this one has enough words");
    await expect(page.locator(".fb-btn--strong")).toBeEnabled();
    await expect(page.locator(".fb-report")).not.toContainText("at least 3 words");
});
