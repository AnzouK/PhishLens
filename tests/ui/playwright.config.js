// Playwright config for the popup UI smoke tests (see popup.spec.js).
"use strict";
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
    testDir: __dirname,
    timeout: 30_000,
    retries: 1,
    reporter: [["list"]],
    use: { browserName: "chromium", headless: true },
});
