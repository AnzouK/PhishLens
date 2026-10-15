// Playwright config for the popup UI smoke tests (see popup.spec.js).
"use strict";
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
    testDir: __dirname,
    timeout: 30_000,
    retries: 1,
    reporter: [["list"]],
    // English UI whatever the machine language: the tests check English texts.
    use: { browserName: "chromium", headless: true, locale: "en-US" },
});
