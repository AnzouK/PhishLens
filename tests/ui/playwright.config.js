// Playwright config for the popup UI smoke tests (see popup.spec.js).
"use strict";
const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
    testDir: __dirname,
    timeout: 30_000,
    retries: 1,
    reporter: [["list"]],
    // English UI whatever the machine language: the tests check English texts.
    // PW_CHANNEL=chrome uses the Google Chrome already installed (CI
    // runners have it) instead of downloading Playwright's Chromium.
    use: {
        browserName: "chromium",
        channel: process.env.PW_CHANNEL || undefined,
        headless: true,
        locale: "en-US",
    },
});
