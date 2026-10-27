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
