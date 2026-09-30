"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { installFakeChrome, loadLib } = require("./helpers");

function fresh() {
    installFakeChrome();
    return loadLib("lime_cache.js");
}
const FEATURES = [{ token: "verify", weight: 0.4, supports: "phishing" }];

test("put then get returns a cache hit", async () => {
    const C = fresh();
    const payload = { raw_text: "Verify your account" };
    assert.equal(await C.get("https://x", payload), null);
    await C.put("https://x", payload, FEATURES);
    const hit = await C.get("https://x", payload);
    assert.deepEqual(hit, { features: FEATURES, cached: true });
});

test("key depends on backend and text, not on trailing slash", async () => {
    const C = fresh();
    const a = await C.hashPayload("https://x/", { raw_text: "t" });
    assert.equal(a, await C.hashPayload("https://x", { raw_text: "t" }));
    assert.notEqual(a, await C.hashPayload("https://y", { raw_text: "t" }));
    assert.notEqual(a, await C.hashPayload("https://x", { raw_text: "u" }));
    assert.match(a, /^[0-9a-f]{64}$/);
});

test("empty feature lists are not cached", async () => {
    const C = fresh();
    await C.put("https://x", { raw_text: "t" }, []);
    assert.equal((await C.stats()).entries, 0);
});

test("clear empties the cache", async () => {
    const C = fresh();
    await C.put("https://x", { raw_text: "t" }, FEATURES);
    await C.clear();
    assert.equal(await C.get("https://x", { raw_text: "t" }), null);
});
