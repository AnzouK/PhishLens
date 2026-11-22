"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const EXT = path.join(__dirname, "..", "..", "extension");

test("a change then a click ask for the permission once", async () => {
    let calls = 0;
    let answer = null;
    globalThis.chrome = {
        storage: { local: { get: (k, cb) => cb && cb({}), set() {} } },
        permissions: {
            request: () => {
                calls++;
                return new Promise((resolve) => { answer = resolve; });
            },
        },
    };
    globalThis.document = { getElementById: () => null };
    globalThis.window = globalThis;
    globalThis.PhishLensI18n = { t: (k) => k, tn: (k) => k };
    globalThis.PhishLensDom = {};
    require(path.join(EXT, "lib", "shared.js"));
    const { requestOrigins } = await import(pathToFileURL(path.join(EXT, "popup", "settings.js")).href);
    // The address field's change event, then the test button's click,
    // while Chrome's prompt is still open.
    const first = requestOrigins(["https://mail.example/*"]);
    const second = requestOrigins(["https://mail.example/*"]);
    assert.equal(calls, 1);
    answer(true);
    assert.deepEqual(await Promise.all([first, second]), [true, true]);
    // Answered: a later click asks again.
    const third = requestOrigins(["https://mail.example/*"]);
    assert.equal(calls, 2);
    answer(false);
    assert.equal(await third, false);
    // Other origins are a separate prompt.
    requestOrigins(["http://127.0.0.1/*"]);
    assert.equal(calls, 3);
});
