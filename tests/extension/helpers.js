// Test helpers: an in-memory stand-in for chrome.storage.local with the
// callback API the extension uses, and a loader that gives each test a
// fresh copy of a library file.
"use strict";
const path = require("node:path");

function installFakeChrome() {
    const store = {};
    globalThis.chrome = {
        storage: {
            local: {
                get(keys, cb) {
                    const out = {};
                    for (const k of [].concat(keys)) if (k in store) out[k] = structuredClone(store[k]);
                    cb(out);
                },
                set(obj, cb) {
                    for (const [k, v] of Object.entries(obj)) store[k] = structuredClone(v);
                    if (cb) cb();
                },
            },
        },
    };
    return store;
}

function loadLib(name) {
    const file = path.join(__dirname, "..", "..", "extension", "lib", name);
    delete require.cache[require.resolve(file)];
    return require(file);
}

module.exports = { installFakeChrome, loadLib };
