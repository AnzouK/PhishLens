// What PhishLens reads from Gmail's page (lib/gmail_page.js), on sample
// pages in tests/fixtures/gmail/. When Gmail changes, these fail on the
// new sample before users see a broken scan.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { loadLib } = require("./helpers");

const FIX = path.join(__dirname, "..", "fixtures", "gmail");
const read = (name) => fs.readFileSync(path.join(FIX, name), "utf8");
const G = loadLib("gmail_page.js");

test("the account token is read from Gmail's inline script", () => {
    assert.equal(G.ikFromScripts(["var other = 1;", read("globals_script.txt")]), "1a2b3c4d5e");
    assert.equal(G.ikFromScripts(["var other = 1;"]), null);
    assert.equal(G.ikFromScripts(['var GLOBALS=[1,2,3,4,5,6,7,8,9,"not-a-token"];']), null);
});

test("the Show original URL names the account and the message", () => {
    assert.equal(G.accountPath("/mail/u/2/"), "/mail/u/2");
    assert.equal(G.accountPath("/"), "/mail/u/0");
    assert.equal(G.originalQuery({ messageId: "#msg-f:1812345678901234567" }), "permmsgid=msg-f%3A1812345678901234567");
    assert.equal(G.originalQuery({ messageId: "#msg-a:r-123456" }), "permmsgid=msg-a%3Ar-123456");
    assert.equal(G.originalQuery({ legacyId: "18c2f0a1b2c3d4e5" }), "th=18c2f0a1b2c3d4e5");
    assert.equal(G.originalQuery({ thread: "18c2f0a1b2c3d4e5" }), "th=18c2f0a1b2c3d4e5");
    assert.equal(G.originalQuery({ messageId: "nonsense" }), null);
    assert.equal(G.originalUrl("https://mail.google.com", "/mail/u/1/", "1a2b3c4d5e", "th=ab"),
        "https://mail.google.com/mail/u/1/?ik=1a2b3c4d5e&view=om&th=ab");
});

test("the raw message is read from the Show original page, entities decoded", () => {
    const { raw, reason } = G.parseShowOriginal(read("show_original.html"));
    assert.equal(reason, undefined);
    assert.match(raw, /^Delivered-To: reader@example.org/);
    assert.match(raw, /^From: "Example News" <news@example.com>$/m);
    assert.match(raw, /digest\?a=1&b=2 <- here\./);
    assert.ok(!raw.includes("</pre>"));
});

test("a message the user sent, or another page, is not used", () => {
    assert.match(G.parseShowOriginal(read("show_original_sent.html")).reason, /no delivery headers/);
    assert.match(G.parseShowOriginal("<html><body>Sign in</body></html>").reason, /layout/);
    assert.match(G.parseShowOriginal('<pre id="raw_message_text">hello</pre>').reason, /not an email/);
});

test("Gmail's sender check labels are recognised in the supported languages", () => {
    assert.equal(G.authRowKind("mailed-by:"), "mailedBy");
    assert.equal(G.authRowKind(" Signé par : "), "signedBy");
    assert.equal(G.authRowKind("ondertekend door"), "signedBy");
    assert.equal(G.authRowKind("to:"), null);
    assert.equal(G.viaDomain("via sendgrid.net"), "sendgrid.net");
    assert.equal(G.viaDomain("via the website"), null);
    assert.equal(G.inInbox("#inbox/FMfcgz"), true);
    assert.equal(G.inInbox("#spam/FMfcgz"), false);
    assert.equal(G.inInbox("#trash"), false);
});
