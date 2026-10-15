// The extension and the server redact reports with the same rules: both
// are checked against tests/fixtures/redaction_cases.json.
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const R = require(path.join(__dirname, "..", "..", "extension", "lib", "redact.js"));
const CASES = require(path.join(__dirname, "..", "fixtures", "redaction_cases.json"));

for (const c of CASES) {
    test(`redacts: ${c.text.slice(0, 40)}`, () => {
        assert.equal(R.redact(c.text, c.terms), c.expected);
    });
}

test("redacting twice changes nothing", () => {
    for (const c of CASES) assert.equal(R.redact(c.expected, c.terms), c.expected);
});

test("nothing personal is left", () => {
    const terms = R.termsFrom("kalinda.okoro91@gmail.com", "Kalinda Okoro");
    const out = R.redact("Hi Kalinda Okoro, wire 250000 to FR7630006000011234567890189, call +234 803 123 4567, " +
        "mail kalinda.o@example.org, profile @kal_99 https://x.example/u/kalinda?ref=1 signed okoro91", terms);
    for (const leak of ["Kalinda", "Okoro", "kalinda", "250000", "FR76", "803", "kal_99", "/u/", "okoro91"]) {
        assert.ok(!out.includes(leak), `${leak} in ${out}`);
    }
    assert.ok(out.includes("<URL:x.example>"));
});

test("account words: mail providers are not names", () => {
    assert.deepEqual(R.termsFrom("ana.silva@gmail.com"), ["ana", "silva"]);
});
