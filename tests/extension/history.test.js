"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { installFakeChrome, loadLib } = require("./helpers");

function fresh() {
    installFakeChrome();
    return loadLib("history.js");
}

test("saveScan stores newest first and sanitises fields", async () => {
    const H = fresh();
    await H.saveScan({ source: "gmail", subject: "first", verdict: "safe", score: 0.1 });
    await H.saveScan({ source: "file", subject: "x".repeat(300), verdict: "weird", score: NaN });
    const list = await H.getHistory();
    assert.equal(list.length, 2);
    assert.equal(list[0].subject.length, 120);
    assert.equal(list[0].verdict, "safe");          // unknown verdicts fall back to safe
    assert.equal(list[0].score, 0);                  // NaN score becomes 0
    assert.equal(list[1].subject, "first");
});

test("history is capped at MAX_ENTRIES", async () => {
    const H = fresh();
    for (let i = 0; i < H.MAX_ENTRIES + 5; i++) {
        await H.saveScan({ subject: `s${i}`, verdict: "safe" });
    }
    const list = await H.getHistory();
    assert.equal(list.length, H.MAX_ENTRIES);
    assert.equal(list[0].subject, `s${H.MAX_ENTRIES + 4}`);
});

test("attachTokens keeps the top 5", async () => {
    const H = fresh();
    const id = await H.saveScan({ subject: "a", verdict: "phishing" });
    const tokens = Array.from({ length: 8 }, (_, i) => ({ token: `t${i}`, weight: i }));
    await H.attachTokens(id, tokens);
    const [e] = await H.getHistory();
    assert.equal(e.tokens.length, 5);
});

test("getStats counts verdicts and ranks phishing tokens", async () => {
    const H = fresh();
    await H.saveScan({ verdict: "phishing", score: 0.9, source: "gmail",
        tokens: [{ token: "Verify", weight: 0.4 }, { token: "account", weight: 0.1 }] });
    await H.saveScan({ verdict: "phishing", score: 0.8, source: "file",
        tokens: [{ token: "verify", weight: 0.3 }] });
    await H.saveScan({ verdict: "safe", score: 0.1, source: "paste",
        tokens: [{ token: "meeting", weight: 0.5 }] });
    const s = await H.getStats();
    assert.equal(s.total, 3);
    assert.equal(s.phishing, 2);
    assert.equal(s.phishingPct, 67);
    assert.equal(s.topTokens[0].token, "verify");    // case-folded and summed
    assert.ok(!s.topTokens.some((t) => t.token === "meeting"));
    assert.equal(s.bySource.gmail, 1);
    assert.equal(s.days.length, 30);
});

test("exportCSV neutralises spreadsheet formulas", async () => {
    const H = fresh();
    await H.saveScan({ verdict: "phishing", subject: '=HYPERLINK("http://evil.example","click")',
        sender: "+attacker@evil.example" });
    await H.saveScan({ verdict: "safe", subject: 'Lunch, "today"', sender: "a@b.c" });
    const csv = await H.exportCSV();
    const lines = csv.split("\n");
    assert.equal(lines.length, 3);
    assert.ok(lines[1].includes('"Lunch, ""today"""'));
    assert.ok(lines[2].includes(`"'=HYPERLINK(""http://evil.example"",""click"")"`));
    assert.ok(lines[2].includes("'+attacker@evil.example"));
    assert.ok(!/,=/.test(csv) && !/,\+/.test(csv));
});

test("deleteScan and clearHistory", async () => {
    const H = fresh();
    const id = await H.saveScan({ verdict: "safe" });
    await H.saveScan({ verdict: "safe" });
    await H.deleteScan(id);
    assert.equal((await H.getHistory()).length, 1);
    await H.clearHistory();
    assert.equal((await H.getHistory()).length, 0);
});

test("attachment scans are counted by source", async () => {
    const H = fresh();
    await H.saveScan({ source: "gmail-attachment", subject: "invoice.pdf", verdict: "phishing", score: 0.9 });
    await H.saveScan({ source: "attachment", subject: "scan.png", verdict: "safe", score: 0.1 });
    const stats = await H.getStats();
    assert.equal(stats.bySource["gmail-attachment"], 1);
    assert.equal(stats.bySource.attachment, 1);
    assert.equal((await H.getHistory())[1].source, "gmail-attachment");
});

test("live evaluation from user reviews", async () => {
    const H = fresh();
    const a = await H.saveScan({ verdict: "phishing" });
    const b = await H.saveScan({ verdict: "phishing" });
    const c = await H.saveScan({ verdict: "safe" });
    const d = await H.saveScan({ verdict: "safe" });
    await H.saveScan({ verdict: "safe" });                 // not reviewed
    await H.setLabel(a, "correct");                        // TP
    await H.setLabel(b, "wrong");                          // FP
    await H.setLabel(c, "correct");                        // TN
    await H.setLabel(d, "wrong");                          // FN
    const { live } = await H.getStats();
    assert.deepEqual([live.reviewed, live.tp, live.fp, live.tn, live.fn], [4, 1, 1, 1, 1]);
    assert.equal(live.accuracy, 0.5);
    await H.setLabel(d, null);                             // clearing a review
    assert.equal((await H.getStats()).live.reviewed, 3);
    assert.match(await H.exportCSV(), /,label,lang,lang_user\n/);
});

test("daily buckets use the local date", async () => {
    const H = fresh();
    await H.saveScan({ verdict: "safe" });
    const { days } = await H.getStats();
    const today = days[days.length - 1];
    const d = new Date();
    const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
    assert.equal(today.date, key);
    assert.equal(today.safe, 1);
});

test("language answers, reports and drafts", async () => {
    installFakeChrome();
    const H = loadLib("history.js");
    const id = await H.saveScan({ verdict: "phishing", subject: "Your bank", sender: "a@b.c", lang: "fr" });
    assert.equal(await H.updateScan(id, { lang_user: "pt", reported: "a1b2c3d4e5f6", label: "wrong" }), true);
    assert.equal(await H.updateScan(id, { lang_user: "<x>", reported: "not a ref" }), true);
    const [e] = await H.getHistory();
    assert.equal(e.lang, "fr");
    assert.equal(e.lang_user, "pt");
    assert.equal(e.reported, "a1b2c3d4e5f6");
    await H.saveDraft(id, "Bonjour <NAME>, votre compte");
    assert.equal(await H.getDraft(id), "Bonjour <NAME>, votre compte");
    await H.deleteScan(id);
    assert.equal(await H.getDraft(id), "");
});

test("shared statistics carry no subject, sender or text", async () => {
    installFakeChrome();
    const H = loadLib("history.js");
    await H.saveScan({ verdict: "safe", subject: "Secret plan", sender: "boss@corp.example", score: 0.2, lang: "en" });
    const rows = H.statsRows(await H.getHistory());
    assert.equal(rows.length, 1);
    assert.ok(!JSON.stringify(rows).includes("Secret") && !JSON.stringify(rows).includes("corp"));
    assert.deepEqual(Object.keys(rows[0]).sort(),
        ["agents", "day", "label", "lang", "lang_user", "score", "source", "trusted", "verdict"]);
});

test("two scans saved at the same moment are both kept", async () => {
    const store = installFakeChrome();
    const get = chrome.storage.local.get;
    // Storage answers later, as the real one does.
    chrome.storage.local.get = (keys, cb) => setTimeout(() => get(keys, cb), 5);
    const H = loadLib("history.js");
    await Promise.all([
        H.saveScan({ source: "gmail", verdict: "safe", score: 0.1 }),
        H.saveScan({ source: "outlook", verdict: "phishing", score: 0.9 }),
    ]);
    assert.equal(store[H.STORAGE_KEY].length, 2);
});
