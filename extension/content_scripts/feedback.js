// Language and report controls under a verdict (Gmail and Outlook). The
// controls are lib/report_ui.js and the redaction lib/redact.js; this file
// connects them to the banner and to the history.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { debug } = PhishLensShared;

// The user's own address and name on this page, removed from anything
// they report.
function accountTerms() {
    const found = [];
    const title = document.title.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    if (title) found.push(title[0]);
    for (const el of document.querySelectorAll('a[aria-label*="@"], [role="tree"] [title*="@"]')) {
        // An email's own links are the sender's, not the user's account:
        // five of them used to fill the list before the real one.
        if (PL.inMessageBody(el)) continue;
        found.push(el.getAttribute("aria-label") || el.getAttribute("title") || "");
        if (found.length > 4) break;
    }
    return PhishLensRedact.termsFrom(...found);
}

// The redacted text kept for a later report: subject, body and links.
function draftText(subject, body, links) {
    const text = [subject, body, ...(links || []).slice(0, 20)].filter(Boolean).join("\n");
    return PhishLensRedact.redact(text.slice(0, 20000), accountTerms());
}

// Adds the controls to the banner in `root` and keeps the redacted text
// with the history entry `historyId`, for a report from Insights later.
PL.attachFeedback = function attachFeedback(root, data, { historyId, source, subject, body, links }) {
    const main = root.querySelector(".pll-banner .pll-banner__main");
    if (!main || data.verdict === "error") return;
    const draft = draftText(subject, body, links);
    const history = PhishLensApi.history;
    if (historyId && draft) history.draft(historyId, draft).catch((e) => debug("report draft", e));
    const state = { langUser: null };
    const update = (patch) => historyId && history.update(historyId, patch).catch((e) => debug("history update", e));

    const box = document.createElement("div");
    box.className = "plr-box";
    box.append(PhishLensReport.languageLine({
        code: data.language?.code,
        onChoice: (code) => { state.langUser = code; update({ lang_user: code }); },
    }));
    box.append(PhishLensReport.reportButton({
        verdict: data.verdict,
        getText: async () => draft,
        redact: (text) => PhishLensRedact.redact(text, accountTerms()),
        send: PhishLensReport.sendWith(PhishLensApi.feedback,
            (kind, text) => PhishLensReport.payload(kind, text, data, { source, langUser: state.langUser })),
        onSent: (_kind, reference) => update({ label: "wrong", reported: reference }),
    }));
    main.append(box);
};

// Saves a scan in the history; resolves to its id, or null.
PL.saveScan = function saveScan(data, extra) {
    return PhishLensApi.history.save(PhishLensHistory.entryFrom(data, extra)).catch((e) => {
        debug("history save", e);
        return null;
    });
};
})();
