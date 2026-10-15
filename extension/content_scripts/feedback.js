// =====================================================================
// PhishLens content script: language and report controls under a verdict
// (Gmail and Outlook). The controls themselves are lib/report_ui.js, the
// redaction lib/redact.js; this file connects them to the banner and to
// the history.
// =====================================================================

// The user's own address and name on this page, so they are removed from
// anything they report.
function pllAccountTerms() {
    const found = [];
    const title = document.title.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
    if (title) found.push(title[0]);
    for (const el of document.querySelectorAll('a[aria-label*="@"], [role="tree"] [title*="@"]')) {
        found.push(el.getAttribute("aria-label") || el.getAttribute("title") || "");
        if (found.length > 4) break;
    }
    return PhishLensRedact.termsFrom(...found);
}

// The redacted text kept for a later report: subject, body and links.
function pllDraftText(subject, body, links) {
    const text = [subject, body, ...(links || []).slice(0, 20)].filter(Boolean).join("\n");
    return PhishLensRedact.redact(text.slice(0, 20000), pllAccountTerms());
}

function pllReportPayload(kind, text, data, extra) {
    return {
        kind,
        text,
        verdict: data.verdict,
        fused_score: Number(data.fused_score) || 0,
        agents: {
            text: Number(data.agents?.text?.phishing_probability) || 0,
            url: Number(data.agents?.url?.phishing_probability) || 0,
            metadata: Number(data.agents?.metadata?.phishing_probability) || 0,
        },
        trust_path: data.trust_path || null,
        source: extra.source,
        lang: data.language?.code || null,
        lang_user: extra.langUser || null,
        ui_lang: PhishLensI18n.language(),
        version: chrome.runtime.getManifest?.().version || null,
    };
}

// Adds the controls to the banner of `root` once the scan is in the
// history (historyId), and keeps the redacted text for a later report.
function pllAttachFeedback(root, data, { historyId, source, subject, body, links }) {
    const main = root.querySelector(".pll-banner .pll-banner__main");
    if (!main || data.verdict === "error") return;
    const draft = pllDraftText(subject, body, links);
    if (historyId && draft) {
        chrome.runtime.sendMessage({ type: "phishlens.history.draft", id: historyId, text: draft }).catch(() => {});
    }
    const state = { langUser: null };
    const update = (patch) => historyId &&
        chrome.runtime.sendMessage({ type: "phishlens.history.update", id: historyId, patch }).catch(() => {});

    const box = document.createElement("div");
    box.className = "plr-box";
    box.append(PhishLensReport.languageLine({
        code: data.language?.code,
        onChoice: (code) => { state.langUser = code; update({ lang_user: code }); },
    }));
    box.append(PhishLensReport.reportButton({
        verdict: data.verdict,
        getText: async () => draft,
        redact: (text) => PhishLensRedact.redact(text, pllAccountTerms()),
        send: (kind, text) => chrome.runtime.sendMessage({
            type: "phishlens.feedback",
            payload: pllReportPayload(kind, text, data, { source, langUser: state.langUser }),
        }),
        onSent: (_kind, reference) => update({ label: "wrong", reported: reference }),
    }));
    main.append(box);
}
