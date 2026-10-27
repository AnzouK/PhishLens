// Reports from the popup: a wrong verdict (lib/report_ui.js does the
// panel) and the shared statistics of Insights. Both go to PhishLens
// Cloud through the service worker, only after the user confirms.
import { $, h, t, I18N } from "./ui.js";

const { PhishLensReport: REPORT, PhishLensRedact: REDACT, PhishLensHistory: HISTORY, PhishLensApi: API } = window;

const sender = (data, extra) => REPORT.sendWith(API.feedback, (kind, text) => REPORT.payload(kind, text, data, extra));

// A history entry in the shape of an /analyse answer, for a report.
function entryAsResult(e) {
    return {
        verdict: e.verdict, fused_score: e.score, language: { code: e.lang },
        agents: {
            text: { phishing_probability: e.agents?.text },
            url: { phishing_probability: e.agents?.url },
            metadata: { phishing_probability: e.agents?.metadata },
        },
    };
}

// Under a result: the language line and "Wrong verdict? Report it".
// Pasted text is offered for the report; for a file the user pastes the
// part they want to send.
export function renderResultFeedback(data, historyId, pasted, source) {
    const extra = { source, langUser: null };
    $("result-feedback").replaceChildren(h("div.plr-box", null,
        REPORT.languageLine({
            code: data.language?.code,
            onChoice: (code) => {
                extra.langUser = code;
                if (historyId) HISTORY.updateScan(historyId, { lang_user: code });
            },
        }),
        REPORT.reportButton({
            verdict: data.verdict,
            getText: async () => (pasted ? REDACT.redact(pasted) : ""),
            redact: (x) => REDACT.redact(x),
            send: sender(data, extra),
            onSent: (_k, reference) => historyId && HISTORY.updateScan(historyId, { label: "wrong", reported: reference }),
        })));
}

// The report panel of a history row marked wrong.
export async function historyReportPanel(entry) {
    return REPORT.reportPanel({
        verdict: entry.verdict,
        text: (await HISTORY.getDraft(entry.id)) || "",
        redact: (x) => REDACT.redact(x),
        send: sender(entryAsResult(entry), { source: entry.source, lang: entry.lang, langUser: entry.lang_user }),
        onSent: (_k, reference) => HISTORY.updateScan(entry.id, { reported: reference }),
    });
}

// "Share my statistics": the reviewed history without subject, sender or text.
export function renderShareStats(list) {
    const host = $("share-stats");
    host.replaceChildren();
    if (!list.length) return;
    const rows = HISTORY.statsRows(list);
    const open = () => {
        if (host.querySelector(".plr-report")) return;
        const status = h("p.plr-report__status", { role: "status" });
        const send = h("button.plr-btn.plr-btn--strong", { type: "button" }, t("share_stats_send"));
        const panel = h("div.plr-report", null,
            h("p.plr-report__intro", null, t("share_stats_intro", { count: rows.length })),
            h("textarea.plr-report__text", {
                readOnly: true, rows: 6, "aria-label": t("fb_report_preview"),
                value: JSON.stringify(rows.slice(0, 3), null, 1),
            }),
            h("div.plr-report__actions", null,
                send,
                h("button.plr-btn", { type: "button", onclick: () => panel.remove() }, t("fb_cancel"))),
            status);
        send.addEventListener("click", async () => {
            send.disabled = true;
            status.textContent = t("fb_sending");
            try {
                const reference = await API.feedback({
                    kind: "stats", rows, ui_lang: I18N.language(), version: chrome.runtime.getManifest?.().version || null,
                });
                panel.replaceChildren(REPORT.sentMessage(reference));
            } catch (e) {
                status.textContent = t("fb_failed", { error: e.message || t("unknown_error") });
                send.disabled = false;
            }
        });
        host.append(panel);
    };
    host.append(h("button.btn.btn--ghost", { type: "button", onclick: open }, t("share_stats")));
}
