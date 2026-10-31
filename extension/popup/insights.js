// The Insights view: statistics, the 30-day chart, the top phishing
// words, the live evaluation from the user's reviews, and the recent
// scans with their review buttons. Everything comes from lib/history.js.
import { $, h, t, I18N, spriteIcon, openView, goBack, currentView } from "./ui.js";
import { historyReportPanel, renderShareStats } from "./report.js";

const HISTORY = window.PhishLensHistory;

function timeAgo(ts) {
    const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (s < 60) return t("ago_s", { n: s });
    const m = Math.floor(s / 60);
    if (m < 60) return t("ago_m", { n: m });
    const hours = Math.floor(m / 60);
    if (hours < 24) return t("ago_h", { n: hours });
    const d = Math.floor(hours / 24);
    if (d < 30) return t("ago_d", { n: d });
    return new Date(ts).toISOString().slice(0, 10);
}

// One column per day; the chart is 84 px high, 18 of them for the date.
function dailyChart(days) {
    const maxDaily = Math.max(1, ...days.map((d) => d.phishing + d.safe));
    return days.map((d) => {
        const total = d.phishing + d.safe;
        const height = total ? Math.max(3, Math.round((total / maxDaily) * 62)) : 0;
        const phishH = total ? Math.round((d.phishing / total) * 100) : 0;
        return h("div.dc-col", { title: t("chart_day_title", { date: d.date, total, phishing: d.phishing, safe: d.safe }) },
            h("div.dc-stack", { style: { height: `${height}px` } },
                h("span.dc-phishing", { style: { height: `${phishH}%` } }),
                h("span.dc-safe", { style: { height: `${100 - phishH}%` } })),
            h("div.dc-label", null, d.date.slice(5)));
    });
}

function topTokens(tokens) {
    if (!tokens.length) return [h("div.empty-hint", null, t("no_top_tokens"))];
    const maxW = Math.max(...tokens.map((tok) => tok.weight));
    return tokens.map((tok) => h("div.token-row", null,
        h("span.token-row__label", null, tok.token),
        h("span.token-row__bar", null, h("span", { style: { width: `${Math.round((tok.weight / maxW) * 100)}%` } }))));
}

function liveEvaluation(live) {
    if (!live?.reviewed) return [h("div.empty-hint", null, t("live_empty"))];
    const pctOf = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
    const cell = (value, label) => h("div", null, h("strong", null, String(value)), h("span", null, t(label)));
    return [
        h("div.live-eval__grid", null,
            cell(live.reviewed, "live_reviewed"), cell(pctOf(live.accuracy), "live_accuracy_label"),
            cell(live.fp, "live_fp"), cell(live.fn, "live_fn")),
        h("div.empty-hint", null, t("live_detail", {
            precision: pctOf(live.precision), recall: pctOf(live.recall), fpr: pctOf(live.falsePositiveRate),
        })),
    ];
}

function reviewButtons(e) {
    const review = (label) => async () => {
        await HISTORY.setLabel(e.id, e.label === label ? null : label);
        renderInsights();
    };
    const button = (label, key, extra = "") => h(`button.review-btn${extra}${e.label === label ? ".review-btn--on" : ""}`,
        { type: "button", dataset: { label }, title: t(`${key}_title`), onclick: review(label) }, t(key));
    let after = null;
    if (e.reported) {
        after = h("span.review-sent", null, t("review_reported"));
    } else if (e.label === "wrong") {
        after = h("button.review-btn.review-report", {
            type: "button", title: t("review_report_title"),
            onclick: async (ev) => {
                const item = ev.target.closest(".history-item");
                if (!item.querySelector(".plr-report")) item.append(await historyReportPanel(e));
            },
        }, t("review_report"));
    }
    return h("div.history-item__review", { role: "group", "aria-label": t("review_group") },
        button("correct", "review_right"), button("wrong", "review_wrong", ".review-btn--wrong"), after);
}

function historyRow(e) {
    const srcKey = "src_" + String(e.source || "").replace(/-/g, "_");
    return h("div.history-item", { dataset: { verdict: e.verdict, id: e.id } },
        h("div.history-item__dot", null, spriteIcon(e.verdict === "phishing" ? "alert" : "shield-check")),
        h("div.history-item__main", null,
            h("div.history-item__subject", null, window.PhishLensShared.safeName(e.subject) || t("no_subject")),
            h("div.history-item__meta", null,
                h("span", null, I18N.has(srcKey) ? t(srcKey) : e.source),
                h("span", null, "·"),
                h("span", null, timeAgo(e.ts)),
                e.sender && [h("span", null, "·"), h("span", null, e.sender)])),
        h("div.history-item__score", null, `${Math.round((e.score || 0) * 100)}%`),
        reviewButtons(e));
}

export async function renderInsights() {
    const stats = await HISTORY.getStats();
    const list = await HISTORY.getHistory();
    const empty = !stats || stats.total === 0;
    $("insights-empty").hidden = !empty;
    for (const el of [$("insights-stats"), $("ratio-block"), $("top-tokens-block"), $("daily-chart").closest(".chart-block")]) {
        el.style.display = empty ? "none" : "";
    }
    if (empty) {
        $("history-list").replaceChildren();
        renderShareStats([]);
        return;
    }
    $("stat-total").textContent = stats.total;
    $("stat-phishing-pct").textContent = `${stats.phishingPct}%`;
    $("stat-avg-score").textContent = stats.avgScore.toFixed(2);
    $("ratio-safe-count").textContent = stats.safe;
    $("ratio-phishing-count").textContent = stats.phishing;
    $("ratio-safe-fill").style.width = `${stats.safePct}%`;
    $("ratio-phishing-fill").style.width = `${stats.phishingPct}%`;
    $("daily-chart").replaceChildren(...dailyChart(stats.days));
    $("top-tokens").replaceChildren(...topTokens(stats.topTokens));
    $("live-eval").replaceChildren(...liveEvaluation(stats.live));
    $("history-list").replaceChildren(...list.slice(0, 20).map(historyRow));
    renderShareStats(list);
}

function download(name, mime, text) {
    const url = URL.createObjectURL(new Blob([text], { type: mime }));
    h("a", { href: url, download: name }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const today = () => new Date().toISOString().slice(0, 10);

export function initInsights() {
    $("insights-btn").addEventListener("click", async () => {
        await renderInsights();
        openView("insights");
    });
    $("insights-back").addEventListener("click", goBack);
    $("export-csv-btn").addEventListener("click", async () => {
        download(`phishlens-history-${today()}.csv`, "text/csv;charset=utf-8", await HISTORY.exportCSV());
    });
    $("export-json-btn").addEventListener("click", async () => {
        download(`phishlens-history-${today()}.json`, "application/json", await HISTORY.exportJSON());
    });
    $("clear-history-btn").addEventListener("click", async () => {
        if (!confirm(t("confirm_clear"))) return;
        await HISTORY.clearHistory();
        await renderInsights();
    });
    // Shift-click on a row removes that scan.
    $("history-list").addEventListener("click", async (ev) => {
        const id = ev.shiftKey && ev.target.closest(".history-item")?.dataset.id;
        if (id && confirm(t("confirm_remove"))) {
            await HISTORY.deleteScan(id);
            await renderInsights();
        }
    });
    I18N.onChange(() => {
        if (currentView() === "insights") renderInsights();
    });
}
