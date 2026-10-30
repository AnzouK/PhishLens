// The Result view: verdict, one card per agent with its badges, the
// files of an archive, and the words behind the text score.
import { $, h, t, tn, I18N, spriteIcon } from "./ui.js";

const { SOURCE_LABELS, isCaution } = window.PhishLensConstants;

const THREAT_KEYS = {
    MALWARE: "threat_malware",
    SOCIAL_ENGINEERING: "threat_phishing",
    PHISHING: "threat_phishing",
    UNWANTED_SOFTWARE: "threat_unwanted",
    POTENTIALLY_HARMFUL_APPLICATION: "threat_harmful_app",
    SPAM: "threat_spam",
    BOTNET_CC: "threat_botnet",
    SUSPICIOUS: "threat_suspicious",
};

const badge = (text, kind, title) => h(`span.badge.badge--${kind}`, { title: title ? String(title).slice(0, 240) : null }, text);

// Verified-sender pill: allowlist, then DKIM alignment, then Gmail's inbox.
function renderTrustPill(data) {
    const pill = $("verdict-trusted");
    const auth = data.sender_auth || {};
    const domain = data.sender_domain || "";
    const [key, title] = data.trusted_sender ? ["badge_trusted", t("trusted_title_popup", { domain })]
        : auth.cryptographically_verified ? ["badge_dkim", t("dkim_title_popup", { domain, spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc })]
        : auth.gmail_inbox_soft_verified ? ["badge_gmail", t("badge_gmail_title")]
        : [null, null];
    pill.hidden = !key;
    if (key) {
        pill.textContent = t(key);
        pill.title = title;
    }
}

function subline(data, isPhishing, caution, flags) {
    const flagText = flags.length ? t("found_flags", { flags: flags.map(I18N.flagLabel).join(", ") }) : "";
    if (isPhishing) return t(data.links_elsewhere && !(data.link_alignment?.aligned > 0) ? "lead_links_elsewhere" : "sub_phishing") + flagText;
    if (caution) return t("sub_caution") + flagText;
    if (data.forwarded?.detected) return t("sub_forwarded");
    if (data.shared_links?.count) return t("sub_shared", { services: (data.shared_links.services || []).join(", ") });
    if (data.trusted_sender) return t("sub_trusted");
    if (data.sender_auth?.cryptographically_verified) return t("sub_crypto");
    return t("verdict_safe_sub");
}

// Element ids and hint keys of each agent card ("meta-score", "meta_high").
const PREFIX = { text: "text", url: "url", metadata: "meta" };

function fillAgent(key, agent) {
    const prefix = PREFIX[key];
    const bar = $(`${prefix}-bar`);
    const card = bar.closest(".agent");
    if (key === "metadata" && agent?.checked === false) {
        $(`${prefix}-score`).textContent = "—";
        bar.style.width = "0%";
        card.dataset.flagged = "safe";
        $(`${prefix}-hint`).textContent = t("meta_not_checked");
        return;
    }
    const p = Number(agent?.phishing_probability) || 0;
    const pct = Math.round(p * 100);
    $(`${prefix}-score`).textContent = `${pct}%`;
    bar.style.width = `${pct}%`;
    card.dataset.flagged = agent?.verdict === "Phishing" ? "phishing" : "safe";
    $(`${prefix}-hint`).textContent = t(`${prefix}_${p >= 0.7 ? "high" : p >= 0.4 ? "mid" : "low"}`);
}

function renderUrlBadges(rep) {
    const host = $("url-badges");
    const badges = [];
    if (rep?.checked && rep.malicious_count === 0) {
        badges.push(badge(tn("links_checked", rep.checked), "good", t("links_clean_title")));
    } else if (rep?.checked) {
        for (const src of rep.sources_hit || []) {
            const source = SOURCE_LABELS[src] || src;
            badges.push(badge(t("chip_flagged_by", { source }), "bad", t("chip_flagged_title", { source, count: rep.malicious_count })));
        }
        for (const type of rep.threat_types || []) {
            badges.push(badge(THREAT_KEYS[type] ? t(THREAT_KEYS[type]) : type.toLowerCase(), "bad", t("threat_type_title", { type })));
        }
    }
    host.replaceChildren(...badges);
    host.hidden = !rep?.checked;
}

function renderMetaBadges(auth) {
    const badges = [];
    if (auth?.impersonation?.brand) {
        const brand = String(auth.impersonation.brand).replace(/(^|\s)\S/g, (c) => c.toUpperCase());
        const vars = { brand, domain: auth.impersonation.domain || "?" };
        badges.push(badge(t("chip_impersonation", vars), "bad", t("chip_impersonation_title", vars)));
    }
    if (auth?.cryptographically_verified) badges.push(badge(t("dkim_aligned"), "good", t("dkim_aligned_title")));
    for (const [name, verdict] of [["SPF", auth?.spf], ["DKIM", auth?.dkim], ["DMARC", auth?.dmarc]]) {
        // "none", "neutral", "temperror": no badge.
        const kind = { pass: "good", fail: "bad", softfail: "warn" }[verdict];
        if (kind) badges.push(badge(t(`auth_${verdict}`, { name }), kind, t(`auth_${verdict}_title`, { name })));
    }
    if (auth?.spamhaus_dbl_listed) badges.push(badge(t("chip_spamhaus"), "bad", t("chip_spamhaus_title")));
    if ((auth?.reasons || []).includes("no_auth_header") && !badges.length) {
        badges.push(badge(t("no_auth_header"), "warn", t("no_auth_header_title")));
    }
    const host = $("meta-badges");
    host.replaceChildren(...badges);
    host.hidden = !badges.length;
}

// Inside an archive: the files that explain the verdict, then every
// file, folded. File names come from the archive: text nodes only.
function renderArchiveFiles(att, isPhishing) {
    const box = $("archive-files");
    box.replaceChildren();
    if (att?.kind === "archive") {
        const risky = Array.isArray(att.suspicious_files) ? att.suspicious_files : [];
        const entries = Array.isArray(att.entries) ? att.entries : [];
        const name = (n) => h("span.archive-files__name", { title: n }, n);
        if (risky.length) {
            box.append(h(`div.archive-files__risky.archive-files__risky--${isPhishing ? "bad" : "warn"}`, null,
                h("div.archive-files__title", null, t(isPhishing ? "att_do_not_open" : "att_check_before")),
                h("ul", null, risky.map((f) => h("li", null, name(f.name),
                    h("span.archive-files__why", null, (f.reasons || []).map(I18N.reasonLabel).join(", ")))))));
        }
        if (entries.length) {
            box.append(h("details.archive-files__all", null,
                h("summary", null, t("att_files_list", { count: att.entry_count || entries.length })),
                h("ul", null,
                    entries.map((n) => h("li", null, name(n))),
                    att.entry_count > entries.length &&
                        h("li.archive-files__more", null, t("att_and_more", { count: att.entry_count - entries.length })))));
        }
    }
    box.hidden = !box.childElementCount;
}

export function renderResult(data) {
    const isPhishing = data.verdict === "phishing";
    const isAttachment = !!data.attachment;
    const flags = data.attachment?.notable_features || [];
    const caution = isAttachment && !isPhishing && isCaution(flags);

    $("verdict-card").classList.toggle("verdict-card--danger", isPhishing);
    $("verdict-icon").replaceChildren(spriteIcon(isPhishing ? "alert" : "shield-check"));
    $("verdict-label").textContent = isPhishing
        ? t(isAttachment ? "verdict_file_phishing" : "verdict_phishing")
        : caution ? t("verdict_file_caution") : t(isAttachment ? "verdict_file_safe" : "verdict_safe");
    $("verdict-sub").textContent = subline(data, isPhishing, caution, flags);
    renderTrustPill(data);
    renderArchiveFiles(data.attachment, isPhishing);
    for (const key of ["text", "url", "metadata"]) fillAgent(key, data.agents?.[key]);
    renderUrlBadges(data.url_reputation);
    renderMetaBadges(data.sender_auth);
    explanation.reset(!isAttachment);
}

// The words behind the text score, computed in the background while the
// user reads the result, and shown when "Why this verdict?" is opened.
// /explain does not take attachments, so the panel is hidden for them.
const explanation = {
    panel: $("explain-panel"),
    tokens: $("explain-tokens"),
    status: $("explain-status"),
    features: null,
    error: null,
    run: 0,

    reset(visible) {
        this.run++;
        this.features = null;
        this.error = null;
        this.panel.hidden = !visible;
        this.panel.removeAttribute("open");
        this.tokens.replaceChildren();
        this.status.hidden = true;
    },

    async fetch(payload, historyId) {
        const run = this.run;
        try {
            const result = await window.PhishLensApi.explain(payload);
            if (run !== this.run) return;              // the user moved on
            this.features = result.features || [];
            if (historyId) {
                const tokens = this.features.slice(0, 5).map((f) => ({ token: f.token || "", weight: f.weight || 0 }));
                await window.PhishLensHistory.attachTokens(historyId, tokens);
            }
        } catch (e) {
            if (run !== this.run) return;
            this.error = e.message;
        }
        if (this.panel.open) this.render();
    },

    render() {
        if (this.error) return this.showStatus(t("explain_unavailable", { error: this.error }));
        if (!this.features) {
            this.tokens.replaceChildren(h("span.explain__status", null, t("computing_lime")));
            return;
        }
        // LIME weights are tiny: the colour shows each word's weight
        // relative to the strongest one, the exact share is in the tooltip.
        const shown = this.features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
        if (!shown.length) return this.showStatus(t("no_tokens_model"));
        const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
        this.tokens.replaceChildren(...shown.map((f) => {
            const rel = Math.abs(Number(f.weight) || 0) / max;
            const phishing = f.supports === "phishing";
            return h(`span.token.${phishing ? "token--phishing" : "token--safe"}`, {
                style: { "--a": (0.10 + rel * 0.35).toFixed(2) },
                title: t("token_title_popup", { side: t(phishing ? "side_phishing" : "side_safe"), pct: Math.round(rel * 100) }),
            }, f.token);
        }));
        this.status.hidden = true;
    },

    showStatus(text) {
        this.tokens.replaceChildren();
        this.status.hidden = false;
        this.status.textContent = text;
    },
};

explanation.panel.addEventListener("toggle", () => {
    if (explanation.panel.open) explanation.render();
});

export const explain = (payload, historyId) => explanation.fetch(payload, historyId);
export const cancelExplanation = () => explanation.reset(true);
