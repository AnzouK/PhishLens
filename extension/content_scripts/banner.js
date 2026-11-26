// Verdict banner above an email in Gmail and Outlook. It holds the
// verdict, a plain-language line, one meter per agent, signal chips and
// the words behind the text score.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t } = PhishLensI18n;
const { h, icon } = PhishLensDom;
const { SOURCE_LABELS } = PhishLensConstants;

// "None of its links lead to that domain" is shown only when that is
// literally true. The rule also fires on a file-host link next to a decoy
// link to the sender's own domain.
const allLinksElsewhere = (data) => data.links_elsewhere && !(data.link_alignment?.aligned > 0);

// Line under the title. On a safe verdict with a high agent score it
// explains why that score did not count. In the caution style it starts
// with "Some signs are unusual", followed by that reason when there is
// one.
function bannerLead(data, phishing, caution) {
    if (phishing) return t(allLinksElsewhere(data) ? "lead_links_elsewhere" : "lead_phishing");
    const reason = safeReason(data);
    if (!caution) return t(reason || "lead_safe", { services: sharedServices(data) });
    return [t("lead_caution"), reason && reason !== "lead_one_signal" ? t(reason, { services: sharedServices(data) }) : ""]
        .filter(Boolean).join(" ");
}

PL.bannerLead = bannerLead;

const sharedServices = (data) => (data.shared_links?.services || []).join(", ");

// Key of the line that explains a safe verdict, or null for the plain
// "no strong phishing signals" (PhishLensShared.safeReason).
function safeReason(data) {
    const reason = PhishLensShared.safeReason(data);
    return reason ? `lead_${reason}` : null;
}

// Brand names come from the server in lower case ("la poste" becomes
// "La Poste").
const brandName = (name) => String(name || "").replace(/(^|\s)\S/g, (c) => c.toUpperCase());

// One meter per agent. A null value means the agent had nothing to read.
function meter(label, value, offTitle = "meter_not_checked_title") {
    if (value === null) {
        return h("div.pll-meter", { title: t(offTitle, { label }) },
            h("span.pll-meter__l", null, label),
            h("span.pll-meter__off", null, t("meter_not_checked")));
    }
    const p = Math.max(0, Math.min(100, Number(value) || 0));
    const level = PhishLensShared.scoreLevel(p / 100);
    return h("div.pll-meter", { title: t("meter_title", { label, pct: p }) },
        h("span.pll-meter__l", null, label),
        h("span.pll-meter__track", null, h(`span.pll-meter__fill.pll-meter__fill--${level}`, { style: { width: `${p}%` } })),
        h("span.pll-meter__v", null, `${p}%`));
}

// Trust pill: allowlist > DKIM alignment > DMARC > Outlook internal > Gmail inbox.
// The server never reports dmarc_verified and the Gmail inbox together.
function trustBadge(data) {
    const auth = data.sender_auth || {};
    const pill = (key, title) => h("span.pll-trusted", { title }, t(key));
    if (data.trusted_sender) return pill("badge_trusted", t("badge_trusted_title", { domain: data.sender_domain || "" }));
    if (auth.cryptographically_verified) {
        return pill("badge_dkim", t("badge_dkim_title", {
            domain: data.sender_domain || "", spf: auth.spf || "none", dkim: auth.dkim || "none", dmarc: auth.dmarc || "none",
        }));
    }
    if (auth.dmarc_verified) {
        return pill("badge_dmarc", t("badge_dmarc_title", {
            domain: data.sender_domain || "", spf: auth.spf || "none", dkim: auth.dkim || "none", dmarc: auth.dmarc || "none",
        }));
    }
    if (auth.outlook_internal) return pill("badge_internal", t("badge_internal_title"));
    if (auth.gmail_inbox_soft_verified) return pill("badge_gmail", t("badge_gmail_title"));
    return null;
}

// `base` is "pll-chip" in the banner and "pll-att-chip" on an attachment card.
const chipOf = (base) => (kind, text, title) => h(`span.${base}${kind ? `.${base}--${kind}` : ""}`, { title }, text);
const chip = chipOf("pll-chip");

// Chips are shown worst first: bad, then warn, then good, then neutral,
// in the banner (pll-chip--bad...) and on attachment cards (pll-att-chip--bad...).
const CHIP_ORDER = ["bad", "warn", "good"];
const chipRank = (c) => {
    const i = CHIP_ORDER.findIndex((kind) => String(c.className).split(" ").some((cls) => cls.endsWith(`--${kind}`)));
    return i < 0 ? CHIP_ORDER.length : i;
};
// Array.prototype.sort is stable, so chips of one kind keep their order.
const byRank = (chips) => chips.sort((a, b) => chipRank(a) - chipRank(b));
PL.byRank = byRank;

// One orange or red chip per unusual sign (PhishLensShared.unusualSigns).
// attachments.js reuses this for the card of an attached email.
function signChips(data, base = "pll-chip") {
    const make = chipOf(base);
    const chips = [];
    const imp = data.sender_auth?.impersonation;
    if (imp?.brand) {
        const vars = { brand: brandName(imp.brand), domain: imp.domain || "?" };
        chips.push(make("bad", t("chip_impersonation", vars), t("chip_impersonation_title", vars)));
    }
    if (data.forwarded?.detected) {
        const orig = data.forwarded.original_sender;
        chips.push(make("warn",
            orig ? t("chip_forwarded_from", { sender: orig }) : t("chip_forwarded"),
            orig ? t("chip_original_sender", { sender: orig }) : t("chip_original_unknown")));
    }
    if (data.shared_links?.count) {
        chips.push(make("warn", t("chip_shared", { services: (data.shared_links.services || []).join(", ") }),
            (data.shared_links.urls || []).join("\n")));
    }
    const rep = data.url_reputation || {};
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const source = SOURCE_LABELS[src] || src;
            chips.push(make("bad", t("chip_flagged_by", { source }), t("chip_flagged_title", { source, count: rep.malicious_count })));
        }
    }
    const auth = data.sender_auth || {};
    if (PhishLensShared.authFailed(auth)) {
        if (auth.dmarc === "fail") chips.push(make("bad", t("chip_dmarc_fail"), t("chip_dmarc_fail_title")));
        else if (auth.dkim === "fail") chips.push(make("bad", t("chip_dkim_fail"), t("chip_dkim_fail_title")));
        else chips.push(make("warn", t("chip_spf_fail"), t("chip_spf_fail_title")));
    }
    if (auth.spamhaus_dbl_listed) chips.push(make("bad", t("chip_spamhaus"), t("chip_spamhaus_title")));
    return byRank(chips);
}
PL.signChips = signChips;

function signalChips(data) {
    const chips = signChips(data);
    if (data._fullHeaders) chips.push(chip("good", t("chip_full_headers"), t("chip_full_headers_title")));
    if (data._threadMessages > 1) {
        chips.push(chip("", t("chip_latest", { count: data._threadMessages }), t("chip_latest_title")));
    }
    const rep = data.url_reputation || {};
    if (!(rep.malicious_count > 0) && rep.checked > 0) {
        chips.push(chip("good", t("chip_links_clean"), t("chip_links_clean_title")));
    }
    byRank(chips);
    return chips.length ? h("div.pll-signals", null, chips) : null;
}

function closeButton(banner) {
    return h("button.pll-banner__close", {
        type: "button", title: t("dismiss"), "aria-label": t("dismiss"), onclick: () => banner.remove(),
    }, icon("close"));
}

// An error, or a neutral notice ({ verdict: "notice" }) such as the
// privacy notice before the first scan.
function errorContent(data, notice = false) {
    return [
        h("span.pll-banner__icon", null, icon(notice ? "info" : "alert")),
        h("div.pll-banner__main", null,
            h("div.pll-banner__title", null, data.title || t("error_title")),
            h("div.pll-banner__lead", null, data.error || "")),
    ];
}

// `kind` is "danger", "caution" or "safe" (PhishLensShared.displayVerdict).
function verdictContent(data, kind) {
    const phishing = kind === "danger";
    const caution = kind === "caution";
    const meta = data.agents?.metadata?.checked === false ? null : PL.pct(data.agents?.metadata?.phishing_probability);
    // With almost no text the text model did not count, so its meter
    // reads "not checked".
    const wording = data.text_agent_used === false ? null : PL.pct(data.agents?.text?.phishing_probability);
    return [
        h("span.pll-banner__icon", null, icon(phishing || caution ? "alert" : "shieldCheck")),
        h("div.pll-banner__main", null,
            h("div.pll-banner__head", null,
                h("span.pll-banner__title", null, t(phishing ? "verdict_phishing" : caution ? "verdict_caution" : "verdict_safe")),
                trustBadge(data)),
            h("div.pll-banner__lead", null, bannerLead(data, phishing, caution)),
            h("div.pll-meters", null,
                meter(t("meter_wording"), wording, "meter_text_not_checked_title"),
                meter(t("meter_links"), PL.pct(data.agents?.url?.phishing_probability)),
                meter(t("meter_sender"), meta)),
            signalChips(data),
            h("details.pll-banner__why", null,
                h("summary", null, t("why_verdict")),
                h("p.pll-banner__hint", null, t("why_hint")),
                h("div.pll-banner__tokens", null, h("span.pll-banner__loading", null, t("computing_explanation"))))),
    ];
}

// Shows the banner for `data` in `emailView`, replacing any earlier one.
// `data` is an /analyse answer or { verdict: "error" or "notice", title,
// error }. On Outlook it goes before `anchor`. On Gmail it finds its own
// place.
PL.showBanner = function showBanner(emailView, data, anchor = null) {
    const old = emailView.querySelector(".pll-banner");
    // A privacy notice replaced by another banner was not accepted.
    old?._pllCancel?.();
    old?.remove();
    const notice = data.verdict === "notice";
    const isError = notice || data.verdict === "error";
    // A safe verdict next to a red meter or an orange or red chip is
    // shown in the caution style (PhishLensShared.displayVerdict).
    const kind = notice ? "notice" : isError ? "error" : PhishLensShared.displayVerdict(data);
    const banner = h("div", { class: `pll-banner pll-banner--${kind}` });
    banner.append(...(isError ? errorContent(data, notice) : verdictContent(data, kind)), closeButton(banner));

    const { SEL } = PhishLensGmail;
    const headerBar = emailView.querySelector(SEL.headerBar);
    if (anchor?.parentNode) {
        anchor.parentNode.insertBefore(banner, anchor);
    } else if (headerBar?.parentNode) {
        headerBar.parentNode.insertBefore(banner, headerBar);
    } else {
        const bodyEl = emailView.querySelector(SEL.body);
        bodyEl?.parentNode?.insertBefore(banner, bodyEl);
    }
    return banner;
};

// Words behind the text score. LIME weights are tiny (often below 0.01),
// so the colour strength shows each word's weight relative to the
// strongest. Single characters and bare numbers mean nothing to a reader,
// so we keep them in the history but don't show them.
PL.attachExplanation = function attachExplanation(emailView, features, cached = false) {
    const slot = emailView.querySelector(".pll-banner .pll-banner__tokens");
    if (!slot) return;
    if (!features.length) {
        slot.textContent = t("no_tokens");
        return;
    }
    const shown = features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
    if (!shown.length) {
        slot.textContent = t("no_meaningful_words");
        return;
    }
    const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
    slot.replaceChildren(...shown.map((f) => {
        const rel = Math.abs(Number(f.weight) || 0) / max;
        const phishingSide = f.supports === "phishing";
        return h(`span.pll-tok.${phishingSide ? "pll-tok--phishing" : "pll-tok--safe"}`, {
            style: { "--pll-a": (0.10 + rel * 0.35).toFixed(2) },
            title: t("token_title", { side: t(phishingSide ? "side_phishing" : "side_safe"), pct: Math.round(rel * 100) }),
        }, f.token);
    }));
    if (cached) slot.append(h("span.pll-cache-hint", { title: t("cached_title") }, t("cached")));
};

// Fetches the explanation after a scan, from the cache or the server, and
// stores its top words in the history entry.
PL.explainInBackground = async function explainInBackground(view, payload, data, historyId) {
    if (data.text_agent_used === false) {
        const slot = view.querySelector(".pll-banner .pll-banner__tokens");
        if (slot) slot.textContent = t("almost_no_text");
        return;
    }
    let result;
    try {
        result = await PhishLensApi.explain(payload);
    } catch (e) {
        PhishLensShared.debug("explanation not available", e);
        const slot = view.querySelector(".pll-banner .pll-banner__tokens");
        if (slot) slot.textContent = t("explain_unavailable", { error: e.message });
        return;
    }
    const features = result.features || [];
    PL.attachExplanation(view, features, result.cached);
    if (historyId) {
        const tokens = features.slice(0, 5).map((f) => ({ token: f.token || "", weight: f.weight || 0 }));
        PhishLensApi.history.attachTokens(historyId, tokens).catch((e) => PhishLensShared.debug("history tokens", e));
    }
};

// Before the first scan with PhishLens Cloud, shows the same notice as
// the popup about where the email goes. Resolves to true once the user
// has seen it (now or earlier, in the page or the popup), false if
// dismissed.
const NOTICE_KEY = "privacy_notice_seen";
PL.confirmCloudUse = async function confirmCloudUse(view, anchor = null) {
    const s = await new Promise((resolve) => chrome.storage.local.get([NOTICE_KEY, "backend"], (v) => resolve(v || {})));
    if (s[NOTICE_KEY] || (s.backend && s.backend !== "cloud")) return true;
    return new Promise((resolve) => {
        const banner = PL.showBanner(view, {
            verdict: "notice", title: t("privacy_notice_title"), error: t("privacy_notice_text"),
        }, anchor);
        const lang = PhishLensI18n.language();
        const ok = h("button.pll-att-btn", {
            type: "button",
            onclick: () => {
                chrome.storage.local.set({ [NOTICE_KEY]: true });
                banner.remove();
                resolve(true);
            },
        }, t("privacy_notice_ok"));
        const policy = h("a.pll-notice-link", {
            href: PhishLensShared.privacyUrl(lang),
            target: "_blank", rel: "noopener",
        }, t("privacy_notice_link"));
        banner.querySelector(".pll-banner__main").append(h("div.pll-notice-actions", null, ok, " ", policy));
        banner.querySelector(".pll-banner__close").addEventListener("click", () => resolve(false));
        banner._pllCancel = () => resolve(false);
    });
};

PL.showError = function showError(view, error, anchor = null) {
    PL.showBanner(view, { verdict: "error", error: String(error?.message || error) }, anchor);
};
})();
