// The verdict banner above an email (Gmail and Outlook): verdict, a
// plain-language line, one meter per agent, signal chips, and the words
// behind the text score.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t } = PhishLensI18n;
const { h, icon } = PhishLensDom;
const { SOURCE_LABELS } = PhishLensConstants;

// The line under the title. On a safe verdict with a high agent score,
// it says why that score did not count: red meters under "looks safe"
// would read as a contradiction.
function bannerLead(data, phishing) {
    if (phishing) return t(data.links_elsewhere ? "lead_links_elsewhere" : "lead_phishing");
    if (data.forwarded?.detected) return t("lead_forwarded");
    if (data.shared_links?.count) return t("lead_shared", { services: (data.shared_links.services || []).join(", ") });
    if (data.text_agent_used === false) return t("lead_no_text");
    const high = ["text", "url", "metadata"].some((k) => (data.agents?.[k]?.phishing_probability || 0) >= 0.7);
    if (!high) return t("lead_safe");
    if (data.trust_path === "trusted_sender" || data.trusted_sender) return t("lead_trusted");
    const byPath = { crypto_verified: "lead_crypto", outlook_internal: "lead_internal", gmail_inbox_soft: "lead_gmail" };
    return t(byPath[data.trust_path] || "lead_one_signal");
}

// "la poste" -> "La Poste": brand names come from the server in lower case.
const brandName = (name) => String(name || "").replace(/(^|\s)\S/g, (c) => c.toUpperCase());

// One meter per agent; value null: the agent had nothing to read.
function meter(label, value) {
    if (value === null) {
        return h("div.pll-meter", { title: t("meter_not_checked_title", { label }) },
            h("span.pll-meter__l", null, label),
            h("span.pll-meter__off", null, t("meter_not_checked")));
    }
    const p = Math.max(0, Math.min(100, Number(value) || 0));
    const level = p >= 70 ? "high" : p >= 40 ? "mid" : "low";
    return h("div.pll-meter", { title: t("meter_title", { label, pct: p }) },
        h("span.pll-meter__l", null, label),
        h("span.pll-meter__track", null, h(`span.pll-meter__fill.pll-meter__fill--${level}`, { style: { width: `${p}%` } })),
        h("span.pll-meter__v", null, `${p}%`));
}

// Trust pill: allowlist > DKIM alignment > Outlook internal > Gmail inbox.
function trustBadge(data) {
    const auth = data.sender_auth || {};
    const pill = (key, title) => h("span.pll-trusted", { title }, t(key));
    if (data.trusted_sender) return pill("badge_trusted", t("badge_trusted_title", { domain: data.sender_domain || "" }));
    if (auth.cryptographically_verified) {
        return pill("badge_dkim", t("badge_dkim_title", {
            domain: data.sender_domain || "", spf: auth.spf || "none", dkim: auth.dkim || "none", dmarc: auth.dmarc || "none",
        }));
    }
    if (auth.outlook_internal) return pill("badge_internal", t("badge_internal_title"));
    if (auth.gmail_inbox_soft_verified) return pill("badge_gmail", t("badge_gmail_title"));
    return null;
}

const chip = (kind, text, title) => h(`span.pll-chip${kind ? ".pll-chip--" + kind : ""}`, { title }, text);

function signalChips(data) {
    const chips = [];
    const imp = data.sender_auth?.impersonation;
    if (imp?.brand) {
        const vars = { brand: brandName(imp.brand), domain: imp.domain || "?" };
        chips.push(chip("bad", t("chip_impersonation", vars), t("chip_impersonation_title", vars)));
    }
    if (data.forwarded?.detected) {
        const orig = data.forwarded.original_sender;
        chips.push(chip("warn",
            orig ? t("chip_forwarded_from", { sender: orig }) : t("chip_forwarded"),
            orig ? t("chip_original_sender", { sender: orig }) : t("chip_original_unknown")));
    }
    if (data.shared_links?.count) {
        chips.push(chip("warn", t("chip_shared", { services: (data.shared_links.services || []).join(", ") }),
            (data.shared_links.urls || []).join("\n")));
    }
    if (data._fullHeaders) chips.push(chip("good", t("chip_full_headers"), t("chip_full_headers_title")));
    if (data._threadMessages > 1) {
        chips.push(chip("", t("chip_latest", { count: data._threadMessages }), t("chip_latest_title")));
    }
    const rep = data.url_reputation || {};
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const source = SOURCE_LABELS[src] || src;
            chips.push(chip("bad", t("chip_flagged_by", { source }), t("chip_flagged_title", { source, count: rep.malicious_count })));
        }
    } else if (rep.checked > 0) {
        chips.push(chip("good", t("chip_links_clean"), t("chip_links_clean_title")));
    }
    const auth = data.sender_auth || {};
    if (auth.dmarc === "fail") chips.push(chip("bad", t("chip_dmarc_fail"), t("chip_dmarc_fail_title")));
    else if (auth.dkim === "fail") chips.push(chip("bad", t("chip_dkim_fail"), t("chip_dkim_fail_title")));
    else if (auth.spf === "fail") chips.push(chip("warn", t("chip_spf_fail"), t("chip_spf_fail_title")));
    if (auth.spamhaus_dbl_listed) chips.push(chip("bad", t("chip_spamhaus"), t("chip_spamhaus_title")));
    return chips.length ? h("div.pll-signals", null, chips) : null;
}

function closeButton(banner) {
    return h("button.pll-banner__close", {
        type: "button", title: t("dismiss"), "aria-label": t("dismiss"), onclick: () => banner.remove(),
    }, icon("close"));
}

function errorContent(data) {
    return [
        h("span.pll-banner__icon", null, icon("alert")),
        h("div.pll-banner__main", null,
            h("div.pll-banner__title", null, data.title || t("error_title")),
            h("div.pll-banner__lead", null, data.error || "")),
    ];
}

function verdictContent(data, phishing) {
    const meta = data.agents?.metadata?.checked === false ? null : PL.pct(data.agents?.metadata?.phishing_probability);
    return [
        h("span.pll-banner__icon", null, icon(phishing ? "alert" : "shieldCheck")),
        h("div.pll-banner__main", null,
            h("div.pll-banner__head", null,
                h("span.pll-banner__title", null, t(phishing ? "verdict_phishing" : "verdict_safe")),
                trustBadge(data)),
            h("div.pll-banner__lead", null, bannerLead(data, phishing)),
            h("div.pll-meters", null,
                meter(t("meter_wording"), PL.pct(data.agents?.text?.phishing_probability)),
                meter(t("meter_links"), PL.pct(data.agents?.url?.phishing_probability)),
                meter(t("meter_sender"), meta)),
            signalChips(data),
            h("details.pll-banner__why", null,
                h("summary", null, t("why_verdict")),
                h("p.pll-banner__hint", null, t("why_hint")),
                h("div.pll-banner__tokens", null, h("span.pll-banner__loading", null, t("computing_explanation"))))),
    ];
}

// Shows the banner for `data` (an /analyse answer, or { verdict: "error",
// title, error }) in `emailView`, replacing any earlier one. `anchor`:
// insert it before that element (Outlook); Gmail finds its own place.
PL.showBanner = function showBanner(emailView, data, anchor = null) {
    emailView.querySelector(".pll-banner")?.remove();
    const isError = data.verdict === "error";
    const phishing = data.verdict === "phishing";
    const banner = h("div", {
        class: "pll-banner " + (isError ? "pll-banner--error" : phishing ? "pll-banner--danger" : "pll-banner--safe"),
    });
    banner.append(...(isError ? errorContent(data) : verdictContent(data, phishing)), closeButton(banner));

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

// The words behind the text score. LIME weights are tiny (often < 0.01):
// the colour strength shows each word's weight relative to the strongest.
// Single characters and bare numbers mean nothing to a reader; they stay
// in the history but are not shown.
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

// After a scan: the explanation (computed in the background, or from the
// cache) and its top words in the history entry.
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

// Before the first scan with PhishLens Cloud, the same notice as the
// popup's: where the email goes. Resolves to true once the user has seen
// it (now or earlier, in the page or in the popup), false if dismissed.
const NOTICE_KEY = "privacy_notice_seen";
PL.confirmCloudUse = async function confirmCloudUse(view, anchor = null) {
    const s = await new Promise((resolve) => chrome.storage.local.get([NOTICE_KEY, "backend"], (v) => resolve(v || {})));
    if (s[NOTICE_KEY] || (s.backend && s.backend !== "cloud")) return true;
    return new Promise((resolve) => {
        const banner = PL.showBanner(view, {
            verdict: "error", title: t("privacy_notice_title"), error: t("privacy_notice_text"),
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
            href: `https://phishlens.dev/${lang && lang !== "en" ? lang + "/" : ""}privacy.html`,
            target: "_blank", rel: "noopener",
        }, t("privacy_notice_link"));
        banner.querySelector(".pll-banner__main").append(h("div.pll-notice-actions", null, ok, " ", policy));
        banner.querySelector(".pll-banner__close").addEventListener("click", () => resolve(false));
    });
};

// The error banner for a failed scan.
PL.showError = function showError(view, error, anchor = null) {
    PL.showBanner(view, { verdict: "error", error: String(error?.message || error) }, anchor);
};
})();
