// =====================================================================
// PhishLens content script: the verdict banner (Gmail and Outlook).
// =====================================================================
// Renders the result of /analyse above the email: verdict, plain-language
// explanation, one meter per agent, signal chips, and the words behind
// the text agent's score (LIME).
// =====================================================================

// Plain-language line under the title. When the verdict is safe but some
// agent scored high, say why the high score did not count, otherwise the
// red meters under a "looks safe" title read as a contradiction.
function bannerLead(data, phishing) {
    if (phishing) {
        // A DKIM-signed sender flagged because all its links lead elsewhere:
        // say why next to the "DKIM verified" badge.
        return t(data.links_elsewhere ? "lead_links_elsewhere" : "lead_phishing");
    }
    if (data.forwarded?.detected) {
        return t("lead_forwarded");
    }
    if (data.shared_links?.count) {
        const svc = (data.shared_links.services || []).join(", ");
        return t("lead_shared", { services: svc });
    }
    if (data.text_agent_used === false) {
        return t("lead_no_text");
    }
    const high = ["text", "url", "metadata"].some((k) => (data.agents?.[k]?.phishing_probability || 0) >= 0.7);
    if (high) {
        if (data.trust_path === "trusted_sender" || data.trusted_sender) {
            return t("lead_trusted");
        }
        if (data.trust_path === "crypto_verified") {
            return t("lead_crypto");
        }
        if (data.trust_path === "outlook_internal") {
            return t("lead_internal");
        }
        if (data.trust_path === "gmail_inbox_soft") {
            return t("lead_gmail");
        }
        return t("lead_one_signal");
    }
    return t("lead_safe");
}

// "la poste" -> "La Poste": brand names come from the backend in lower case.
function pllBrand(name) {
    return String(name || "").replace(/(^|\s)\S/g, (c) => c.toUpperCase());
}

// One compact meter per agent: label, bar, percentage; value null: the
// agent had nothing to read ("not checked").
function pllMeter(label, value) {
    if (value === null) {
        return `<div class="pll-meter" title="${escapeHTML(t("meter_not_checked_title", { label }))}">
        <span class="pll-meter__l">${escapeHTML(label)}</span>
        <span class="pll-meter__off">${escapeHTML(t("meter_not_checked"))}</span>
    </div>`;
    }
    const p = Math.max(0, Math.min(100, Number(value) || 0));
    const level = p >= 70 ? "high" : p >= 40 ? "mid" : "low";
    return `<div class="pll-meter" title="${escapeHTML(t("meter_title", { label, pct: p }))}">
        <span class="pll-meter__l">${escapeHTML(label)}</span>
        <span class="pll-meter__track"><span class="pll-meter__fill pll-meter__fill--${level}" style="width:${p}%"></span></span>
        <span class="pll-meter__v">${p}%</span>
    </div>`;
}

// ---------------------------------------------------------------------
// Render the verdict banner above the email body
// ---------------------------------------------------------------------
// `anchor` (optional): insert the banner just before this element
// (used by the Outlook script); Gmail finds its own place.
function showBanner(emailView, data, anchor = null) {
    let banner = emailView.querySelector(":scope > .pll-banner") ||
                 emailView.querySelector(".pll-banner");
    if (banner) banner.remove();

    banner = document.createElement("div");
    banner.className = "pll-banner";

    if (data.verdict === "error") {
        banner.classList.add("pll-banner--error");
        banner.innerHTML = `
            <span class="pll-banner__icon">${PLL_ICON.alert}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__title">${escapeHTML(data.title || t("error_title"))}</div>
              <div class="pll-banner__lead">${escapeHTML(data.error || "")}</div>
            </div>
            <button type="button" class="pll-banner__close" title="${escapeHTML(t("dismiss"))}" aria-label="${escapeHTML(t("dismiss"))}">${PLL_ICON.close}</button>`;
    } else {
        const phishing = data.verdict === "phishing";
        banner.classList.add(phishing ? "pll-banner--danger" : "pll-banner--safe");
        const text   = pct(data.agents?.text?.phishing_probability);
        const url    = pct(data.agents?.url?.phishing_probability);
        const meta   = data.agents?.metadata?.checked === false ? null : pct(data.agents?.metadata?.phishing_probability);
        // Trust pill: allowlist > DKIM alignment > Gmail-inbox-soft > nothing.
        const cryptoVerified   = !!data.sender_auth?.cryptographically_verified;
        const gmailSoftVerified = !!data.sender_auth?.gmail_inbox_soft_verified;
        let trustedBadge = "";
        if (data.trusted_sender) {
            trustedBadge = `<span class="pll-trusted" title="${escapeHTML(t("badge_trusted_title", { domain: data.sender_domain || "" }))}">${escapeHTML(t("badge_trusted"))}</span>`;
        } else if (cryptoVerified) {
            const spf = data.sender_auth?.spf || "none";
            const dkim = data.sender_auth?.dkim || "none";
            const dmarc = data.sender_auth?.dmarc || "none";
            trustedBadge = `<span class="pll-trusted" title="${escapeHTML(t("badge_dkim_title", { domain: data.sender_domain || "", spf, dkim, dmarc }))}">${escapeHTML(t("badge_dkim"))}</span>`;
        } else if (data.sender_auth?.outlook_internal) {
            trustedBadge = `<span class="pll-trusted" title="${escapeHTML(t("badge_internal_title"))}">${escapeHTML(t("badge_internal"))}</span>`;
        } else if (gmailSoftVerified) {
            trustedBadge = `<span class="pll-trusted" title="${escapeHTML(t("badge_gmail_title"))}">${escapeHTML(t("badge_gmail"))}</span>`;
        }

        // Threat-intel signals under the score line.
        const signalChips = renderBannerSignals(data);
        banner.innerHTML = `
            <span class="pll-banner__icon">${phishing ? PLL_ICON.alert : PLL_ICON.shieldCheck}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__head">
                <span class="pll-banner__title">${escapeHTML(phishing ? t("verdict_phishing") : t("verdict_safe"))}</span>
                ${trustedBadge}
              </div>
              <div class="pll-banner__lead">${escapeHTML(bannerLead(data, phishing))}</div>
              <div class="pll-meters">
                ${pllMeter(t("meter_wording"), text)}
                ${pllMeter(t("meter_links"), url)}
                ${pllMeter(t("meter_sender"), meta)}
              </div>
              ${signalChips}
              <details class="pll-banner__why">
                <summary>${escapeHTML(t("why_verdict"))}</summary>
                <p class="pll-banner__hint">${escapeHTML(t("why_hint"))}</p>
                <div class="pll-banner__tokens"><span class="pll-banner__loading">${escapeHTML(t("computing_explanation"))}</span></div>
              </details>
            </div>
            <button type="button" class="pll-banner__close" title="${escapeHTML(t("dismiss"))}" aria-label="${escapeHTML(t("dismiss"))}">${PLL_ICON.close}</button>`;
    }

    const headerBar = emailView.querySelector(HEADER_BAR);
    if (anchor && anchor.parentNode) {
        anchor.parentNode.insertBefore(banner, anchor);
    } else if (headerBar && headerBar.parentNode) {
        headerBar.parentNode.insertBefore(banner, headerBar);
    } else {
        const bodyEl = emailView.querySelector(BODY_SEL);
        bodyEl?.parentNode?.insertBefore(banner, bodyEl);
    }

    banner.querySelector(".pll-banner__close")?.addEventListener("click", () => banner.remove());
}

function attachExplanation(emailView, features, cached = false) {
    const slot = emailView.querySelector(".pll-banner .pll-banner__tokens");
    if (!slot) return;
    if (!features.length) {
        slot.textContent = t("no_tokens");
        return;
    }
    // LIME weights are tiny (often < 0.01), so printing them shows "0.00".
    // Show relative influence instead: colour strength scales with the
    // token's weight compared with the strongest one.
    // Single characters and bare numbers ("1", "t") carry no meaning for
    // a reader; keep them out of the display (they stay in the history).
    const shown = features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
    if (!shown.length) { slot.textContent = t("no_meaningful_words"); return; }
    const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
    const chips = shown.map((f) => {
        const w = Number(f.weight) || 0;
        const rel = Math.abs(w) / max;
        const cls = f.supports === "phishing" ? "pll-tok--phishing" : "pll-tok--safe";
        return `<span class="pll-tok ${cls}" style="--pll-a:${(0.10 + rel * 0.35).toFixed(2)}" ` +
               `title="${escapeHTML(t("token_title", { side: f.supports === "phishing" ? t("side_phishing") : t("side_safe"), pct: Math.round(rel * 100) }))}">${escapeHTML(f.token)}</span>`;
    }).join("");
    slot.innerHTML = cached
        ? chips + `<span class="pll-cache-hint" title="${escapeHTML(t("cached_title"))}">${escapeHTML(t("cached"))}</span>`
        : chips;
}

// ---------------------------------------------------------------------
// Threat-intel signal chips inside the Gmail banner.
// ---------------------------------------------------------------------
const _SOURCE_LABEL_GMAIL = {
    google_safe_browsing: "Google Safe Browsing",
    phishtank:            "PhishTank",
    urlhaus:              "URLhaus",
    spamhaus_dbl:         "Spamhaus DBL",
};

function renderBannerSignals(data) {
    const chips = [];

    // A brand's name over another domain's address.
    const imp = data.sender_auth?.impersonation;
    if (imp?.brand) {
        const vars = { brand: pllBrand(imp.brand), domain: imp.domain || "?" };
        chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(t("chip_impersonation_title", vars))}">${escapeHTML(t("chip_impersonation", vars))}</span>`);
    }

    // Forwarded email, shared-file links, thread position.
    if (data.forwarded?.detected) {
        const orig = data.forwarded.original_sender;
        chips.push(`<span class="pll-chip pll-chip--warn" title="${escapeHTML(orig ? t("chip_original_sender", { sender: orig }) : t("chip_original_unknown"))}">${escapeHTML(orig ? t("chip_forwarded_from", { sender: orig }) : t("chip_forwarded"))}</span>`);
    }
    if (data.shared_links?.count) {
        chips.push(`<span class="pll-chip pll-chip--warn" title="${escapeHTML((data.shared_links.urls || []).join("\n"))}">${escapeHTML(t("chip_shared", { services: (data.shared_links.services || []).join(", ") }))}</span>`);
    }
    if (data._fullHeaders) {
        chips.push(`<span class="pll-chip pll-chip--good" title="${escapeHTML(t("chip_full_headers_title"))}">${escapeHTML(t("chip_full_headers"))}</span>`);
    }
    if (data._threadMessages > 1) {
        chips.push(`<span class="pll-chip" title="${escapeHTML(t("chip_latest_title"))}">${escapeHTML(t("chip_latest", { count: data._threadMessages }))}</span>`);
    }
    const rep = data.url_reputation || {};
    const auth = data.sender_auth || {};

    // URL reputation chips: one per intel source that flagged.
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL_GMAIL[src] || src;
            chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(t("chip_flagged_title", { source: label, count: rep.malicious_count }))}">${escapeHTML(t("chip_flagged_by", { source: label }))}</span>`);
        }
    } else if (rep.checked > 0) {
        chips.push(`<span class="pll-chip pll-chip--good" title="${escapeHTML(t("chip_links_clean_title"))}">${escapeHTML(t("chip_links_clean"))}</span>`);
    }

    // Sender-auth failures worth surfacing prominently.
    if (auth.dmarc === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(t("chip_dmarc_fail_title"))}">${escapeHTML(t("chip_dmarc_fail"))}</span>`);
    } else if (auth.dkim === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(t("chip_dkim_fail_title"))}">${escapeHTML(t("chip_dkim_fail"))}</span>`);
    } else if (auth.spf === "fail") {
        chips.push(`<span class="pll-chip pll-chip--warn" title="${escapeHTML(t("chip_spf_fail_title"))}">${escapeHTML(t("chip_spf_fail"))}</span>`);
    }

    if (auth.spamhaus_dbl_listed) {
        chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(t("chip_spamhaus_title"))}">${escapeHTML(t("chip_spamhaus"))}</span>`);
    }

    if (!chips.length) return "";
    return `<div class="pll-signals">${chips.join(" ")}</div>`;
}
