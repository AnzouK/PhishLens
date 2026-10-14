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
        return "Don't click its links, open its attachments or reply until you have checked the sender another way.";
    }
    if (data.forwarded?.detected) {
        return "This is a forwarded email: the person who forwarded it is not the author, so their trust was not applied to the content.";
    }
    if (data.shared_links?.count) {
        const svc = (data.shared_links.services || []).join(", ");
        return `No strong phishing signals, but it links to a shared file or form (${svc}). Open it only if you expected it, and never sign in from it.`;
    }
    if (data.text_agent_used === false) {
        return "This email has almost no text, so only its links and sender were checked. Stay careful with image-only emails.";
    }
    const high = ["text", "url", "metadata"].some((k) => (data.agents?.[k]?.phishing_probability || 0) >= 0.7);
    if (high) {
        if (data.trust_path === "trusted_sender" || data.trusted_sender) {
            return "Some wording or links resemble phishing, but the sender is on the trusted list, so they weigh less.";
        }
        if (data.trust_path === "crypto_verified") {
            return "Some wording or links resemble phishing, but the sender is proven by DKIM, so they weigh less.";
        }
        if (data.trust_path === "outlook_internal") {
            return "Some wording or links resemble phishing, but it comes from inside your organisation, so they weigh less.";
        }
        if (data.trust_path === "gmail_inbox_soft") {
            return "Some wording or links resemble phishing, but Gmail verified the sender before delivery, so they weigh less.";
        }
        return "One signal looks suspicious, but not enough overall. Stay careful with this one.";
    }
    return "No strong phishing signals. Stay careful with unexpected requests for money or passwords.";
}

// One compact meter per agent: label, bar, percentage.
function pllMeter(label, value) {
    const p = Math.max(0, Math.min(100, Number(value) || 0));
    const level = p >= 70 ? "high" : p >= 40 ? "mid" : "low";
    return `<div class="pll-meter" title="${escapeHTML(label)}: ${p}% phishing">
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
              <div class="pll-banner__title">${escapeHTML(data.title || "PhishLens could not scan this email")}</div>
              <div class="pll-banner__lead">${escapeHTML(data.error || "")}</div>
            </div>
            <button type="button" class="pll-banner__close" title="Dismiss" aria-label="Dismiss">${PLL_ICON.close}</button>`;
    } else {
        const phishing = data.verdict === "phishing";
        banner.classList.add(phishing ? "pll-banner--danger" : "pll-banner--safe");
        const text   = pct(data.agents?.text?.phishing_probability);
        const url    = pct(data.agents?.url?.phishing_probability);
        const meta   = pct(data.agents?.metadata?.phishing_probability);
        // Trust pill: allowlist > DKIM alignment > Gmail-inbox-soft > nothing.
        const cryptoVerified   = !!data.sender_auth?.cryptographically_verified;
        const gmailSoftVerified = !!data.sender_auth?.gmail_inbox_soft_verified;
        let trustedBadge = "";
        if (data.trusted_sender) {
            trustedBadge = `<span class="pll-trusted" title="Sender domain is in the verified allowlist (${escapeHTML(data.sender_domain || "")})">Trusted sender</span>`;
        } else if (cryptoVerified) {
            const spf = data.sender_auth?.spf || "none";
            const dkim = data.sender_auth?.dkim || "none";
            const dmarc = data.sender_auth?.dmarc || "none";
            trustedBadge = `<span class="pll-trusted" title="DKIM signature aligned with From: ${escapeHTML(data.sender_domain || "")}, SPF=${escapeHTML(spf)} DKIM=${escapeHTML(dkim)} DMARC=${escapeHTML(dmarc)}">DKIM verified</span>`;
        } else if (data.sender_auth?.outlook_internal) {
            trustedBadge = `<span class="pll-trusted" title="Sent from inside your organisation: your mail server authenticated it. Softer signal than a DKIM check.">Internal sender</span>`;
        } else if (gmailSoftVerified) {
            trustedBadge = `<span class="pll-trusted" title="Gmail delivered this to Inbox, so its own SPF/DKIM/DMARC verification passed. Softer signal than a full crypto verification.">Delivered by Gmail</span>`;
        }

        // Threat-intel signals under the score line.
        const signalChips = renderBannerSignals(data);
        banner.innerHTML = `
            <span class="pll-banner__icon">${phishing ? PLL_ICON.alert : PLL_ICON.shieldCheck}</span>
            <div class="pll-banner__main">
              <div class="pll-banner__head">
                <span class="pll-banner__title">${phishing ? "This email looks like phishing" : "This email looks safe"}</span>
                ${trustedBadge}
              </div>
              <div class="pll-banner__lead">${bannerLead(data, phishing)}</div>
              <div class="pll-meters">
                ${pllMeter("Wording", text)}
                ${pllMeter("Links", url)}
                ${pllMeter("Sender", meta)}
              </div>
              ${signalChips}
              <details class="pll-banner__why">
                <summary>Why this verdict?</summary>
                <p class="pll-banner__hint">Words that pushed the text model the most. Stronger colour means stronger influence; orange points to phishing, green to safe.</p>
                <div class="pll-banner__tokens"><span class="pll-banner__loading">Computing the explanation…</span></div>
              </details>
            </div>
            <button type="button" class="pll-banner__close" title="Dismiss" aria-label="Dismiss">${PLL_ICON.close}</button>`;
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
        slot.textContent = "No salient tokens returned.";
        return;
    }
    // LIME weights are tiny (often < 0.01), so printing them shows "0.00".
    // Show relative influence instead: colour strength scales with the
    // token's weight compared with the strongest one.
    // Single characters and bare numbers ("1", "t") carry no meaning for
    // a reader; keep them out of the display (they stay in the history).
    const shown = features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
    if (!shown.length) { slot.textContent = "No meaningful words to show for this email."; return; }
    const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
    const chips = shown.map((f) => {
        const w = Number(f.weight) || 0;
        const rel = Math.abs(w) / max;
        const cls = f.supports === "phishing" ? "pll-tok--phishing" : "pll-tok--safe";
        return `<span class="pll-tok ${cls}" style="--pll-a:${(0.10 + rel * 0.35).toFixed(2)}" ` +
               `title="Pushes toward ${escapeHTML(f.supports)} (${Math.round(rel * 100)}% of the strongest word)">${escapeHTML(f.token)}</span>`;
    }).join("");
    slot.innerHTML = cached
        ? chips + '<span class="pll-cache-hint" title="Explanation served from the local cache, no server call">cached</span>'
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

    // Forwarded email, shared-file links, thread position.
    if (data.forwarded?.detected) {
        const orig = data.forwarded.original_sender;
        chips.push(`<span class="pll-chip pll-chip--warn" title="${escapeHTML(orig ? "Original sender: " + orig : "Original sender not found")}">Forwarded${orig ? ": " + escapeHTML(orig) : ""}</span>`);
    }
    if (data.shared_links?.count) {
        chips.push(`<span class="pll-chip pll-chip--warn" title="${escapeHTML((data.shared_links.urls || []).join("\n"))}">Shared file: ${escapeHTML((data.shared_links.services || []).join(", "))}</span>`);
    }
    if (data._fullHeaders) {
        chips.push(`<span class="pll-chip pll-chip--good" title="PhishLens read the full original message (all headers), not only the visible page">Full headers checked</span>`);
    }
    if (data._threadMessages > 1) {
        chips.push(`<span class="pll-chip" title="In a conversation, PhishLens scans the last expanded message">Latest message of ${data._threadMessages}</span>`);
    }
    const rep = data.url_reputation || {};
    const auth = data.sender_auth || {};

    // URL reputation chips: one per intel source that flagged.
    if (rep.malicious_count > 0) {
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL_GMAIL[src] || src;
            chips.push(`<span class="pll-chip pll-chip--bad" title="${escapeHTML(label)} flagged ${rep.malicious_count} URL(s)">Flagged by ${escapeHTML(label)}</span>`);
        }
    } else if (rep.checked > 0) {
        chips.push(`<span class="pll-chip pll-chip--good" title="Every link was checked against the threat-intelligence sources">Links checked, none flagged</span>`);
    }

    // Sender-auth failures worth surfacing prominently.
    if (auth.dmarc === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DMARC check failed: the From: domain does not authorise this sender">DMARC fail</span>`);
    } else if (auth.dkim === "fail") {
        chips.push(`<span class="pll-chip pll-chip--bad" title="DKIM signature invalid or missing">DKIM fail</span>`);
    } else if (auth.spf === "fail") {
        chips.push(`<span class="pll-chip pll-chip--warn" title="SPF check failed: sender IP not authorised">SPF fail</span>`);
    }

    if (auth.spamhaus_dbl_listed) {
        chips.push(`<span class="pll-chip pll-chip--bad" title="Sender domain is on the Spamhaus block list">Sender on Spamhaus list</span>`);
    }

    if (!chips.length) return "";
    return `<div class="pll-signals">${chips.join(" ")}</div>`;
}
