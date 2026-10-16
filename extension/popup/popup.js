// =====================================================================
// PhishLens popup logic.
// =====================================================================

// Server choice (chrome.storage "backend"): "cloud" (PhishLens Cloud, the
// default), "local" (Docker on this computer) or "custom" (a typed URL).
const { DEFAULT_BACKEND, resolveBackend, escapeHTML, apiErrorMessage } = window.PhishLensShared;
const I18N = window.PhishLensI18n;
const { t, tn, flagLabel, reasonLabel } = I18N;

let backendChoice = DEFAULT_BACKEND;     // "local" | "cloud" | "custom"
let backendCustomUrl = "";
function getApiBase() {
    return resolveBackend(backendChoice, backendCustomUrl);
}

// ---------- DOM refs ----------
const $ = (id) => document.getElementById(id);
const views = {
    upload: $("view-upload"),
    loading: $("view-loading"),
    result: $("view-result"),
    settings: $("view-settings"),
    insights: $("view-insights"),
};

// Track the id of the currently-displayed scan so we can attach its LIME
// tokens to the history entry once /explain resolves.
let currentHistoryId = null;
const dropZone = $("drop-zone");
const analyzeBtn = $("analyze-btn");
const status = $("status");
const backBtn = $("back-btn");
const themeBtn = $("theme-toggle");
const explainPanel = $("explain-panel");
const explainTokens = $("explain-tokens");
const explainStatus = $("explain-status");

// Inline SVG icon from the sprite in popup.html.
const icon = (name) => `<svg class="i" aria-hidden="true"><use href="#i-${name}"/></svg>`;

// ---------- accepted files ----------
// .eml goes to /analyse; everything in ATTACHMENT_EXTS goes to
// /analyse_attachment.
const ATTACHMENT_EXTS = ["pdf", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "docx", "docm", "doc", "xlsx", "xlsm", "xls", "pptx", "pptm", "ppt",
                         // Archives, calendar invites, plain text
                         "zip", "rar", "7z", "ics", "txt"];
// Attachment flags meaning "could not look inside" (see gmail.js).
const CAUTION_FLAGS = ["encrypted_archive", "encrypted_document", "uninspectable_archive",
                       "disk_image_attachment", "disk_image_in_archive", "zip_bomb_suspected", "inner_files_not_extracted"];
const FILE_ACCEPT = [".eml", ...ATTACHMENT_EXTS.map((e) => "." + e)].join(",");
const fileExt = (name) => ((name || "").split(".").pop() || "").toLowerCase();

// ---------- state ----------
let activeTab = "file";          // "file" | "paste"
let selectedFile = null;
let pastedText = "";
let runId = 0;                   // bumped on each Analyze click: old fetches that finish after a new run are ignored
let explainData = null;          // resolved features or null
let explainError = null;         // string error message or null

// ---------- theme persistence ----------
const STORAGE = chrome?.storage?.local;

// Version in the footer, read from the manifest.
try {
    const v = chrome?.runtime?.getManifest?.().version;
    const el = document.getElementById("app-version");
    if (v && el) el.textContent = `v${v}`;
} catch { /* not in an extension context (tests) */ }
(async function initTheme() {
    let saved = null;
    try {
        if (STORAGE) {
            saved = (await new Promise((r) => STORAGE.get(["theme"], r)))?.theme;
        }
    } catch {}
    if (saved === "light" || saved === "dark") {
        document.documentElement.setAttribute("data-theme", saved);
    }
})();
// ---------- backend choice persistence ----------
async function loadBackendChoice() {
    try {
        if (!STORAGE) return;
        const s = await new Promise((r) => STORAGE.get(["backend", "backend_custom_url"], r));
        if (s.backend === "local" || s.backend === "cloud" || s.backend === "custom") {
            backendChoice = s.backend;
        }
        if (typeof s.backend_custom_url === "string") {
            backendCustomUrl = s.backend_custom_url;
        }
    } catch {}
}
loadBackendChoice();

themeBtn.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { STORAGE?.set({ theme: next }); } catch {}
});

// ---------- view switching ----------
function showView(name) {
    Object.entries(views).forEach(([k, el]) => {
        el.classList.toggle("view--active", k === name);
    });
}

// ---------- tab switching (File / Paste) ----------
document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
        const tab = btn.dataset.tab;
        if (tab === activeTab) return;
        activeTab = tab;
        document.querySelectorAll(".tab").forEach((b) =>
            b.classList.toggle("tab--active", b.dataset.tab === tab));
        document.querySelectorAll(".tab-panel").forEach((p) =>
            p.classList.toggle("tab-panel--active", p.dataset.panel === tab));
        updateAnalyzeEnabled();
        hideStatus();
    });
});

function updateAnalyzeEnabled() {
    if (activeTab === "file") {
        analyzeBtn.disabled = !selectedFile;
    } else {
        analyzeBtn.disabled = pastedText.trim().length < 20;
    }
}

// ---------- drop-zone interactions ----------
function setSelectedFile(file) {
    selectedFile = file;
    if (!file) {
        dropZone.classList.remove("drop-zone--filled");
        dropZone.innerHTML = `
            <input id="file-input" type="file" accept="${FILE_ACCEPT}" hidden />
            <div class="drop-zone__icon">${icon("upload")}</div>
            <div class="drop-zone__label">${t("drop_label_html")}</div>
            <div class="drop-zone__hint">${escapeHTML(t("drop_hint"))}</div>`;
        rewireFileInput();
        updateAnalyzeEnabled();
        return;
    }
    dropZone.classList.add("drop-zone--filled");
    dropZone.innerHTML = `
        <input id="file-input" type="file" accept="${FILE_ACCEPT}" hidden />
        <div class="drop-zone__icon">${icon("file")}</div>
        <div class="drop-zone__filename">${escapeHTML(file.name)}</div>
        <div class="drop-zone__hint">${escapeHTML(t("click_to_change"))}</div>`;
    rewireFileInput();
    updateAnalyzeEnabled();
    hideStatus();
}

// paste textarea wiring
const pasteInput = $("paste-input");
const pasteCounter = $("paste-counter");
const pasteClipboardBtn = $("paste-clipboard-btn");
pasteInput.addEventListener("input", () => {
    pastedText = pasteInput.value;
    pasteCounter.textContent = pastedText.length;
    updateAnalyzeEnabled();
    hideStatus();
});
pasteClipboardBtn.addEventListener("click", async () => {
    try {
        const txt = await navigator.clipboard.readText();
        if (!txt) {
            showStatus(t("clipboard_empty"));
            return;
        }
        pasteInput.value = txt;
        pastedText = txt;
        pasteCounter.textContent = txt.length;
        updateAnalyzeEnabled();
        hideStatus();
        pasteInput.focus();
    } catch (e) {
        showStatus(t("clipboard_error"));
    }
});

function rewireFileInput() {
    const newInput = $("file-input");
    newInput.addEventListener("change", (e) => {
        const f = e.target.files?.[0];
        if (f) setSelectedFile(f);
    });
}
rewireFileInput();

dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drop-zone--active");
});
dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drop-zone--active");
});
dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drop-zone--active");
    const f = e.dataTransfer.files?.[0];
    if (!f) return;
    const ext = fileExt(f.name);
    if (ext === "eml" || ATTACHMENT_EXTS.includes(ext)) {
        setSelectedFile(f);
    } else {
        showStatus(t("drop_wrong_type"));
    }
});

// ---------- status helpers ----------
function showStatus(msg, danger = true) {
    status.textContent = msg;
    status.hidden = false;
    status.style.color = danger ? "" : "var(--text-mute)";
}
function hideStatus() {
    status.hidden = true;
    status.textContent = "";
}

// ---------- file -> base64 ----------
function fileToB64(file) {
    return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result.split(",")[1]);
        r.onerror = reject;
        r.readAsDataURL(file);
    });
}

// ---------- /analyse ----------
analyzeBtn.addEventListener("click", async () => {
    hideStatus();
    showView("loading");

    // build payload depending on active tab. Attachments (see
    // ATTACHMENT_EXTS) go to /analyse_attachment; .eml stays on /analyse.
    let payload;
    let endpointPath = "/analyse";
    try {
        if (activeTab === "file") {
            if (!selectedFile) throw new Error(t("pick_first"));
            if (selectedFile.size > 10 * 1024 * 1024)
                throw new Error(t("file_too_large"));
            const ext = fileExt(selectedFile.name);
            const b64 = await fileToB64(selectedFile);
            if (ATTACHMENT_EXTS.includes(ext)) {
                endpointPath = "/analyse_attachment";
                payload = {
                    content_b64: b64,
                    filename:    selectedFile.name,
                    mime_type:   selectedFile.type || null,
                };
            } else {
                payload = { raw_email_b64: b64 };
            }
        } else {
            if (pastedText.trim().length < 20)
                throw new Error(t("paste_min"));
            payload = { raw_text: pastedText };
        }
    } catch (e) {
        showView("upload");
        showStatus(String(e.message || e));
        return;
    }

    // bump the run id so any in-flight /explain from a previous run is ignored
    const thisRun = ++runId;
    explainData = null;
    explainError = null;

    try {
        const resp = await fetch(`${getApiBase()}${endpointPath}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(apiErrorMessage(err, resp.status));
        }
        const data = await resp.json();
        if (thisRun !== runId) return;     // stale, user already moved on
        renderResult(data);
        showView("result");

        // Persist this scan in the local history via the shared module.
        try {
            const entry = {
                source:  payload.content_b64 ? "attachment"
                       : payload.raw_email_b64 ? "file" : "paste",
                subject: (selectedFile?.name || "").slice(0, 120),
                sender:  data.sender_domain || "",
                verdict: data.verdict,
                score:   Number(data.fused_score) || 0,
                agents: {
                    text:     Number(data.agents?.text?.phishing_probability)     || 0,
                    url:      Number(data.agents?.url?.phishing_probability)      || 0,
                    metadata: Number(data.agents?.metadata?.phishing_probability) || 0,
                },
                trusted: !!data.trusted_sender,
                lang:    data.language?.code,
            };
            currentHistoryId = await window.PhishLensHistory?.saveScan(entry);
        } catch (histErr) {
            console.warn("[PhishLens] failed to persist history entry:", histErr);
            currentHistoryId = null;
        }
        // Pasted text is offered for the report; for a file the person
        // pastes the part they want to send.
        renderResultFeedback(data, currentHistoryId, payload.raw_text || "",
            payload.content_b64 ? "attachment" : payload.raw_email_b64 ? "file" : "paste");

        // fire LIME explanation in the background: tagged with the run id.
        // Skip LIME for attachment payloads: /explain only accepts
        // raw_text / raw_email_b64, and the DistilBERT explanation isn't
        // that meaningful on extracted PDF/HTML text anyway.
        if (payload.raw_text || payload.raw_email_b64) {
            fetchExplain(payload, thisRun);
        } else {
            // Hide the LIME panel entirely for attachments
            explainData = null;
            explainError = null;
        }
    } catch (e) {
        if (thisRun !== runId) return;     // user already moved on, swallow
        showView("upload");
        showStatus(
            String(e?.message || e).startsWith("Failed to fetch")
                ? t("unreachable")
                : String(e.message || e)
        );
    }
});

// ---------- render result ----------
function renderResult(data) {
    const isPhishing = data.verdict === "phishing";
    const isAttachment = !!data.attachment;

    // Hide the LIME "Why?" panel entirely for attachment scans: /explain
    // doesn't accept attachment payloads and DistilBERT explanations on
    // extracted PDF/HTML text aren't very meaningful anyway.
    if (explainPanel) explainPanel.hidden = isAttachment;

    // verdict card
    const card = $("verdict-card");
    card.classList.toggle("verdict-card--danger", isPhishing);
    $("verdict-icon").innerHTML = icon(isPhishing ? "alert" : "shield-check");
    const flags = data.attachment?.notable_features || [];
    const caution = isAttachment && !isPhishing && flags.some((f) => CAUTION_FLAGS.includes(f));
    renderArchiveFiles(data.attachment, isPhishing);
    $("verdict-label").textContent = isPhishing
        ? t(isAttachment ? "verdict_file_phishing" : "verdict_phishing")
        : caution ? t("verdict_file_caution") : t(isAttachment ? "verdict_file_safe" : "verdict_safe");

    // Verified-sender pill: three tiers:
    //   1. Trusted allowlist (static list, highest trust: kept for legacy)
    //   2. DKIM-aligned (cryptographic proof the sender is who they claim)
    //   3. Neither → hidden
    const trustedEl = $("verdict-trusted");
    const cryptoVerified   = !!data.sender_auth?.cryptographically_verified;
    const gmailSoftVerified = !!data.sender_auth?.gmail_inbox_soft_verified;
    if (data.trusted_sender) {
        trustedEl.hidden = false;
        trustedEl.textContent = t("badge_trusted");
        trustedEl.title = t("trusted_title_popup", { domain: data.sender_domain || "" });
    } else if (cryptoVerified) {
        trustedEl.hidden = false;
        trustedEl.textContent = t("badge_dkim");
        trustedEl.title = t("dkim_title_popup", { domain: data.sender_domain || "", spf: data.sender_auth.spf,
                                                  dkim: data.sender_auth.dkim, dmarc: data.sender_auth.dmarc });
    } else if (gmailSoftVerified) {
        trustedEl.hidden = false;
        trustedEl.textContent = t("badge_gmail");
        trustedEl.title = t("badge_gmail_title");
    } else {
        trustedEl.hidden = true;
    }

    const flagText = flags.length ? t("found_flags", { flags: flags.map(flagLabel).join(", ") }) : "";
    $("verdict-sub").textContent = isPhishing
        ? t("sub_phishing") + flagText
        : caution
        ? t("sub_caution") + flagText
        : data.forwarded?.detected
        ? t("sub_forwarded")
        : data.shared_links?.count
        ? t("sub_shared", { services: (data.shared_links.services || []).join(", ") })
        : (data.trusted_sender
            ? t("sub_trusted")
            : cryptoVerified
                ? t("sub_crypto")
                : t("verdict_safe_sub"));

    // helper to fill an agent block
    const fillAgent = (key, scoreEl, barEl, hintEl, hintCopy) => {
        const a = data.agents[key];
        const pct = Math.round(a.phishing_probability * 100);
        scoreEl.textContent = `${pct}%`;
        barEl.style.width = `${pct}%`;
        const flagged = a.verdict === "Phishing";
        const agentBlock = barEl.closest(".agent");
        agentBlock.dataset.flagged = flagged ? "phishing" : "safe";
        hintEl.textContent = hintCopy(a.phishing_probability);
    };

    fillAgent(
        "text", $("text-score"), $("text-bar"), $("text-hint"),
        (p) => t(p >= 0.7 ? "text_high" : p >= 0.4 ? "text_mid" : "text_low")
    );
    fillAgent(
        "url", $("url-score"), $("url-bar"), $("url-hint"),
        (p) => t(p >= 0.7 ? "url_high" : p >= 0.4 ? "url_mid" : "url_low")
    );
    fillAgent(
        "metadata", $("meta-score"), $("meta-bar"), $("meta-hint"),
        (p) => t(p >= 0.7 ? "meta_high" : p >= 0.4 ? "meta_mid" : "meta_low")
    );
    if (data.agents.metadata?.checked === false) {
        $("meta-score").textContent = "—";
        $("meta-bar").style.width = "0%";
        $("meta-bar").closest(".agent").dataset.flagged = "safe";
        $("meta-hint").textContent = t("meta_not_checked");
    }

    // Reputation & auth badges
    renderUrlBadges(data.url_reputation);
    renderMetaBadges(data.sender_auth);

    // collapse explain by default
    explainPanel.removeAttribute("open");
    explainTokens.innerHTML = "";
    explainStatus.hidden = true;
}

// ---------- sender and threat-intel badges ----------
// Human-readable labels for the raw threat-intel enum values.
const _THREAT_KEY = {
    "MALWARE":                          "threat_malware",
    "SOCIAL_ENGINEERING":               "threat_phishing",
    "UNWANTED_SOFTWARE":                "threat_unwanted",
    "POTENTIALLY_HARMFUL_APPLICATION":  "threat_harmful_app",
    "SPAM":                             "threat_spam",
    "BOTNET_CC":                        "threat_botnet",
    "SUSPICIOUS":                       "threat_suspicious",
    "PHISHING":                         "threat_phishing",
};
const _SOURCE_LABEL = {
    "google_safe_browsing":  "Google Safe Browsing",
    "phishtank":             "PhishTank",
    "urlhaus":               "URLhaus",
    "spamhaus_dbl":          "Spamhaus DBL",
};

// Escape user-visible strings before inlining them into a title/tooltip.
function _sanitizeTitle(s) {
    return String(s || "").replace(/["\n\r]/g, " ").slice(0, 240);
}

function _mkBadge(text, kind, title) {
    const el = document.createElement("span");
    el.className = `badge badge--${kind}`;
    el.textContent = text;
    if (title) el.title = _sanitizeTitle(title);
    return el;
}

// Inside an archive, name the files that explain the verdict,
// then list every file (folded). Built with DOM nodes: file names come
// from the archive and are never inserted as HTML.
function renderArchiveFiles(att, isPhishing) {
    const box = $("archive-files");
    if (!box) return;
    box.replaceChildren();
    box.hidden = true;
    if (!att || att.kind !== "archive") return;
    const el = (tag, cls, text) => {
        const n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined) n.textContent = text;
        return n;
    };
    const risky = Array.isArray(att.suspicious_files) ? att.suspicious_files : [];
    const entries = Array.isArray(att.entries) ? att.entries : [];
    if (risky.length) {
        const block = el("div", "archive-files__risky archive-files__risky--" + (isPhishing ? "bad" : "warn"));
        block.append(el("div", "archive-files__title", isPhishing ? t("att_do_not_open") : t("att_check_before")));
        const ul = el("ul");
        risky.forEach((f) => {
            const li = el("li");
            const name = el("span", "archive-files__name", f.name);
            name.title = f.name;
            li.append(name, el("span", "archive-files__why", (f.reasons || []).map(reasonLabel).join(", ")));
            ul.append(li);
        });
        block.append(ul);
        box.append(block);
    }
    if (entries.length) {
        const det = el("details", "archive-files__all");
        det.append(el("summary", "", t("att_files_list", { count: att.entry_count || entries.length })));
        const ul = el("ul");
        entries.forEach((n) => {
            const li = el("li");
            const name = el("span", "archive-files__name", n);
            name.title = n;
            li.append(name);
            ul.append(li);
        });
        if (att.entry_count > entries.length) ul.append(el("li", "archive-files__more", t("att_and_more", { count: att.entry_count - entries.length })));
        det.append(ul);
        box.append(det);
    }
    box.hidden = !box.childElementCount;
}

function renderUrlBadges(rep) {
    const host = $("url-badges");
    host.innerHTML = "";
    if (!rep || !rep.checked) { host.hidden = true; return; }
    if (rep.malicious_count === 0) {
        host.appendChild(_mkBadge(tn("links_checked", rep.checked), "good", t("links_clean_title")));
    } else {
        // Per-source badges: one per intel source that fired
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL[src] || src;
            host.appendChild(_mkBadge(t("chip_flagged_by", { source: label }), "bad",
                                      t("chip_flagged_title", { source: label, count: rep.malicious_count })));
        }
        // Threat-type badges: collapse enum values into words
        for (const tt of rep.threat_types || []) {
            const label = _THREAT_KEY[tt] ? t(_THREAT_KEY[tt]) : tt.toLowerCase();
            host.appendChild(_mkBadge(label, "bad", t("threat_type_title", { type: tt })));
        }
    }
    host.hidden = false;
}

function renderMetaBadges(auth) {
    const host = $("meta-badges");
    host.innerHTML = "";
    if (!auth) { host.hidden = true; return; }

    const badges = [];
    if (auth.impersonation?.brand) {
        const brand = String(auth.impersonation.brand).replace(/(^|\s)\S/g, (c) => c.toUpperCase());
        const vars = { brand, domain: auth.impersonation.domain || "?" };
        badges.push(_mkBadge(t("chip_impersonation", vars), "bad", t("chip_impersonation_title", vars)));
    }
    if (auth.cryptographically_verified) {
        badges.push(_mkBadge(t("dkim_aligned"), "good", t("dkim_aligned_title")));
    }
    const results = {
        SPF:   auth.spf,
        DKIM:  auth.dkim,
        DMARC: auth.dmarc,
    };
    for (const [name, verdict] of Object.entries(results)) {
        if (verdict === "pass") {
            badges.push(_mkBadge(t("auth_pass", { name }), "good", t("auth_pass_title", { name })));
        } else if (verdict === "fail") {
            badges.push(_mkBadge(t("auth_fail", { name }), "bad", t("auth_fail_title", { name })));
        } else if (verdict === "softfail") {
            badges.push(_mkBadge(t("auth_softfail", { name }), "warn", t("auth_softfail_title", { name })));
        }
        // "none" / "neutral" / "temperror" → no badge (silent)
    }
    if (auth.spamhaus_dbl_listed) {
        badges.push(_mkBadge(t("chip_spamhaus"), "bad", t("chip_spamhaus_title")));
    }
    // Explicit signal that the message didn't ship with auth headers at all
    if ((auth.reasons || []).includes("no_auth_header") && badges.length === 0) {
        badges.push(_mkBadge(t("no_auth_header"), "warn", t("no_auth_header_title")));
    }

    if (badges.length === 0) { host.hidden = true; return; }
    for (const b of badges) host.appendChild(b);
    host.hidden = false;
}

// ---------- LIME explain (background pre-fire) ----------
async function fetchExplain(payload, thisRun) {
    const base = getApiBase();
    // Client-side cache: LIME output only depends on {backend, text},
    // both stable enough for a 30-day TTL. Re-opening the same email
    // returns instantly instead of eating 8-15 s of CPU on the server.
    try {
        const cached = await window.PhishLensLimeCache?.get(base, payload);
        if (cached && thisRun === runId) {
            explainData = cached.features;
            if (explainPanel.open) renderExplain(explainData);
            // Skip the network call entirely: history token attach below
            // still runs so we don't lose the analytics signal.
            if (currentHistoryId && Array.isArray(explainData)) {
                const tokens = explainData.slice(0, 5).map((f) => ({
                    token:  f.token  || (Array.isArray(f) ? f[0] : ""),
                    weight: f.weight ?? (Array.isArray(f) ? f[1] : 0),
                }));
                try { await window.PhishLensHistory?.attachTokens(currentHistoryId, tokens); }
                catch {}
            }
            return;
        }
    } catch {}

    try {
        const resp = await fetch(`${base}/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (thisRun !== runId) return;        // stale: discard
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(apiErrorMessage(err, resp.status));
        }
        const data = await resp.json();
        if (thisRun !== runId) return;        // stale: discard
        explainData = data.features || [];
        if (explainPanel.open) renderExplain(explainData);

        // Persist to the LIME cache (fire-and-forget).
        try { window.PhishLensLimeCache?.put(base, payload, explainData); }
        catch {}

        // Attach top LIME tokens to the history entry so the analytics
        // view can aggregate them into the "top phishing tokens" chart.
        if (currentHistoryId && Array.isArray(explainData)) {
            const tokens = explainData.slice(0, 5).map((f) => ({
                token:  f.token  || (Array.isArray(f) ? f[0] : ""),
                weight: f.weight ?? (Array.isArray(f) ? f[1] : 0),
            }));
            try { await window.PhishLensHistory?.attachTokens(currentHistoryId, tokens); }
            catch {}
        }
    } catch (e) {
        if (thisRun !== runId) return;        // stale: discard
        explainError = e?.message || String(e);
        if (explainPanel.open) showExplainError();
    }
}

explainPanel.addEventListener("toggle", () => {
    if (!explainPanel.open) return;
    if (explainData) { renderExplain(explainData); return; }
    if (explainError) { showExplainError(); return; }
    // not done yet: show waiting state
    explainTokens.innerHTML =
        `<span class="explain__status">${escapeHTML(t("computing_lime"))}</span>`;
});

function showExplainError() {
    explainTokens.innerHTML = "";
    explainStatus.hidden = false;
    explainStatus.textContent = t("explain_unavailable", { error: explainError });
}

function renderExplain(features) {
    if (!features.length) {
        explainTokens.innerHTML = "";
        explainStatus.hidden = false;
        explainStatus.textContent = t("no_tokens_model");
        return;
    }
    // LIME weights are tiny (often < 0.01), so printing them showed "0.00".
    // Colour strength now reflects each word's weight relative to the
    // strongest one; the exact figure stays in the tooltip.
    const shown = features.filter((f) => String(f.token || "").length > 1 && !/^\d+$/.test(f.token));
    const max = Math.max(...shown.map((f) => Math.abs(Number(f.weight) || 0))) || 1;
    explainTokens.innerHTML = shown.map((f) => {
        const w = Number(f.weight) || 0;
        const rel = Math.abs(w) / max;
        const cls = f.supports === "phishing" ? "token--phishing" : "token--safe";
        return `<span class="token ${cls}" style="--a:${(0.10 + rel * 0.35).toFixed(2)}"
                      title="${escapeHTML(t("token_title_popup", { side: f.supports === "phishing" ? t("side_phishing") : t("side_safe"), pct: Math.round(rel * 100) }))}">${escapeHTML(f.token)}</span>`;
    }).join("");
    explainStatus.hidden = true;
}

// ---------- back button ----------
backBtn.addEventListener("click", () => {
    runId++;                              // invalidate any pending fetch
    selectedFile = null;
    pastedText = "";
    pasteInput.value = "";
    pasteCounter.textContent = "0";
    explainData = null;
    explainError = null;
    setSelectedFile(null);
    showView("upload");
});

// ---------- settings view ----------
const settingsBtn = $("settings-btn");
const settingsBack = $("settings-back");
const customUrlInput = $("custom-url");
const testConnBtn = $("test-conn-btn");
const connStatus = $("conn-status");
let previousView = "upload";

function renderSettings() {
    const radios = document.querySelectorAll('input[name="backend"]');
    radios.forEach((r) => { r.checked = (r.value === backendChoice); });
    customUrlInput.value = backendCustomUrl;
    customUrlInput.disabled = backendChoice !== "custom";
    connStatus.hidden = true;
    connStatus.className = "conn-status";
    connStatus.textContent = "";
    updateCustomUrlWarn();
}

settingsBtn.addEventListener("click", () => {
    previousView = Object.entries(views).find(([k, el]) =>
        el.classList.contains("view--active"))?.[0] || "upload";
    renderSettings();
    showView("settings");
});

settingsBack.addEventListener("click", () => {
    showView(previousView === "settings" ? "upload" : previousView);
});

document.querySelectorAll('input[name="backend"]').forEach((r) => {
    r.addEventListener("change", () => {
        if (!r.checked) return;
        backendChoice = r.value;
        customUrlInput.disabled = backendChoice !== "custom";
        STORAGE?.set({ backend: backendChoice });
        if (backendChoice === "custom" && !customUrlInput.value) {
            customUrlInput.focus();
        }
        updateCustomUrlWarn();
    });
});

// Gmail options (read by content_scripts/gmail.js).
const optFullHeaders = $("opt-full-headers");
const optAutoScan = $("opt-auto-scan");
STORAGE?.get(["opt_full_headers", "opt_auto_scan"], (s) => {
    optFullHeaders.checked = s.opt_full_headers !== false;
    optAutoScan.checked = s.opt_auto_scan === true;
});
optFullHeaders.addEventListener("change", () => STORAGE?.set({ opt_full_headers: optFullHeaders.checked }));
optAutoScan.addEventListener("change", () => STORAGE?.set({ opt_auto_scan: optAutoScan.checked }));

// An http:// URL to a remote server would send emails in clear
// text. Local and private-network addresses are fine (nothing leaves the
// computer or the home network).
const customUrlWarn = $("custom-url-warn");
function isPlainRemoteUrl(value) {
    let u;
    try { u = new URL(value); } catch { return false; }
    if (u.protocol !== "http:") return false;
    const h = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h === "::1") return false;
    const m = h.match(/^(\d+)\.(\d+)\.\d+\.\d+$/);
    if (m) {
        const a = Number(m[1]), b = Number(m[2]);
        if (a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)) return false;
    }
    return true;
}
function updateCustomUrlWarn() {
    customUrlWarn.hidden = !(backendChoice === "custom" && isPlainRemoteUrl(customUrlInput.value.trim()));
}

customUrlInput.addEventListener("input", () => {
    backendCustomUrl = customUrlInput.value.trim();
    STORAGE?.set({ backend_custom_url: backendCustomUrl });
    updateCustomUrlWarn();
});

// ---------- insights view (history + analytics) ----------
const insightsBtn      = $("insights-btn");
const insightsBack     = $("insights-back");
const insightsEmpty    = $("insights-empty");
const insightsStats    = $("insights-stats");
const ratioBlock       = $("ratio-block");
const topTokensBlock   = $("top-tokens-block");
const dailyChart       = $("daily-chart");
const topTokensEl      = $("top-tokens");
const historyList      = $("history-list");
const exportCsvBtn     = $("export-csv-btn");
const exportJsonBtn    = $("export-json-btn");
const clearHistoryBtn  = $("clear-history-btn");

async function renderInsights() {
    const stats = await window.PhishLensHistory?.getStats();
    const list  = await window.PhishLensHistory?.getHistory();
    if (!stats || stats.total === 0) {
        insightsEmpty.hidden = false;
        insightsStats.style.display = "none";
        ratioBlock.style.display = "none";
        topTokensBlock.style.display = "none";
        document.querySelector(".chart-block:not(#top-tokens-block)").style.display = "none";
        historyList.innerHTML = "";
        return;
    }
    insightsEmpty.hidden = true;
    insightsStats.style.display = "";
    ratioBlock.style.display = "";
    topTokensBlock.style.display = "";
    document.querySelector(".chart-block:not(#top-tokens-block)").style.display = "";

    // Stat cards
    $("stat-total").textContent = stats.total;
    $("stat-phishing-pct").textContent = `${stats.phishingPct}%`;
    $("stat-avg-score").textContent = stats.avgScore.toFixed(2);

    // Ratio bar
    $("ratio-safe-count").textContent = stats.safe;
    $("ratio-phishing-count").textContent = stats.phishing;
    $("ratio-safe-fill").style.width = `${stats.safePct}%`;
    $("ratio-phishing-fill").style.width = `${stats.phishingPct}%`;

    // Daily chart (30 columns, height proportional to total scans that day)
    const maxDaily = Math.max(1, ...stats.days.map((d) => d.phishing + d.safe));
    dailyChart.innerHTML = stats.days.map((d) => {
        const tot = d.phishing + d.safe;
        // Bar height in pixels (the chart is 84px high, 18px go to the
        // date label): percentages need a sized parent and collapsed.
        const h = tot ? Math.max(3, Math.round((tot / maxDaily) * 62)) : 0;
        const phishH = tot ? Math.round((d.phishing / tot) * 100) : 0;
        const safeH  = 100 - phishH;
        const short = d.date.slice(5);   // MM-DD
        return `
          <div class="dc-col" title="${escapeHTML(t("chart_day_title", { date: d.date, total: tot, phishing: d.phishing, safe: d.safe }))}">
            <div class="dc-stack" style="height:${h}px">
              <span class="dc-phishing" style="height:${phishH}%"></span>
              <span class="dc-safe"     style="height:${safeH}%"></span>
            </div>
            <div class="dc-label">${short}</div>
          </div>`;
    }).join("");

    // Top phishing tokens
    if (stats.topTokens.length === 0) {
        topTokensEl.innerHTML =
            `<div class="empty-hint">${escapeHTML(t("no_top_tokens"))}</div>`;
    } else {
        const maxW = Math.max(...stats.topTokens.map((tok) => tok.weight));
        topTokensEl.innerHTML = stats.topTokens.map((tok) => {
            const pct = Math.round((tok.weight / maxW) * 100);
            return `
              <div class="token-row">
                <span class="token-row__label">${escapeHTML(tok.token)}</span>
                <span class="token-row__bar"><span style="width:${pct}%"></span></span>
              </div>`;
        }).join("");
    }

    // Live evaluation, from the scans the user reviewed below.
    const live = stats.live || { reviewed: 0 };
    const pctOf = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
    $("live-eval").innerHTML = live.reviewed
        ? `<div class="live-eval__grid">
             <div><strong>${live.reviewed}</strong><span>${escapeHTML(t("live_reviewed"))}</span></div>
             <div><strong>${pctOf(live.accuracy)}</strong><span>${escapeHTML(t("live_accuracy_label"))}</span></div>
             <div><strong>${live.fp}</strong><span>${escapeHTML(t("live_fp"))}</span></div>
             <div><strong>${live.fn}</strong><span>${escapeHTML(t("live_fn"))}</span></div>
           </div>
           <div class="empty-hint">${escapeHTML(t("live_detail", { precision: pctOf(live.precision), recall: pctOf(live.recall), fpr: pctOf(live.falsePositiveRate) }))}</div>`
        : `<div class="empty-hint">${escapeHTML(t("live_empty"))}</div>`;

    // Recent history: last 20
    historyList.innerHTML = list.slice(0, 20).map((e) => {
        const dot = icon(e.verdict === "phishing" ? "alert" : "shield-check");
        const when = timeAgo(e.ts);
        const subj = e.subject || t("no_subject");
        const srcKey = "src_" + String(e.source || "").replace(/-/g, "_");
        const src = I18N.has(srcKey) ? t(srcKey) : e.source;
        return `
          <div class="history-item" data-verdict="${e.verdict}" data-id="${e.id}">
            <div class="history-item__dot">${dot}</div>
            <div class="history-item__main">
              <div class="history-item__subject">${escapeHTML(subj)}</div>
              <div class="history-item__meta">
                <span>${escapeHTML(src)}</span>
                <span>·</span>
                <span>${when}</span>
                ${e.sender ? `<span>·</span><span>${escapeHTML(e.sender)}</span>` : ""}
              </div>
            </div>
            <div class="history-item__score">${Math.round((e.score || 0) * 100)}%</div>
            <div class="history-item__review" role="group" aria-label="${escapeHTML(t("review_group"))}">
              <button type="button" class="review-btn${e.label === "correct" ? " review-btn--on" : ""}" data-label="correct" title="${escapeHTML(t("review_right_title"))}">${escapeHTML(t("review_right"))}</button>
              <button type="button" class="review-btn review-btn--wrong${e.label === "wrong" ? " review-btn--on" : ""}" data-label="wrong" title="${escapeHTML(t("review_wrong_title"))}">${escapeHTML(t("review_wrong"))}</button>
              ${e.label === "wrong" && !e.reported
                ? `<button type="button" class="review-btn review-report" title="${escapeHTML(t("review_report_title"))}">${escapeHTML(t("review_report"))}</button>`
                : e.reported ? `<span class="review-sent">${escapeHTML(t("review_reported"))}</span>` : ""}
            </div>
          </div>`;
    }).join("");
    historyList.querySelectorAll(".review-report").forEach((b) => {
        b.addEventListener("click", async () => {
            const item = b.closest(".history-item");
            const entry = list.find((x) => x.id === item?.dataset.id);
            if (!entry || item.querySelector(".plr-report")) return;
            const text = (await window.PhishLensHistory.getDraft(entry.id)) || "";
            item.append(window.PhishLensReport.reportPanel({
                verdict: entry.verdict, text, redact: (x) => window.PhishLensRedact.redact(x),
                send: (kind, txt) => sendReport(kind, txt, entryAsResult(entry), entry),
                onSent: async (_k, reference) => {
                    await window.PhishLensHistory.updateScan(entry.id, { reported: reference });
                },
            }));
        });
    });
    renderShareStats(list);
    historyList.querySelectorAll(".review-btn[data-label]").forEach((b) => {
        b.addEventListener("click", async () => {
            const id = b.closest(".history-item")?.dataset.id;
            const on = b.classList.contains("review-btn--on");
            await window.PhishLensHistory?.setLabel(id, on ? null : b.dataset.label);
            renderInsights();
        });
    });
}


// ---------- language and reports ----------
const { PhishLensReport: REPORT, PhishLensRedact: REDACT } = window;

function sendReport(kind, text, data, entry = {}) {
    return chrome.runtime.sendMessage({
        type: "phishlens.feedback",
        payload: {
            kind, text,
            verdict: data.verdict,
            fused_score: Number(data.fused_score) || 0,
            agents: {
                text: Number(data.agents?.text?.phishing_probability) || 0,
                url: Number(data.agents?.url?.phishing_probability) || 0,
                metadata: Number(data.agents?.metadata?.phishing_probability) || 0,
            },
            trust_path: data.trust_path || null,
            source: entry.source || "paste",
            lang: data.language?.code || entry.lang || null,
            lang_user: entry.lang_user || null,
            ui_lang: I18N.language(),
            version: chrome.runtime.getManifest?.().version || null,
        },
    });
}

// A history entry in the shape of a /analyse answer, for sendReport.
function entryAsResult(e) {
    return {
        verdict: e.verdict, fused_score: e.score, language: { code: e.lang },
        agents: { text: { phishing_probability: e.agents?.text }, url: { phishing_probability: e.agents?.url },
                  metadata: { phishing_probability: e.agents?.metadata } },
    };
}

function renderResultFeedback(data, historyId, pasted, source = "paste") {
    const host = $("result-feedback");
    host.replaceChildren();
    const box = document.createElement("div");
    box.className = "plr-box";
    const entry = { source, lang_user: null };
    box.append(REPORT.languageLine({
        code: data.language?.code,
        onChoice: (code) => {
            entry.lang_user = code;
            if (historyId) window.PhishLensHistory?.updateScan(historyId, { lang_user: code });
        },
    }));
    box.append(REPORT.reportButton({
        verdict: data.verdict,
        getText: async () => (pasted ? REDACT.redact(pasted) : ""),
        redact: (x) => REDACT.redact(x),
        send: (kind, text) => sendReport(kind, text, data, entry),
        onSent: (_k, reference) => historyId &&
            window.PhishLensHistory?.updateScan(historyId, { label: "wrong", reported: reference }),
    }));
    host.append(box);
}

// "Share my statistics": reviewed history without subject, sender or text.
function renderShareStats(list) {
    const host = $("share-stats");
    if (!host) return;
    host.replaceChildren();
    if (!list.length) return;
    const rows = window.PhishLensHistory.statsRows(list);
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn btn--ghost";
    btn.textContent = t("share_stats");
    btn.addEventListener("click", () => {
        if (host.querySelector(".plr-report")) return;
        const panel = document.createElement("div");
        panel.className = "plr-report";
        const intro = document.createElement("p");
        intro.className = "plr-report__intro";
        intro.textContent = t("share_stats_intro", { count: rows.length });
        const sample = document.createElement("textarea");
        sample.className = "plr-report__text";
        sample.readOnly = true;
        sample.rows = 6;
        sample.value = JSON.stringify(rows.slice(0, 3), null, 1);
        sample.setAttribute("aria-label", t("fb_report_preview"));
        const status = document.createElement("p");
        status.className = "plr-report__status";
        status.setAttribute("role", "status");
        const send = document.createElement("button");
        send.type = "button";
        send.className = "plr-btn plr-btn--strong";
        send.textContent = t("share_stats_send");
        const cancel = document.createElement("button");
        cancel.type = "button";
        cancel.className = "plr-btn";
        cancel.textContent = t("fb_cancel");
        cancel.addEventListener("click", () => panel.remove());
        send.addEventListener("click", async () => {
            send.disabled = true;
            status.textContent = t("fb_sending");
            const r = await chrome.runtime.sendMessage({
                type: "phishlens.feedback",
                payload: { kind: "stats", rows, ui_lang: I18N.language(), version: chrome.runtime.getManifest?.().version || null },
            }).catch((e) => ({ ok: false, error: String(e?.message || e) }));
            if (r?.ok) panel.replaceChildren(REPORT.sentMessage(r.reference));
            else { status.textContent = t("fb_failed", { error: r?.error || t("unknown_error") }); send.disabled = false; }
        });
        const actions = document.createElement("div");
        actions.className = "plr-report__actions";
        actions.append(send, cancel);
        panel.append(intro, sample, actions, status);
        host.append(panel);
    });
    host.append(btn);
}


function timeAgo(ts) {
    const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (s < 60)      return t("ago_s", { n: s });
    const m = Math.floor(s / 60);
    if (m < 60)      return t("ago_m", { n: m });
    const h = Math.floor(m / 60);
    if (h < 24)      return t("ago_h", { n: h });
    const d = Math.floor(h / 24);
    if (d < 30)      return t("ago_d", { n: d });
    return new Date(ts).toISOString().slice(0, 10);
}

insightsBtn.addEventListener("click", async () => {
    previousView = Object.entries(views).find(([k, el]) =>
        el.classList.contains("view--active"))?.[0] || "upload";
    await renderInsights();
    showView("insights");
});

insightsBack.addEventListener("click", () => {
    showView(previousView === "insights" ? "upload" : previousView);
});

// Export handlers: trigger a client-side download using a Blob URL.
function downloadBlob(name, mime, text) {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

exportCsvBtn.addEventListener("click", async () => {
    const csv = await window.PhishLensHistory?.exportCSV();
    if (!csv) return;
    downloadBlob(`phishlens-history-${new Date().toISOString().slice(0, 10)}.csv`,
                 "text/csv;charset=utf-8", csv);
});

exportJsonBtn.addEventListener("click", async () => {
    const json = await window.PhishLensHistory?.exportJSON();
    if (!json) return;
    downloadBlob(`phishlens-history-${new Date().toISOString().slice(0, 10)}.json`,
                 "application/json", json);
});

clearHistoryBtn.addEventListener("click", async () => {
    if (!confirm(t("confirm_clear"))) return;
    await window.PhishLensHistory?.clearHistory();
    await renderInsights();
});

// Click on a history row → delete on shift-click, otherwise ignore for now.
// (Room to open a full detail view in a later version.)
historyList.addEventListener("click", async (ev) => {
    const row = ev.target.closest(".history-item");
    if (!row) return;
    if (ev.shiftKey) {
        const id = row.dataset.id;
        if (id && confirm(t("confirm_remove"))) {
            await window.PhishLensHistory?.deleteScan(id);
            await renderInsights();
        }
    }
});

testConnBtn.addEventListener("click", async () => {
    connStatus.hidden = false;
    connStatus.className = "conn-status conn-status--info";
    connStatus.textContent = t("testing");
    try {
        const url = getApiBase();
        if (!url || !/^https?:\/\//.test(url)) {
            throw new Error(t("url_scheme"));
        }
        // Hit /health (not /) because / now serves the landing HTML
        // through Caddy on the PhishLens Cloud backend.
        const resp = await fetch(`${url}/health`, { method: "GET" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json().catch(() => null);
        connStatus.className = "conn-status conn-status--ok";
        // Servers before 1.15.5 report neither their version nor the model.
        connStatus.textContent = data?.version
            ? t("connected", {
                version: data.version,
                model: data.text_model?.name || data.text_model?.source || t("unknown"),
            })
            : t("connected_old");
    } catch (e) {
        connStatus.className = "conn-status conn-status--err";
        const msg = String(e?.message || e);
        connStatus.textContent = msg.startsWith("Failed to fetch")
            ? t("server_unreachable")
            : msg;
    }
});

// ---------- util ----------

// ---------- language ----------
// The static texts carry data-i18n attributes; the dynamic ones are built
// with t() each time they are shown, so a language change re-renders them.
const langSelect = $("ui-lang");
function fillLanguageMenu(choice) {
    langSelect.replaceChildren();
    const auto = document.createElement("option");
    auto.value = "auto";
    auto.textContent = t("language_auto");
    langSelect.append(auto);
    for (const [code, name] of Object.entries(I18N.LANGUAGES)) {
        const opt = document.createElement("option");
        opt.value = code;
        opt.textContent = name;
        langSelect.append(opt);
    }
    langSelect.value = choice || "auto";
}
function applyLanguage() {
    document.documentElement.lang = I18N.language();
    I18N.applyTo(document);
    fillLanguageMenu(langSelect.value);
}
langSelect.addEventListener("change", () => {
    STORAGE?.set({ [I18N.STORAGE_KEY]: langSelect.value });
    I18N.setLanguage(langSelect.value);
});
I18N.onChange(() => {
    applyLanguage();
    if (views.insights.classList.contains("view--active")) renderInsights();
});
I18N.init().then(() => {
    STORAGE?.get([I18N.STORAGE_KEY], (s) => fillLanguageMenu(s?.[I18N.STORAGE_KEY]));
    applyLanguage();
});

// boot
showView("upload");
