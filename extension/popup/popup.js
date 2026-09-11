// =====================================================================
// PhishLens popup logic — vanilla JS, no build step.
// =====================================================================

// Backend choices (persisted in chrome.storage under "backend").
// "local"  -> http://127.0.0.1:8000                     (Docker on user's Mac)
// "cloud"  -> http://130.61.146.213    (Oracle Cloud)
// "custom" -> whatever URL the user types in the settings view
const BACKEND_PRESETS = {
    local:  "http://127.0.0.1:8000",
    cloud:  "http://130.61.146.213",
};
const DEFAULT_BACKEND = "local";

let backendChoice = DEFAULT_BACKEND;     // "local" | "cloud" | "custom"
let backendCustomUrl = "";
function getApiBase() {
    if (backendChoice === "custom") return backendCustomUrl.replace(/\/$/, "");
    return BACKEND_PRESETS[backendChoice] || BACKEND_PRESETS.local;
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
const fileInput = $("file-input");
const analyzeBtn = $("analyze-btn");
const status = $("status");
const backBtn = $("back-btn");
const themeBtn = $("theme-toggle");
const explainPanel = $("explain-panel");
const explainTokens = $("explain-tokens");
const explainStatus = $("explain-status");

// ---------- state ----------
let activeTab = "file";          // "file" | "paste"
let selectedFile = null;
let pastedText = "";
let lastPayload = null;          // {raw_email_b64} or {raw_text} — for /explain
let runId = 0;                   // bumped on each Analyze click — old fetches that finish after a new run are ignored
let explainData = null;          // resolved features or null
let explainError = null;         // string error message or null

// ---------- theme persistence ----------
const STORAGE = chrome?.storage?.local;
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
            <input id="file-input" type="file" accept=".eml" hidden />
            <div class="drop-zone__icon">📧</div>
            <div class="drop-zone__label">Drag &amp; drop your <code>.eml</code> file</div>
            <div class="drop-zone__hint">or click to browse</div>`;
        rewireFileInput();
        updateAnalyzeEnabled();
        return;
    }
    dropZone.classList.add("drop-zone--filled");
    dropZone.innerHTML = `
        <input id="file-input" type="file" accept=".eml" hidden />
        <div class="drop-zone__icon">📨</div>
        <div class="drop-zone__filename">${escapeHTML(file.name)}</div>
        <div class="drop-zone__hint">Click to change file</div>`;
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
            showStatus("Clipboard is empty.");
            return;
        }
        pasteInput.value = txt;
        pastedText = txt;
        pasteCounter.textContent = txt.length;
        updateAnalyzeEnabled();
        hideStatus();
        pasteInput.focus();
    } catch (e) {
        showStatus("Could not read clipboard. Try Cmd+V.");
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
    if (f && f.name.toLowerCase().endsWith(".eml")) {
        setSelectedFile(f);
    } else {
        showStatus("Please drop a .eml file.");
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

    // build payload depending on active tab
    let payload;
    try {
        if (activeTab === "file") {
            if (!selectedFile) throw new Error("Pick a .eml file first.");
            payload = { raw_email_b64: await fileToB64(selectedFile) };
        } else {
            if (pastedText.trim().length < 20)
                throw new Error("Paste at least 20 characters of email body.");
            payload = { raw_text: pastedText };
        }
    } catch (e) {
        showView("upload");
        showStatus(`❌ ${e.message || e}`);
        return;
    }

    // bump the run id so any in-flight /explain from a previous run is ignored
    const thisRun = ++runId;
    lastPayload = payload;
    explainData = null;
    explainError = null;

    try {
        const resp = await fetch(`${getApiBase()}/analyse`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Server returned ${resp.status}`);
        }
        const data = await resp.json();
        if (thisRun !== runId) return;     // stale, user already moved on
        renderResult(data);
        showView("result");

        // Persist this scan in the local history via the shared module.
        try {
            const entry = {
                source:  (payload.raw_email_b64 ? "file" : "paste"),
                subject: (selectedFile?.name || "").slice(0, 120),
                sender:  data.sender_domain || "",
                verdict: data.verdict,
                score:   Number(data.agents?.text?.phishing_probability) || 0,
                agents: {
                    text:     Number(data.agents?.text?.phishing_probability)     || 0,
                    url:      Number(data.agents?.url?.phishing_probability)      || 0,
                    metadata: Number(data.agents?.metadata?.phishing_probability) || 0,
                },
                trusted: !!data.trusted_sender,
            };
            currentHistoryId = await window.PhishLensHistory?.saveScan(entry);
        } catch (histErr) {
            console.warn("[PhishLens] failed to persist history entry:", histErr);
            currentHistoryId = null;
        }

        // fire LIME explanation in the background — tagged with the run id
        fetchExplain(payload, thisRun);
    } catch (e) {
        if (thisRun !== runId) return;     // user already moved on, swallow
        showView("upload");
        showStatus(
            String(e?.message || e).startsWith("Failed to fetch")
                ? "❌ Could not reach the backend. Is uvicorn running on port 8000?"
                : `❌ ${e.message || e}`
        );
    }
});

// ---------- render result ----------
function renderResult(data) {
    const isPhishing = data.verdict === "phishing";

    // verdict card
    const card = $("verdict-card");
    card.classList.toggle("verdict-card--danger", isPhishing);
    $("verdict-icon").textContent = isPhishing ? "⚠️" : "✅";
    $("verdict-label").textContent = isPhishing
        ? "This email looks like phishing"
        : "This email looks safe";

    // Verified-sender pill — three tiers:
    //   1. Trusted allowlist (static list, highest trust — kept for legacy)
    //   2. DKIM-aligned (cryptographic proof the sender is who they claim)
    //   3. Neither → hidden
    const trustedEl = $("verdict-trusted");
    const cryptoVerified = !!data.sender_auth?.cryptographically_verified;
    if (data.trusted_sender) {
        trustedEl.hidden = false;
        trustedEl.textContent = "✓ Verified sender";
        trustedEl.title = `Sender domain in allowlist: ${data.sender_domain || ""}`;
    } else if (cryptoVerified) {
        trustedEl.hidden = false;
        trustedEl.textContent = "🛡 DKIM verified";
        trustedEl.title =
            `DKIM signature aligned with From: ${data.sender_domain || ""}\n` +
            `SPF=${data.sender_auth.spf} DKIM=${data.sender_auth.dkim} DMARC=${data.sender_auth.dmarc}`;
    } else {
        trustedEl.hidden = true;
    }

    $("verdict-sub").textContent = isPhishing
        ? "We recommend not clicking any links."
        : (data.trusted_sender
            ? "Sender domain is in the verified allowlist."
            : cryptoVerified
                ? "Sender identity confirmed by DKIM signature."
                : "Unlikely to be a phishing attempt.");

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
        (p) => p >= 0.7 ? "The message content reads like a scam."
             : p >= 0.4 ? "The message has some suspicious wording."
             : "The message itself reads normally."
    );
    fillAgent(
        "url", $("url-score"), $("url-bar"), $("url-hint"),
        (p) => p >= 0.7 ? "The links look dangerous."
             : p >= 0.4 ? "Some links look suspicious."
             : "No suspicious links found."
    );
    fillAgent(
        "metadata", $("meta-score"), $("meta-bar"), $("meta-hint"),
        (p) => p >= 0.7 ? "The sender's identity could not be verified."
             : p >= 0.4 ? "The sender's identity looks unusual."
             : "The sender appears legitimate."
    );

    // v1.6+ — reputation & auth badges
    renderUrlBadges(data.url_reputation);
    renderMetaBadges(data.sender_auth);

    // collapse explain by default
    explainPanel.removeAttribute("open");
    explainTokens.innerHTML = "";
    explainStatus.hidden = true;
}

// ---------- v1.6 badges ----------
// Human-readable labels for the raw threat-intel enum values.
const _THREAT_LABEL = {
    "MALWARE":                          "malware",
    "SOCIAL_ENGINEERING":               "phishing",
    "UNWANTED_SOFTWARE":                "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION":  "harmful app",
    "SPAM":                             "spam",
    "BOTNET_CC":                        "botnet C&C",
    "SUSPICIOUS":                       "suspicious",
    "PHISHING":                         "phishing",
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

function renderUrlBadges(rep) {
    const host = $("url-badges");
    host.innerHTML = "";
    if (!rep || !rep.checked) { host.hidden = true; return; }
    if (rep.malicious_count === 0) {
        host.appendChild(_mkBadge(`✓ ${rep.checked} link${rep.checked > 1 ? "s" : ""} checked`,
                                  "good",
                                  "URL reputation cascade returned clean"));
    } else {
        // Per-source badges — one per intel source that fired
        for (const src of rep.sources_hit || []) {
            const label = _SOURCE_LABEL[src] || src;
            host.appendChild(_mkBadge(`🔴 ${label}`, "bad",
                                      `${label} flagged ${rep.malicious_count} URL(s)`));
        }
        // Threat-type badges — collapse enum values into words
        for (const tt of rep.threat_types || []) {
            const label = _THREAT_LABEL[tt] || tt.toLowerCase();
            host.appendChild(_mkBadge(label, "bad", `Threat type reported: ${tt}`));
        }
    }
    host.hidden = false;
}

function renderMetaBadges(auth) {
    const host = $("meta-badges");
    host.innerHTML = "";
    if (!auth) { host.hidden = true; return; }

    const badges = [];
    if (auth.cryptographically_verified) {
        badges.push(_mkBadge("🛡 DKIM aligned", "good",
                             "DKIM signature aligned with the From: domain — sender proven"));
    }
    const results = {
        SPF:   auth.spf,
        DKIM:  auth.dkim,
        DMARC: auth.dmarc,
    };
    for (const [name, verdict] of Object.entries(results)) {
        if (verdict === "pass") {
            badges.push(_mkBadge(`${name} pass`, "good", `${name} check passed`));
        } else if (verdict === "fail") {
            badges.push(_mkBadge(`${name} fail`, "bad",
                                 `${name} check FAILED — possible spoofing`));
        } else if (verdict === "softfail") {
            badges.push(_mkBadge(`${name} softfail`, "warn",
                                 `${name} soft-failed — sender not authorised but not blocked`));
        }
        // "none" / "neutral" / "temperror" → no badge (silent)
    }
    if (auth.spamhaus_dbl_listed) {
        badges.push(_mkBadge("🔴 Spamhaus listed", "bad",
                             "Sender domain is on the Spamhaus DBL"));
    }
    // Explicit signal that the message didn't ship with auth headers at all
    if ((auth.reasons || []).includes("no_auth_header") && badges.length === 0) {
        badges.push(_mkBadge("no auth header", "warn",
                             "Message shipped without SPF/DKIM/DMARC — origin unverifiable"));
    }

    if (badges.length === 0) { host.hidden = true; return; }
    for (const b of badges) host.appendChild(b);
    host.hidden = false;
}

// ---------- LIME explain (background pre-fire) ----------
async function fetchExplain(payload, thisRun) {
    try {
        const resp = await fetch(`${getApiBase()}/explain`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (thisRun !== runId) return;        // stale — discard
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Server returned ${resp.status}`);
        }
        const data = await resp.json();
        if (thisRun !== runId) return;        // stale — discard
        explainData = data.features || [];
        if (explainPanel.open) renderExplain(explainData);

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
        if (thisRun !== runId) return;        // stale — discard
        explainError = e?.message || String(e);
        if (explainPanel.open) showExplainError();
    }
}

explainPanel.addEventListener("toggle", () => {
    if (!explainPanel.open) return;
    if (explainData) { renderExplain(explainData); return; }
    if (explainError) { showExplainError(); return; }
    // not done yet — show waiting state
    explainTokens.innerHTML =
        `<span class="explain__status">Computing LIME explanation… (~5-10s)</span>`;
});

function showExplainError() {
    explainTokens.innerHTML = "";
    explainStatus.hidden = false;
    explainStatus.textContent = `❌ ${explainError}`;
}

function renderExplain(features) {
    if (!features.length) {
        explainTokens.innerHTML = "";
        explainStatus.hidden = false;
        explainStatus.textContent = "No salient tokens returned by the model.";
        return;
    }
    explainTokens.innerHTML = features.map((f) => {
        const cls = f.supports === "phishing" ? "token--phishing" : "token--safe";
        const w = Math.abs(f.weight).toFixed(2);
        return `<span class="token ${cls}" title="${f.supports} contribution: ${w}">
                    ${escapeHTML(f.token)}<span class="token__weight">${w}</span>
                </span>`;
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
    lastPayload = null;
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
    });
});

customUrlInput.addEventListener("input", () => {
    backendCustomUrl = customUrlInput.value.trim();
    STORAGE?.set({ backend_custom_url: backendCustomUrl });
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
        const h = Math.round((tot / maxDaily) * 100);
        const phishH = tot ? Math.round((d.phishing / tot) * h) : 0;
        const safeH  = h - phishH;
        const short = d.date.slice(5);   // MM-DD
        return `
          <div class="dc-col" title="${d.date}: ${tot} scan(s) — ${d.phishing} phishing / ${d.safe} safe">
            <div class="dc-stack" style="height:${h}%">
              <span class="dc-phishing" style="height:${phishH}%"></span>
              <span class="dc-safe"     style="height:${safeH}%"></span>
            </div>
            <div class="dc-label">${short}</div>
          </div>`;
    }).join("");

    // Top phishing tokens
    if (stats.topTokens.length === 0) {
        topTokensEl.innerHTML =
            `<div class="empty-hint">No phishing tokens recorded yet — LIME data will accumulate as you scan.</div>`;
    } else {
        const maxW = Math.max(...stats.topTokens.map((t) => t.weight));
        topTokensEl.innerHTML = stats.topTokens.map((t) => {
            const pct = Math.round((t.weight / maxW) * 100);
            return `
              <div class="token-row">
                <span class="token-row__label">${escapeHtml(t.token)}</span>
                <span class="token-row__bar"><span style="width:${pct}%"></span></span>
              </div>`;
        }).join("");
    }

    // Recent history — last 20
    historyList.innerHTML = list.slice(0, 20).map((e) => {
        const dot = e.verdict === "phishing" ? "🚩" : "✅";
        const when = timeAgo(e.ts);
        const subj = e.subject || "(no subject)";
        const src = ({ gmail: "Gmail", file: ".eml file", paste: "pasted text" })[e.source] || e.source;
        return `
          <div class="history-item" data-verdict="${e.verdict}" data-id="${e.id}">
            <div class="history-item__dot">${dot}</div>
            <div class="history-item__main">
              <div class="history-item__subject">${escapeHtml(subj)}</div>
              <div class="history-item__meta">
                <span>${src}</span>
                <span>·</span>
                <span>${when}</span>
                ${e.sender ? `<span>·</span><span>${escapeHtml(e.sender)}</span>` : ""}
              </div>
            </div>
            <div class="history-item__score">${Math.round((e.score || 0) * 100)}%</div>
          </div>`;
    }).join("");
}

function escapeHtml(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

function timeAgo(ts) {
    const s = Math.max(1, Math.floor((Date.now() - ts) / 1000));
    if (s < 60)      return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60)      return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24)      return `${h}h ago`;
    const d = Math.floor(h / 24);
    if (d < 30)      return `${d}d ago`;
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

// Export handlers — trigger a client-side download using a Blob URL.
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
    if (!confirm("Delete all locally-stored scan history? This cannot be undone.")) return;
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
        if (id && confirm("Remove this entry from history?")) {
            await window.PhishLensHistory?.deleteScan(id);
            await renderInsights();
        }
    }
});

testConnBtn.addEventListener("click", async () => {
    connStatus.hidden = false;
    connStatus.className = "conn-status conn-status--info";
    connStatus.textContent = "Testing…";
    try {
        const url = getApiBase();
        if (!url || !/^https?:\/\//.test(url)) {
            throw new Error("URL must start with http:// or https://");
        }
        const resp = await fetch(`${url}/`, { method: "GET" });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json().catch(() => null);
        connStatus.className = "conn-status conn-status--ok";
        connStatus.textContent = `✓ Backend reachable — model: ${data?.model || "unknown"}`;
    } catch (e) {
        connStatus.className = "conn-status conn-status--err";
        const msg = String(e?.message || e);
        connStatus.textContent = msg.startsWith("Failed to fetch")
            ? "❌ Backend unreachable. Check the URL and that the server is running."
            : `❌ ${msg}`;
    }
});

// ---------- util ----------
function escapeHTML(s) {
    return String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

// boot
showView("upload");
