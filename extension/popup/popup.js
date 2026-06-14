// =====================================================================
// PhishLens popup logic — vanilla JS, no build step.
// =====================================================================

const API_BASE = "http://127.0.0.1:8000";

// ---------- DOM refs ----------
const $ = (id) => document.getElementById(id);
const views = {
    upload: $("view-upload"),
    loading: $("view-loading"),
    result: $("view-result"),
};
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
        const resp = await fetch(`${API_BASE}/analyse`, {
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

    // verified sender pill
    const trustedEl = $("verdict-trusted");
    if (data.trusted_sender) {
        trustedEl.hidden = false;
        trustedEl.title = `Sender domain in allowlist: ${data.sender_domain || ""}`;
    } else {
        trustedEl.hidden = true;
    }

    $("verdict-sub").textContent = isPhishing
        ? "We recommend not clicking any links."
        : (data.trusted_sender
            ? "Sender domain is in the verified allowlist."
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

    // collapse explain by default
    explainPanel.removeAttribute("open");
    explainTokens.innerHTML = "";
    explainStatus.hidden = true;
}

// ---------- LIME explain (background pre-fire) ----------
async function fetchExplain(payload, thisRun) {
    try {
        const resp = await fetch(`${API_BASE}/explain`, {
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
