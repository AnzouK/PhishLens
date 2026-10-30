// The Upload view: a file (.eml or an attachment) or pasted text, sent
// to the server when the user clicks Analyze.
import { $, t, showView, showStatus, hideStatus } from "./ui.js";
import { renderResult, explain, cancelExplanation } from "./result.js";
import { renderResultFeedback } from "./report.js";

const { ATTACHMENT_EXTS, MAX_FILE_MB, fileExt } = window.PhishLensConstants;
const MIN_PASTE = 20;

const state = { tab: "file", file: null, pasted: "", run: 0 };

const analyzeBtn = $("analyze-btn");
const fileInput = $("file-input");
const pasteInput = $("paste-input");
const pasteCounter = $("paste-counter");

function updateAnalyzeEnabled() {
    analyzeBtn.disabled = state.tab === "file" ? !state.file : state.pasted.trim().length < MIN_PASTE;
}

function setFile(file) {
    state.file = file;
    $("drop-zone").classList.toggle("drop-zone--filled", !!file);
    $("drop-empty").hidden = !!file;
    $("drop-filled").hidden = !file;
    $("drop-filename").textContent = window.PhishLensShared.safeName(file?.name);
    if (!file) fileInput.value = "";
    updateAnalyzeEnabled();
    if (file) hideStatus();
}

function setPasted(text) {
    state.pasted = text;
    pasteInput.value = text;
    pasteCounter.textContent = text.length;
    updateAnalyzeEnabled();
    hideStatus();
}

function fileToB64(file) {
    return new Promise((resolve, reject) => {
        const r = new FileReader();
        r.onload = () => resolve(r.result.split(",")[1]);
        r.onerror = reject;
        r.readAsDataURL(file);
    });
}

// What to send for the current input: an .eml goes to /analyse, other
// files to /analyse_attachment, pasted text to /analyse.
async function request() {
    if (state.tab === "paste") {
        if (state.pasted.trim().length < MIN_PASTE) throw new Error(t("paste_min"));
        return { source: "paste", payload: { raw_text: state.pasted } };
    }
    const file = state.file;
    if (!file) throw new Error(t("pick_first"));
    if (file.size > MAX_FILE_MB * 1024 * 1024) throw new Error(t("file_too_large"));
    const b64 = await fileToB64(file);
    if (ATTACHMENT_EXTS.includes(fileExt(file.name))) {
        return { source: "attachment", payload: { content_b64: b64, filename: file.name, mime_type: file.type || null } };
    }
    return { source: "file", payload: { raw_email_b64: b64 } };
}

async function analyze() {
    hideStatus();
    showView("loading");
    let req;
    try {
        req = await request();
    } catch (e) {
        showView("upload");
        showStatus(e.message);
        return;
    }
    const run = ++state.run;
    const API = window.PhishLensApi;
    let data;
    try {
        data = req.source === "attachment" ? await API.analyseAttachment(req.payload) : await API.analyse(req.payload);
    } catch (e) {
        if (run !== state.run) return;     // the user already moved on
        showView("upload");
        showStatus(e.message);
        return;
    }
    if (run !== state.run) return;
    renderResult(data);
    showView("result");

    let historyId = null;
    try {
        historyId = await window.PhishLensHistory.saveScan(window.PhishLensHistory.entryFrom(data, {
            source: req.source, subject: (state.file?.name || "").slice(0, 120), sender: data.sender_domain || "",
        }));
    } catch (e) {
        console.warn("[PhishLens] scan not saved in the history:", e);
    }
    renderResultFeedback(data, historyId, req.payload.raw_text || "", req.source);
    if (req.source !== "attachment") explain(req.payload, historyId);
}

function switchTab(tab) {
    if (tab === state.tab) return;
    state.tab = tab;
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("tab--active", b.dataset.tab === tab));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("tab-panel--active", p.dataset.panel === tab));
    updateAnalyzeEnabled();
    hideStatus();
}

export function initUpload() {
    fileInput.accept = [".eml", ...ATTACHMENT_EXTS.map((e) => "." + e)].join(",");
    document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => switchTab(btn.dataset.tab)));

    fileInput.addEventListener("change", () => {
        if (fileInput.files?.[0]) setFile(fileInput.files[0]);
    });
    const dropZone = $("drop-zone");
    dropZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropZone.classList.add("drop-zone--active");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drop-zone--active"));
    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("drop-zone--active");
        const f = e.dataTransfer.files?.[0];
        if (!f) return;
        const ext = fileExt(f.name);
        if (ext === "eml" || ATTACHMENT_EXTS.includes(ext)) setFile(f);
        else showStatus(t("drop_wrong_type"));
    });

    pasteInput.addEventListener("input", () => setPasted(pasteInput.value));
    $("paste-clipboard-btn").addEventListener("click", async () => {
        let text;
        try {
            text = await navigator.clipboard.readText();
        } catch {
            showStatus(t("clipboard_error"));      // permission refused
            return;
        }
        if (!text) {
            showStatus(t("clipboard_empty"));
            return;
        }
        setPasted(text);
        pasteInput.focus();
    });

    analyzeBtn.addEventListener("click", analyze);
    $("back-btn").addEventListener("click", () => {
        state.run++;                     // a scan still running is ignored
        cancelExplanation();
        setFile(null);
        setPasted("");
        showView("upload");
    });
}
