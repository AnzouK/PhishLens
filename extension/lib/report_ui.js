// "Is this right?" controls under a verdict, in the Gmail and Outlook
// banners and in the popup:
//   languageLine()  "Language detected: French. Correct / Not this language"
//   reportButton()  "Wrong verdict? Report it": a panel with the redacted
//                   text, editable, sent only when the user confirms.
// Classes are prefixed plr- (styled in banner.css and popup.css).
(function () {
"use strict";

const LANGS = ["en", "fr", "pt", "es", "de", "it", "nl", "pl", "ru", "uk", "tr", "ar", "hi", "id", "vi",
    "zh", "ja", "ko", "ha", "yo", "ig", "sw"];

function i18n() { return globalThis.PhishLensI18n; }
function t(key, vars) { return i18n().t(key, vars); }

function languageName(code) {
    if (!code || code === "und") return "";
    if (code === "other") return t("lang_another");
    try {
        const names = new Intl.DisplayNames([i18n().language(), "en"], { type: "language" });
        return names.of(code) || code;
    } catch {
        return code;
    }
}

function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
}

function button(label, cls = "plr-btn") {
    const b = el("button", cls, label);
    b.type = "button";
    return b;
}

// "Language detected: French." with Correct / Not this language. onChoice
// receives the user's answer: the same code, or the one picked.
function languageLine({ code, onChoice }) {
    const line = el("div", "plr-lang");
    const known = code && code !== "und";
    const label = el("span", "plr-lang__text",
        known ? t("fb_lang_detected", { lang: languageName(code) }) : t("fb_lang_unknown"));
    line.append(label);
    const done = (answer) => {
        line.replaceChildren(el("span", "plr-lang__text",
            t("fb_lang_saved", { lang: languageName(answer) })));
        onChoice?.(answer);
    };
    const pick = () => {
        const select = el("select", "plr-select");
        select.setAttribute("aria-label", t("fb_lang_pick"));
        select.append(new Option(t("fb_lang_pick"), ""));
        for (const c of [...LANGS, "other"]) select.append(new Option(languageName(c), c));
        select.addEventListener("change", () => { if (select.value) done(select.value); });
        line.replaceChildren(label, select);
        select.focus();
    };
    if (known) {
        const ok = button(t("fb_lang_ok"));
        ok.addEventListener("click", () => done(code));
        const no = button(t("fb_lang_wrong"));
        no.addEventListener("click", pick);
        line.append(ok, no);
    } else {
        const set = button(t("fb_lang_pick"));
        set.addEventListener("click", pick);
        line.append(set);
    }
    return line;
}

// "Thank you. Reference ...", with a button that copies the reference.
function sentMessage(reference) {
    const box = el("div", "plr-sent");
    box.append(el("p", "plr-report__status", t("fb_sent", { ref: reference })));
    const ref = el("code", "plr-ref", reference);
    const copy = button(t("fb_copy"));
    copy.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(reference);
            copy.textContent = t("fb_copied");
        } catch {
            const range = document.createRange();
            range.selectNodeContents(ref);
            const sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);
        }
    });
    const row = el("div", "plr-lang");
    row.append(ref, copy);
    box.append(row);
    return box;
}

// The report panel: what will be sent, editable, behind a confirmation.
// send(kind, text) returns a promise of {ok, reference, error}.
function reportPanel({ verdict, text, redact, send, onSent }) {
    const kind = verdict === "phishing" ? "false_positive" : "false_negative";
    const panel = el("div", "plr-report");
    panel.append(el("div", "plr-report__title", t(kind === "false_positive" ? "fb_report_title_fp" : "fb_report_title_fn")));
    panel.append(el("p", "plr-report__intro", t("fb_report_intro")));
    const area = el("textarea", "plr-report__text");
    area.value = text || "";
    area.rows = 8;
    area.setAttribute("aria-label", t("fb_report_preview"));
    if (!text) area.placeholder = t("fb_report_paste");
    // Pasted text is redacted at once, so the person sees what will be sent.
    area.addEventListener("paste", (e) => {
        const pasted = e.clipboardData?.getData("text/plain");
        if (!pasted) return;
        e.preventDefault();
        area.setRangeText(redact(pasted), area.selectionStart, area.selectionEnd, "end");
        refresh();
    });
    const check = el("input");
    check.type = "checkbox";
    const checkLabel = el("label", "plr-report__check");
    checkLabel.append(check, document.createTextNode(" " + t("fb_report_check")));
    const sendBtn = button(t("fb_send"), "plr-btn plr-btn--strong");
    sendBtn.disabled = true;
    const cancel = button(t("fb_cancel"));
    const status = el("p", "plr-report__status");
    status.setAttribute("role", "status");
    const hint = el("p", "plr-report__hint");
    const enoughWords = () => area.value.trim().split(/\s+/).filter(Boolean).length >= 3;
    const ready = () => check.checked && enoughWords();
    const refresh = () => {
        sendBtn.disabled = !ready();
        hint.textContent = enoughWords() ? "" : t("fb_too_short");
    };
    check.addEventListener("change", refresh);
    area.addEventListener("input", refresh);
    cancel.addEventListener("click", () => panel.remove());
    sendBtn.addEventListener("click", async () => {
        sendBtn.disabled = true;
        cancel.disabled = true;
        status.textContent = t("fb_sending");
        const r = await send(kind, redact(area.value)).catch((e) => ({ ok: false, error: String(e?.message || e) }));
        if (r?.ok) {
            panel.replaceChildren(sentMessage(r.reference));
            onSent?.(kind, r.reference);
        } else {
            status.textContent = t("fb_failed", { error: r?.error || t("unknown_error") });
            refresh();
            cancel.disabled = false;
        }
    });
    const actions = el("div", "plr-report__actions");
    actions.append(sendBtn, cancel);
    refresh();
    panel.append(area, hint, checkLabel, actions, status);
    return panel;
}

// "Wrong verdict? Report it": opens the panel next to itself. getText
// resolves to the redacted text, or "" when the person has to paste it.
function reportButton({ verdict, getText, redact, send, onSent }) {
    const wrap = el("div", "plr-wrap");
    const b = button(t("fb_report"), "plr-link");
    b.addEventListener("click", async () => {
        if (wrap.querySelector(".plr-report")) return;
        const text = (await getText?.()) || "";
        const panel = reportPanel({ verdict, text, redact, send, onSent });
        wrap.append(panel);
        panel.querySelector("textarea")?.focus();
    });
    wrap.append(b);
    return wrap;
}

// The body of a report (POST /feedback): the verdict and scores, never
// the sender or the subject; `text` was redacted and shown to the user.
function payload(kind, text, data, { source, lang, langUser } = {}) {
    const p = (agent) => Number(data?.agents?.[agent]?.phishing_probability) || 0;
    return {
        kind, text,
        verdict: data?.verdict,
        fused_score: Number(data?.fused_score) || 0,
        agents: { text: p("text"), url: p("url"), metadata: p("metadata") },
        trust_path: data?.trust_path || null,
        source: source || "paste",
        lang: data?.language?.code || lang || null,
        lang_user: langUser || null,
        ui_lang: i18n().language(),
        version: chrome.runtime.getManifest?.().version || null,
    };
}

// What reportPanel expects from send(): { ok, reference } or { ok, error }.
function sendWith(feedback, buildPayload) {
    return (kind, text) => feedback(buildPayload(kind, text))
        .then((reference) => ({ ok: true, reference }))
        .catch((e) => ({ ok: false, error: String(e?.message || e) }));
}

const api = Object.freeze({
    LANGS, languageName, languageLine, reportPanel, reportButton, sentMessage, payload, sendWith,
});
// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = api;
globalThis.PhishLensReport = api;
})();
