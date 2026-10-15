// =====================================================================
// PhishLens: "is this right?" controls under a verdict.
// =====================================================================
// Shared by the Gmail and Outlook banners and the popup:
//   languageLine()  "Language detected: French. Correct / Not this language"
//   reportButton()  "Wrong verdict? Report it", which opens a panel with
//                   the redacted text, editable, sent only on request.
// Classes are prefixed plr- (styled in banner.css and popup.css).
// =====================================================================
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

// The report panel: what will be sent, editable, behind a confirmation.
// send(kind, text) returns a promise of {ok, reference, error}.
function reportPanel({ verdict, text, redact, send, onSent }) {
    const kind = verdict === "phishing" ? "false_positive" : "false_negative";
    const panel = el("div", "plr-report");
    panel.append(el("div", "plr-report__title", t(kind === "false_positive" ? "fb_report_title_fp" : "fb_report_title_fn")));
    panel.append(el("p", "plr-report__intro", t("fb_report_intro")));
    const area = el("textarea", "plr-report__text");
    area.value = text;
    area.rows = 8;
    area.setAttribute("aria-label", t("fb_report_preview"));
    const check = el("input");
    check.type = "checkbox";
    const checkLabel = el("label", "plr-report__check");
    checkLabel.append(check, document.createTextNode(" " + t("fb_report_check")));
    const sendBtn = button(t("fb_send"), "plr-btn plr-btn--strong");
    sendBtn.disabled = true;
    const cancel = button(t("fb_cancel"));
    const status = el("p", "plr-report__status");
    status.setAttribute("role", "status");
    check.addEventListener("change", () => { sendBtn.disabled = !check.checked; });
    cancel.addEventListener("click", () => panel.remove());
    sendBtn.addEventListener("click", async () => {
        sendBtn.disabled = true;
        cancel.disabled = true;
        status.textContent = t("fb_sending");
        const r = await send(kind, redact(area.value)).catch((e) => ({ ok: false, error: String(e?.message || e) }));
        if (r?.ok) {
            panel.replaceChildren(el("p", "plr-report__status", t("fb_sent", { ref: r.reference })));
            onSent?.(kind, r.reference);
        } else {
            status.textContent = t("fb_failed", { error: r?.error || t("unknown_error") });
            sendBtn.disabled = !check.checked;
            cancel.disabled = false;
        }
    });
    const actions = el("div", "plr-report__actions");
    actions.append(sendBtn, cancel);
    panel.append(area, checkLabel, actions, status);
    return panel;
}

// "Wrong verdict? Report it": opens the panel next to itself. getText
// resolves to the redacted text, or "" when nothing can be reported.
function reportButton({ verdict, getText, redact, send, onSent }) {
    const wrap = el("div", "plr-wrap");
    const b = button(t("fb_report"), "plr-link");
    b.addEventListener("click", async () => {
        if (wrap.querySelector(".plr-report")) return;
        const text = await getText();
        if (!text) {
            b.replaceWith(el("span", "plr-lang__text", t("fb_unavailable")));
            return;
        }
        const panel = reportPanel({ verdict, text, redact, send, onSent });
        wrap.append(panel);
        panel.querySelector("textarea")?.focus();
    });
    wrap.append(b);
    return wrap;
}

const api = Object.freeze({ LANGS, languageName, languageLine, reportPanel, reportButton });
// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = api;
globalThis.PhishLensReport = api;
})();
