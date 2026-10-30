// First content script on Gmail and Outlook (after lib/). It creates the
// PhishLensPage namespace: each later file wraps its code in a function
// and adds what it offers to that namespace, so no name leaks between
// files. Only two places depend on the manifest order: this file runs
// first, and gmail.js / outlook.js run last and start the page watchers.
(function () {
"use strict";

const { t } = PhishLensI18n;
const { h, icon } = PhishLensDom;
PhishLensI18n.init();

// A fresh object for each copy of the scripts (see `instance`).
const PL = {};
globalThis.PhishLensPage = PL;

PL.TAG = "[PhishLens]";
PL.isGmail = location.hostname === "mail.google.com";

// After an extension update or reload, the previous copy of the scripts
// stays in open tabs, cut off from the extension. Each copy tags the
// buttons it creates; a newer copy replaces older ones, so the user does
// not have to reload Gmail.
PL.instance = Math.random().toString(36).slice(2, 10);

PL.alive = function alive() {
    try {
        return !!chrome.runtime?.id;
    } catch {
        return false;           // reading chrome.runtime throws once cut off
    }
};

// Every page watcher of this copy, stopped together once it is cut off.
const observers = [];
PL.observe = function observe(callback) {
    const obs = new MutationObserver(callback);
    observers.push(obs);
    obs.observe(document.body, { childList: true, subtree: true });
    return obs;
};
PL.shutdownIfDead = function shutdownIfDead() {
    if (PL.alive()) return false;
    observers.forEach((o) => o.disconnect());
    observers.length = 0;
    return true;
};
// A cut-off copy's chrome.* calls reject with "Extension context
// invalidated": expected after an update, not worth an error entry.
window.addEventListener("unhandledrejection", (ev) => {
    if (/Extension context invalidated/i.test(String(ev.reason?.message || ev.reason))) ev.preventDefault();
});

// Options set in the popup. Full headers on by default; automatic
// scanning off by default (it sends emails without a click).
PL.opts = { fullHeaders: true, autoScan: false };

// Theme: the popup's choice ("theme" in storage). In "auto", the colours
// follow the mail page, not the system: Gmail can be light on a dark
// system and the reverse.
let themeChoice = "auto";
let themeCheckedAt = 0;

PL.pageIsDark = function pageIsDark() {
    let el = document.querySelector('div[role="main"]') || document.body;
    while (el) {
        const bg = getComputedStyle(el).backgroundColor;
        const m = bg && bg.match(/rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?/);
        if (m && (m[4] === undefined || Number(m[4]) > 0.5)) {
            const lum = (0.2126 * m[1] + 0.7152 * m[2] + 0.0722 * m[3]) / 255;
            return lum < 0.45;
        }
        el = el.parentElement;
    }
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches || false;
};

PL.applyTheme = function applyTheme(theme) {
    themeChoice = theme === "light" || theme === "dark" ? theme : "auto";
    const resolved = themeChoice === "auto" ? (PL.pageIsDark() ? "dark" : "light") : themeChoice;
    document.documentElement.setAttribute("data-phishlens-theme", resolved);
    themeCheckedAt = Date.now();
};

// Called as the page changes: the user may switch the mail theme while
// the tab is open. At most every two seconds.
PL.refreshTheme = function refreshTheme() {
    if (themeChoice === "auto" && Date.now() - themeCheckedAt > 2000) PL.applyTheme("auto");
};

chrome.storage?.local?.get(["theme"], (s) => PL.applyTheme(s.theme));
chrome.storage?.onChanged?.addListener((changes, area) => {
    if (area === "local" && changes.theme) PL.applyTheme(changes.theme.newValue);
});
window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", () => PL.applyTheme(themeChoice));

// The "Scan with PhishLens" button, next to the subject.
PL.scanButton = function scanButton({ extraClass = "", iconName = "shield", label, title, onClick }) {
    const btn = h("button", { type: "button", class: "pll-scan-btn " + extraClass, title },
        h("span.pll-scan-btn__icon", null, icon(iconName)),
        h("span.pll-scan-btn__label", null, label));
    btn.addEventListener("click", (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        onClick(btn);
    });
    return btn;
};

PL.setBtnLoading = function setBtnLoading(btn, on) {
    btn.disabled = on;
    btn.classList.toggle("pll-scan-btn--loading", on);
    btn.querySelector(".pll-scan-btn__icon").replaceChildren(icon(on ? "spinner" : "shield"));
    btn.querySelector(".pll-scan-btn__label").textContent = on ? t("scanning") : t("scan_again");
};

// The body of an email, on Gmail and on Outlook. What is inside one is
// written by the sender: never read as part of the mail service's page
// (sender checks, the user's own address).
PL.MESSAGE_BODY = '.a3s, [id^="UniqueMessageBody"]';
PL.inMessageBody = (el) => !!el?.closest?.(PL.MESSAGE_BODY);

// True when the element takes no room on the page, or its text cannot be
// seen: transparent (the element or its text colour), an unreadably
// small font, clipped to nothing, placed far off the page or scaled to
// nothing. innerText already leaves out display:none; these others it
// keeps.
PL.isHidden = function isHidden(el) {
    if (typeof getComputedStyle !== "function" || !el?.getClientRects) return false;
    if (!el.getClientRects().length) return true;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || Number(st.opacity) <= 0.05 || parseFloat(st.fontSize) < 2) return true;
    if (transparent(st.color)) return true;
    if (/^inset\((?:[5-9]\d|\d{3,})(?:\.\d+)?%|^circle\(0(?:px)?[ )]/.test(st.clipPath || "")) return true;
    if (/hidden|clip/.test(`${st.overflow} ${st.overflowX} ${st.overflowY}`)) {
        const r = el.getBoundingClientRect();
        if (r.height < 1 || r.width < 1) return true;
    }
    if (/absolute|fixed/.test(st.position || "") &&
        ["left", "top", "right", "bottom"].some((k) => parseFloat(st[k]) <= -500)) return true;
    if (parseFloat(st.textIndent) <= -500) return true;
    // A scale of 0 gives "matrix(0, 0, 0, 0, x, y)".
    return /^matrix\(0, 0, 0, 0,/.test(st.transform || "");
};

// "rgba(0, 0, 0, 0)" or "transparent": the computed colour of text drawn
// with no ink.
function transparent(color) {
    if (color === "transparent") return true;
    const m = /^rgba\([^)]*,\s*([\d.]+)\)$/.exec(color || "");
    return !!m && Number(m[1]) <= 0.05;
}

// The outermost hidden elements under `el`. Hidden subtrees are not
// walked; at most MAX_WALK elements are examined (Gmail cuts messages
// above 102 KB, far fewer elements than that).
const MAX_WALK = 20000;
PL.hiddenParts = function hiddenParts(el) {
    if (typeof getComputedStyle !== "function" || !el?.children) return [];
    const out = [];
    const stack = [...el.children].reverse();       // popped in page order
    for (let seen = 0; stack.length && seen < MAX_WALK; seen++) {
        const n = stack.pop();
        if (PL.isHidden(n)) out.push(n);
        else stack.push(...[...n.children].reverse());
    }
    return out;
};

// The text of an element without its style sheets and scripts (whose
// textContent is code, not words).
function wordsOf(el) {
    const parts = [];
    const walk = (n) => {
        for (const c of n.childNodes || []) {
            if (c.nodeType === 3) parts.push(c.data);
            else if (c.nodeType === 1 && !/^(STYLE|SCRIPT|NOSCRIPT|TEMPLATE)$/.test(c.tagName)) walk(c);
        }
    };
    walk(el);
    return parts.join(" ").replace(/\s+/g, " ").trim();
}

// The text of an email as the reader sees it, with the text hidden by its
// style (see isHidden) after it: placed before the message, it filled
// what the text model reads with words nobody sees. The hidden parts are
// marked for an instant (banner.css hides them) so innerText leaves them
// out, then read on their own. `hidden` is PL.hiddenParts(el), when the
// caller already has it.
PL.textOf = function textOf(el, hidden = PL.hiddenParts(el)) {
    if (!el) return "";
    hidden.forEach((n) => n.setAttribute("data-pll-hidden", ""));
    let text;
    try {
        text = el.innerText;
    } finally {
        hidden.forEach((n) => n.removeAttribute("data-pll-hidden"));
    }
    const tail = hidden.map(wordsOf).filter(Boolean);
    return [text, ...tail].join("\n").replace(/\s+\n/g, "\n").trim();
};

// Base64 of bytes, in chunks so large files do not overflow the stack.
PL.bytesToBase64 = function bytesToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(bin);
};
PL.utf8ToB64 = (text) => PL.bytesToBase64(new TextEncoder().encode(text));

// http(s) targets of the links in a message body, deduplicated, max 50:
// the visible text only says "Click here", not where the link goes.
// Visible links first, one per host before any second one of the same
// host: fifty hidden links to a large site placed first left the real
// one out. Links to the mail page itself are the mail service's own
// ("View entire message" under a long Gmail email), not the sender's.
// A link no one can see to click: neither it nor what it holds is 2 px
// wide and high (a 1 px image, an empty anchor). An inline link around a
// block (a button table) has a flat box of its own: its content counts.
function tinyLink(a) {
    if (!a.getClientRects) return false;
    const big = (r) => r.width >= 2 && r.height >= 2;
    if ([...a.getClientRects()].some(big)) return false;
    return ![...(a.children || [])].some((c) => c.getBoundingClientRect && big(c.getBoundingClientRect()));
}

PL.linkTargetsOf = function linkTargetsOf(el, hidden = PL.hiddenParts(el)) {
    if (!el) return [];
    const ranked = [[], [], [], []];   // visible new host, visible, hidden new host, hidden
    const hosts = new Set();
    const seen = new Set();
    const anchors = el.querySelectorAll("a[href], area[href]");
    for (let i = 0; i < anchors.length && i < 2000; i++) {
        const href = anchors[i].href || "";
        if (!/^https?:\/\//i.test(href) || href.length > 2048 || seen.has(href)) continue;
        let host;
        try {
            host = new URL(href).hostname;
        } catch {
            continue;
        }
        if (host === location.hostname) continue;
        seen.add(href);
        const isHidden = hidden.some((part) => part.contains(anchors[i])) || tinyLink(anchors[i]);
        ranked[(isHidden ? 2 : 0) + (hosts.has(host) ? 1 : 0)].push(href);
        hosts.add(host);
    }
    return ranked.flat().slice(0, 50);
};

// A sender's display name as sent to the server: invisible characters
// out, spaces collapsed, 200 characters at most (the name comes from the
// email and can be any length).
PL.senderName = function senderName(text) {
    const name = String(text || "").replace(/\p{Cf}/gu, "").replace(/\s+/g, " ").trim().slice(0, 200);
    return name || null;
};

PL.pct = (p) => (p == null ? null : Math.round(p * 100));

// The text sent as raw_text: the body, or the subject and whatever text
// there is when the body is almost empty (image-only emails).
PL.MIN_BODY = 20;
PL.rawText = function rawText(subject, body) {
    const short = !body || body.length < PL.MIN_BODY;
    return (short ? [subject, body].filter(Boolean).join("\n") || "(no text)" : body).slice(0, 4000);
};
})();
