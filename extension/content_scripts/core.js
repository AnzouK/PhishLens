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

// True when the element and everything in it are out of view: no box,
// transparent, clipped to nothing, placed far off the page or scaled to
// nothing. innerText already leaves out display:none; these others it
// keeps.
PL.isHiddenBox = function isHiddenBox(el) {
    if (typeof getComputedStyle !== "function" || !el?.getClientRects) return false;
    const st = getComputedStyle(el);
    // display:contents draws no box of its own but shows its content.
    if (st.display !== "contents" && !el.getClientRects().length) return true;
    if (Number(st.opacity) <= 0.05) return true;
    if (/^rect\(0(?:px)?,? 0(?:px)?,? 0(?:px)?,? 0(?:px)?\)$/.test(st.clip || "")) return true;
    if (/^inset\((?:[5-9]\d|\d{3,})(?:\.\d+)?%|^circle\(0(?:px)?[ )]/.test(st.clipPath || "")) return true;
    if (/hidden|clip/.test(`${st.overflow} ${st.overflowX} ${st.overflowY}`)) {
        const r = el.getBoundingClientRect();
        if (r.height < 1 || r.width < 1) return true;
    }
    if (/absolute|fixed/.test(st.position || "") &&
        ["left", "top", "right", "bottom"].some((k) => parseFloat(st[k]) <= -500)) return true;
    if (parseFloat(st.textIndent) <= -500) return true;
    return flattened(st.transform);
};

// True when the element's own text cannot be read: visibility hidden, a
// font under 2 px, or too little contrast with what is drawn behind it
// (a WCAG ratio under 1.2, like backend/hidden_content.py). Its children
// set their own colour and size: a dark section whose paragraphs are
// white is not hidden.
PL.textUnreadable = function textUnreadable(el, cache) {
    if (typeof getComputedStyle !== "function") return false;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || st.visibility === "collapse" || parseFloat(st.fontSize) < 2) return true;
    const ink = rgba(st.color);
    const behind = backgroundBehind(el, cache);
    return !!ink && (ink[3] <= 0.05 || (!!behind && contrast(over(ink, behind), behind) < 1.2));
};

// Either: the element's text cannot be seen (the shared test cases).
PL.isHidden = (el) => PL.isHiddenBox(el) || PL.textUnreadable(el);

// A transform that flattens the element to a line or a point (a scale of
// 0 on any axis): its 2D matrix has a determinant of 0.
function flattened(transform) {
    const m = /^matrix\(([^)]*)\)$/.exec(transform || "");
    if (!m) return false;
    const [a, b, c, d] = m[1].split(",").map(Number);
    return Math.abs(a * d - b * c) < 1e-4;
}

// [r, g, b, alpha] of a computed colour ("rgb(1, 2, 3)", "rgba(1, 2, 3, 0.5)").
function rgba(color) {
    const m = /^rgba?\((\d+), (\d+), (\d+)(?:, ([\d.]+))?\)$/.exec(color || "");
    return m ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] === undefined ? 1 : Number(m[4])] : null;
}

// [r, g, b] of `top` (with its alpha) drawn over the opaque `bottom`.
function over(top, bottom) {
    const a = top[3];
    return [0, 1, 2].map((i) => Math.round(a * top[i] + (1 - a) * bottom[i]));
}

// WCAG contrast ratio of two colours, 1 (same) to 21 (black on white).
function contrast(a, b) {
    const lum = (c) => {
        const [r, g, b2] = c.map((v) => {
            const x = v / 255;
            return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * r + 0.7152 * g + 0.0722 * b2;
    };
    const [lo, hi] = [lum(a), lum(b)].sort((x, y) => x - y);
    return (hi + 0.05) / (lo + 0.05);
}

// The colour drawn behind an element: its background and its ancestors'
// composed from the white page up, alpha included (backgrounds are not
// inherited, they show through); null when an image is drawn (unknown).
function backgroundBehind(el, cache = new Map()) {
    // Up to the first element already known, an opaque or image
    // background, or the page; then down again, each result memoised (the
    // walk is shared by all the children; a loop, not recursion, for very
    // deep messages).
    const chain = [];
    let below = [255, 255, 255];
    for (let n = el; n && n.nodeType === 1; n = n.parentNode) {
        if (cache.has(n)) {
            below = cache.get(n);
            break;
        }
        const st = getComputedStyle(n);
        const c = rgba(st.backgroundColor);
        const image = !!st.backgroundImage && st.backgroundImage !== "none";
        chain.push([n, c, image]);
        if (image || (c && c[3] >= 1)) {
            below = undefined;
            break;
        }
    }
    for (let i = chain.length - 1; i >= 0; i--) {
        const [n, c, image] = chain[i];
        if (image) below = null;
        else if (c && c[3] >= 1) below = c.slice(0, 3);
        else if (below && c && c[3] > 0) below = over(c, below);
        cache.set(n, below);
    }
    return chain.length ? cache.get(el) : below;
}

// "rgba(0, 0, 0, 0)" or "transparent": the computed colour of text drawn
// with no ink.
function transparent(color) {
    if (color === "transparent") return true;
    const m = /^rgba\([^)]*,\s*([\d.]+)\)$/.exec(color || "");
    return !!m && Number(m[1]) <= 0.05;
}

// What is hidden under `el`: { boxes, texts, generated }. `boxes` are the
// outermost elements hidden whole (their subtrees are not walked); `texts`
// the elements whose own text is unreadable while their children may not
// be; `generated` the words style sheets write (pseudoWords), visible.
// At most MAX_WALK elements are examined (Gmail cuts messages above
// 102 KB, far fewer elements than that).
const MAX_WALK = 20000;
PL.hiddenParts = function hiddenParts(el) {
    const out = { boxes: [], texts: [], generated: [] };
    if (typeof getComputedStyle !== "function" || !el?.children) return out;
    const backgrounds = new Map();
    const stack = [...el.children].reverse();       // popped in page order
    for (let seen = 0; stack.length && seen < MAX_WALK; seen++) {
        const n = stack.pop();
        // <map> and <area> never draw a box of their own (area is
        // display:none in every browser): they are judged through the
        // image that uses the map (shownLink), not as hidden boxes.
        if (n.tagName === "MAP" || n.tagName === "AREA") {
            stack.push(...[...n.children].reverse());
            continue;
        }
        if (PL.isHiddenBox(n)) {
            out.boxes.push(n);
            continue;
        }
        if (ownText(n) && PL.textUnreadable(n, backgrounds)) out.texts.push(n);
        if (seen < MAX_PSEUDO) out.generated.push(...pseudoWords(n, backgrounds));
        stack.push(...[...n.children].reverse());
    }
    return out;
};

// Words a style sheet writes on the page itself (::before and ::after
// content): the reader sees them, innerText does not hold them, so a lure
// written there was out of the text model's reach. Looked for on the
// first MAX_PSEUDO elements.
const MAX_PSEUDO = 5000;
function pseudoWords(n, backgrounds) {
    const words = [];
    for (const pseudo of ["::before", "::after"]) {
        const st = getComputedStyle(n, pseudo) || {};
        // Only what can be read: shown, opaque, not invisible, 2 px or
        // more, and a colour that stands out from what is behind it.
        if (st.display === "none" || /hidden|collapse/.test(st.visibility || "") ||
            Number(st.opacity ?? 1) <= 0.05 || parseFloat(st.fontSize) < 2) continue;
        const ink = rgba(st.color);
        const own = rgba(st.backgroundColor);
        let behind = backgroundBehind(n, backgrounds);
        if (behind && own && own[3] > 0) behind = over(own, behind);
        if (ink && (ink[3] <= 0.05 || (behind && contrast(over(ink, behind), behind) < 1.2))) continue;
        const content = st.content || "";
        for (const m of content.matchAll(/"((?:[^"\\]|\\.){0,500})"/g)) if (m[1].trim()) words.push(m[1]);
    }
    return words;
}

// The text written directly in an element, not in its children.
function ownText(el) {
    return [...(el.childNodes || [])].filter((c) => c.nodeType === 3).map((c) => c.data).join(" ").replace(/\s+/g, " ").trim();
}

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

// The text of an email as the reader sees it, with the hidden text after
// it: placed before the message, it filled what the text model reads
// with words nobody sees. Hidden boxes are marked for an instant
// (banner.css hides them) and unreadable text emptied for that instant,
// then both are read on their own.
// `hidden` is PL.hiddenParts(el), when the caller already has it.
PL.textOf = function textOf(el, hidden = PL.hiddenParts(el)) {
    if (!el) return "";
    // The unreadable text is emptied for the instant innerText is read,
    // and put back: a style rule would also have changed the children.
    const blanked = hidden.texts.flatMap((n) => [...n.childNodes].filter((c) => c.nodeType === 3))
        .map((c) => [c, c.data]);
    hidden.boxes.forEach((n) => n.setAttribute("data-pll-hidden", ""));
    blanked.forEach(([c]) => { c.data = ""; });
    let text;
    try {
        text = el.innerText;
    } finally {
        hidden.boxes.forEach((n) => n.removeAttribute("data-pll-hidden"));
        blanked.forEach(([c, data]) => { c.data = data; });
    }
    const tail = [...hidden.boxes.map(wordsOf), ...hidden.texts.map(ownText)].filter(Boolean);
    const generated = (hidden.generated || []).join(" ");
    // Without invisible characters, before anyone cuts the text to a
    // length: 4,000 zero-width spaces once filled what was sent.
    return PL.withoutInvisible([text, generated, ...tail].filter(Boolean).join("\n"))
        .replace(/\s+\n/g, "\n").trim();
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

// A link no one can see to click: neither it nor what it holds is 2 px
// wide and high (a 1 px image, an empty anchor). An inline link around a
// block (a button table) has a flat box of its own: its content counts.
function tinyLink(a) {
    if (!a.getClientRects) return false;
    // display:contents: no box of its own, its content is what is seen.
    if (typeof getComputedStyle === "function" && getComputedStyle(a).display === "contents") return false;
    const big = (r) => r.width >= 2 && r.height >= 2;
    if ([...a.getClientRects()].some(big)) return false;
    return ![...(a.children || [])].some((c) => c.getBoundingClientRect && big(c.getBoundingClientRect()));
}

// A link the reader can see: outside every hidden box, not too small to
// click, and showing something: text outside the hidden parts, or an
// image or drawing of 2 px at least. Fifty links whose only text was
// transparent once filled the place of the real one.
// The <map> names that shown images use (usemap="#name"), once per scan
// (keyed by that scan's set of hidden boxes).
const mapsSeen = new WeakMap();
function shownMaps(a, inBox, boxes) {
    const root = a.getRootNode?.() || a.ownerDocument;
    if (!root) return new Set();
    if (!mapsSeen.has(boxes)) {
        const names = new Set();
        for (const img of root.querySelectorAll?.("img[usemap], object[usemap]") || []) {
            const r = img.getBoundingClientRect?.();
            const st = typeof getComputedStyle === "function" ? getComputedStyle(img) : {};
            const invisible = /hidden|collapse/.test(st.visibility || "") || Number(st.opacity ?? 1) <= 0.05;
            if (inBox(img) || invisible || (r && (r.width < 2 || r.height < 2))) continue;
            names.add((img.getAttribute("usemap") || "").toLowerCase().replace(/^#/, ""));
        }
        mapsSeen.set(boxes, names);
    }
    return mapsSeen.get(boxes);
}

function shownLink(a, hidden, boxes = new Set(hidden.boxes), unreadable = new Set(hidden.texts)) {
    // Inside a hidden box: walk up the ancestors (sets, not a scan of
    // every box for every link: 10,000 boxes and 20,000 links froze the tab).
    const inBox = (x) => {
        for (let n = x; n; n = n.parentNode) if (boxes.has(n)) return true;
        return false;
    };
    if (inBox(a)) return false;
    // An <area> shows nothing of its own: it is seen through the image
    // whose usemap names its <map>, when that image is shown.
    if (a.tagName === "AREA") {
        const map = a.closest?.("map");
        const name = (map?.getAttribute("name") || map?.id || "").toLowerCase();
        return !!name && shownMaps(a, inBox, boxes).has(name);
    }
    if (tinyLink(a)) return false;
    const walk = (n) => {
        for (const c of n.childNodes || []) {
            if (c.nodeType === 3 && c.data.trim() && !unreadable.has(n)) return true;
            if (c.nodeType !== 1 || boxes.has(c)) continue;
            if (/^(IMG|SVG|PICTURE|VIDEO|CANVAS|OBJECT|EMBED|IFRAME)$/i.test(c.tagName)) {
                // Seen when it has a box of 2 px and is not invisible
                // (visibility hidden keeps the box, not the picture).
                const r = c.getBoundingClientRect?.();
                const st = typeof getComputedStyle === "function" ? getComputedStyle(c) : {};
                const seen = !/hidden|collapse/.test(st.visibility || "") && Number(st.opacity ?? 1) > 0.05;
                if (seen && (!r || (r.width >= 2 && r.height >= 2))) return true;
            } else if (walk(c)) {
                return true;
            }
        }
        return false;
    };
    return walk(a);
}

// http(s) targets of the links in a message body, deduplicated, 50 at
// most, as { visible, hidden }: the visible text only says "Click here",
// not where the link goes. Visible links fill the 50 first, and each
// list has the first link of each host before any second one: fifty
// hidden links placed first left the real one out. The server keeps the
// two lists apart too (link_urls, hidden_link_urls). Links to the mail
// page itself are the mail service's own ("View entire message" under a
// long Gmail email), not the sender's.
PL.linkGroupsOf = function linkGroupsOf(el, hidden = PL.hiddenParts(el)) {
    const groups = { visible: [[], []], hidden: [[], []] };    // [new host, repeated host]
    const hosts = { visible: new Set(), hidden: new Set() };
    const seen = new Set();
    const anchors = el ? el.querySelectorAll("a[href], area[href]") : [];
    const boxes = new Set(hidden.boxes);
    const unreadable = new Set(hidden.texts);
    // As many as the server reads (20,000): a cap on anchors of any kind
    // let 2,000 hidden "#" links hide the ones after them.
    for (let i = 0; i < anchors.length && i < MAX_WALK; i++) {
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
        const kind = shownLink(anchors[i], hidden, boxes, unreadable) ? "visible" : "hidden";
        groups[kind][hosts[kind].has(host) ? 1 : 0].push(href);
        hosts[kind].add(host);
    }
    const visible = groups.visible.flat().slice(0, 50);
    return { visible, hidden: groups.hidden.flat().slice(0, 50 - visible.length) };
};

// Every link target, visible ones first (see linkGroupsOf).
PL.linkTargetsOf = function linkTargetsOf(el, hidden = PL.hiddenParts(el)) {
    const { visible, hidden: unseen } = PL.linkGroupsOf(el, hidden);
    return [...visible, ...unseen];
};

// Characters that take no room on screen (same list as
// backend/unicode_text.py): format characters, the combining grapheme
// joiner, variation selectors, Hangul fillers.
const INVISIBLE_RE = /[\p{Cf}\u034F\u115F\u1160\u3164\uFFA0\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;
// A visible letter of a script the joiners shape (Arabic, Persian, Indic).
const SHAPED_RE = /[\u0600-\u061B\u061D-\u08FF\u0900-\u0DFF\uFB50-\uFDFF\uFE70-\uFEFC]/u;

const shaped = (c) => !!c && SHAPED_RE.test(c) && !/\p{Cf}/u.test(c);

// The text without invisible characters, the joiners (U+200C, U+200D)
// kept between two letters of a script they shape: the same rule as
// backend/unicode_text.without_invisible.
PL.withoutInvisible = function withoutInvisible(text) {
    const s = String(text || "");
    return s.replace(INVISIBLE_RE, (c, i) => (
        (c === "\u200C" || c === "\u200D") && shaped(s[i - 1]) && shaped(s[i + 1]) ? c : ""));
};

// A sender's display name as sent to the server: invisible characters
// out, spaces collapsed, 200 characters at most (the name comes from the
// email and can be any length).
PL.senderName = function senderName(text) {
    const name = PL.withoutInvisible(text).replace(/\s+/g, " ").trim().slice(0, 200);
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
