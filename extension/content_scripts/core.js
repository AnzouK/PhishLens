// First content script on Gmail and Outlook (after lib/). It creates the
// PhishLensPage namespace: each later file wraps its code in a function
// and adds what it offers to that namespace, so no name leaks between
// files. Only two things depend on the manifest order. This file runs
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
// invalidated". That is expected after an update and not logged.
window.addEventListener("unhandledrejection", (ev) => {
    if (/Extension context invalidated/i.test(String(ev.reason?.message || ev.reason))) ev.preventDefault();
});

// Options set in the popup. Full headers are on by default. Automatic
// scanning is off by default because it sends emails without a click.
PL.opts = { fullHeaders: true, autoScan: false };

// Theme chosen in the popup ("theme" in storage). In "auto" the colours
// follow the mail page rather than the system, because Gmail can be light
// on a dark system and the reverse.
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

// The user may switch the mail theme while the tab is open, so this runs
// as the page changes, at most every two seconds.
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

// Email body on Gmail and Outlook. Its content is written by the sender,
// so it is never read as part of the mail service's page (sender checks,
// the user's own address).
PL.MESSAGE_BODY = '.a3s, [id^="UniqueMessageBody"]';
PL.inMessageBody = (el) => !!el?.closest?.(PL.MESSAGE_BODY);

// True when the element and all of its content are out of view (no box,
// transparent, clipped to nothing, far off the page or scaled to nothing).
// innerText already skips display:none but keeps these.
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
// font under 2 px, or a WCAG contrast ratio under 1.2 against what is
// drawn behind it (the same threshold as backend/hidden_content.py).
// Children set their own colour and size, so a dark section with white
// paragraphs is not hidden.
PL.textUnreadable = function textUnreadable(el, cache) {
    if (typeof getComputedStyle !== "function") return false;
    const st = getComputedStyle(el);
    if (st.visibility === "hidden" || st.visibility === "collapse" || parseFloat(st.fontSize) < 2) return true;
    const ink = rgba(st.color);
    const behind = backgroundBehind(el, cache);
    return !!ink && (ink[3] <= 0.05 || (!!behind && contrast(over(ink, behind), behind) < 1.2));
};

// Either check (used by the shared test cases).
PL.isHidden = (el) => PL.isHiddenBox(el) || PL.textUnreadable(el);

// A scale of 0 on any axis flattens the element to a line or a point, and
// its 2D matrix then has a determinant of 0.
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

// Colour drawn behind an element, composed from the white page up through
// its ancestors' backgrounds with alpha. Backgrounds are not inherited but
// show through. Returns null when a background image is in the way, since
// its colour is unknown.
function backgroundBehind(el, cache = new Map()) {
    // Walk up to the first cached element, an opaque or image background,
    // or the page, then back down and cache each result so siblings share
    // the work. A loop rather than recursion, for very deep messages.
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

// Hidden content under `el`, as { boxes, texts, generated }. `boxes` are
// the outermost elements hidden whole (their subtrees are skipped).
// `texts` are elements whose own text is unreadable even if their children
// are not. `generated` holds the visible words written by style sheets
// (pseudoWords). The walk stops after MAX_WALK elements, well above what
// fits in the 102 KB at which Gmail clips a message.
const MAX_WALK = 20000;
PL.hiddenParts = function hiddenParts(el) {
    const out = { boxes: [], texts: [], generated: [] };
    if (typeof getComputedStyle !== "function" || !el?.children) return out;
    const backgrounds = new Map();
    const stack = [...el.children].reverse();       // popped in page order
    for (let seen = 0; stack.length && seen < MAX_WALK; seen++) {
        const n = stack.pop();
        // <map> and <area> never draw a box of their own (area is
        // display:none in every browser). They are judged through the
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

// Words written by a style sheet (::before and ::after content). The
// reader sees them but innerText leaves them out, so a lure placed there
// would never reach the text model. Only the first MAX_PSEUDO elements
// are checked.
const MAX_PSEUDO = 5000;
function pseudoWords(n, backgrounds) {
    const words = [];
    for (const pseudo of ["::before", "::after"]) {
        const st = getComputedStyle(n, pseudo) || {};
        // Keep only readable content: shown, not transparent, at least
        // 2 px, and in a colour that stands out from the background.
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

// Text of an element, skipping style sheets and scripts, whose
// textContent is code.
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

// Text of an email as the reader sees it, followed by the hidden text.
// Hidden text placed before the message would otherwise fill what the
// text model reads with words nobody sees. While innerText is read,
// hidden boxes are marked (banner.css hides them) and unreadable text is
// emptied; both are then read separately. `hidden` is PL.hiddenParts(el)
// when the caller already has it.
PL.textOf = function textOf(el, hidden = PL.hiddenParts(el)) {
    if (!el) return "";
    // The text nodes are emptied and restored afterwards. A style rule
    // would have changed the children as well.
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
    // Collapse invisible characters before anything truncates the text,
    // or a few thousand zero-width spaces can use up the whole length.
    // Runs are cut to one character rather than removed because the
    // server reads the text both as shown and as written.
    return PL.collapseInvisible([text, generated, ...tail].filter(Boolean).join("\n"))
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

// A link too small to see or click: neither it nor its content is 2 px
// wide and high (a 1 px image, an empty anchor). An inline link around a
// block (a button table) has a flat box of its own, so its content is
// measured instead.
function tinyLink(a) {
    if (!a.getClientRects) return false;
    // display:contents has no box of its own; only its content shows.
    if (typeof getComputedStyle === "function" && getComputedStyle(a).display === "contents") return false;
    const big = (r) => r.width >= 2 && r.height >= 2;
    if ([...a.getClientRects()].some(big)) return false;
    return ![...(a.children || [])].some((c) => c.getBoundingClientRect && big(c.getBoundingClientRect()));
}

// <map> names used by visible images (usemap="#name"), computed once per
// scan and keyed by that scan's set of hidden boxes.
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

// A link the reader can see: outside every hidden box, large enough to
// click, and showing something (text outside the hidden parts, or an
// image or drawing of at least 2 px). Links whose only text is
// transparent must not take the place of the real one.
function shownLink(a, hidden, boxes = new Set(hidden.boxes), unreadable = new Set(hidden.texts)) {
    // Check the ancestors against a set. Scanning every box for every
    // link froze the tab on 10,000 boxes and 20,000 links.
    const inBox = (x) => {
        for (let n = x; n; n = n.parentNode) if (boxes.has(n)) return true;
        return false;
    };
    if (inBox(a)) return false;
    // An <area> shows nothing itself. It counts as shown when the image
    // whose usemap names its <map> is shown.
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
            // Pictures, and the shapes of a drawing (a link inside an <svg>
            // around a <rect> shows the shape).
            if (/^(IMG|SVG|PICTURE|VIDEO|CANVAS|OBJECT|EMBED|IFRAME|RECT|PATH|CIRCLE|ELLIPSE|POLYGON|POLYLINE|LINE|USE|IMAGE)$/i.test(c.tagName)) {
                // Seen when its box is at least 2 px and it is not
                // invisible (visibility hidden keeps the box but not the
                // picture).
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

// Address of a link as a string. In a real page an <a> inside an <svg> is
// an SVGAElement whose .href is an SVGAnimatedString ({ baseVal }), and
// the address may be in xlink:href. Relative addresses are resolved.
function linkHref(a) {
    // The browser has already resolved an HTML link's .href.
    if (typeof a.href === "string" && /^https?:\/\//i.test(a.href)) return a.href;
    const raw = typeof a.href === "string"
        ? a.href
        : a.href?.baseVal || a.getAttribute?.("href") || a.getAttribute?.("xlink:href") || "";
    if (!raw) return "";
    // Anything else (the raw attribute of an SVG link, possibly with
    // spaces, capitals or a relative path) is resolved here.
    try {
        return new URL(raw.trim(), location.href).href;
    } catch {
        try {
            return new URL(raw.trim()).href;
        } catch {
            return "";
        }
    }
}

// http(s) link targets in a message body, deduplicated, at most 50, as
// { visible, hidden }. The visible text ("Click here") does not say where
// a link goes. Visible links fill the 50 slots first, and in each list the
// first link to a host comes before any repeat, so hidden links placed
// first cannot push the real one out. The server keeps the two lists
// apart as well (link_urls, hidden_link_urls). Links to the mail page
// itself belong to the mail service (Gmail's "View entire message" under
// a long email), not to the sender.
PL.linkGroupsOf = function linkGroupsOf(el, hidden = PL.hiddenParts(el)) {
    const groups = { visible: [[], []], hidden: [[], []] };    // [new host, repeated host]
    const hosts = { visible: new Set(), hidden: new Set() };
    const seen = new Set();
    const anchors = el ? el.querySelectorAll("a, area") : [];
    const boxes = new Set(hidden.boxes);
    const unreadable = new Set(hidden.texts);
    // Every anchor is examined, but only the first MAX_WALK distinct
    // addresses get the costly visibility check; the rest count as hidden.
    // Capping anchors instead would let thousands of copies of a decoy
    // hide the link that follows them.
    let checked = 0;
    for (let i = 0; i < anchors.length; i++) {
        let href = linkHref(anchors[i]);
        // A very long address is truncated rather than dropped, since the
        // checks mostly read its host.
        if (!/^https?:\/\//i.test(href)) continue;
        if (href.length > 2048) href = href.slice(0, 2048);
        if (seen.has(href)) continue;
        let host;
        try {
            host = new URL(href).hostname;
        } catch {
            continue;
        }
        if (host === location.hostname) continue;
        seen.add(href);
        const shown = checked++ < MAX_WALK && shownLink(anchors[i], hidden, boxes, unreadable);
        const kind = shown ? "visible" : "hidden";
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

// Text without invisible characters, keeping the joiners that Arabic,
// Persian and Indic scripts need. Defined in lib/shared.js with the same
// rule as backend/unicode_text.without_invisible.
PL.withoutInvisible = PhishLensShared.withoutInvisible;
PL.collapseInvisible = PhishLensShared.collapseInvisible;

// Sender display name as sent to the server, without invisible
// characters, spaces collapsed and cut to 200 characters. The name comes
// from the email and can be any length.
PL.senderName = function senderName(text) {
    const name = PL.withoutInvisible(text).replace(/\s+/g, " ").trim().slice(0, 200);
    return name || null;
};

PL.pct = (p) => (p == null ? null : Math.round(p * 100));

// raw_text is the body, or the subject plus whatever text there is when
// the body is almost empty (image-only emails).
PL.MIN_BODY = 20;
// When both are sent, the server reads the page text instead of the
// message's own, so a shorter limit would lose the end of long emails.
PL.MAX_RAW_TEXT = 20000;
PL.rawText = function rawText(subject, body) {
    const short = !body || body.length < PL.MIN_BODY;
    return (short ? [subject, body].filter(Boolean).join("\n") || "(no text)" : body).slice(0, PL.MAX_RAW_TEXT);
};
})();
