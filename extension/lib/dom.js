// Building DOM nodes without HTML strings: text from emails and from the
// server only ever becomes a text node or an attribute value, so nothing
// has to be escaped by hand.
(function () {
"use strict";

const SVG_NS = "http://www.w3.org/2000/svg";
const SVG_TAGS = new Set(["svg", "path", "use", "g", "circle", "rect"]);
// Set as properties: the attribute would not change the current state.
const PROPERTIES = new Set(["value", "checked", "disabled", "hidden", "readOnly"]);

function append(node, children) {
    for (const child of children) {
        if (child == null || child === false || child === "") continue;
        if (Array.isArray(child)) append(node, child);
        else node.append(child instanceof Node ? child : String(child));
    }
}

// h("span.badge.badge--good", { title: "…", onclick: fn }, "text", otherNode)
//   tag.class.class   classes after the tag name
//   class             more classes (string)
//   style             object; "--name" keys set CSS custom properties
//   dataset           object copied to data-* attributes
//   on<event>         listener
//   null, undefined and false props and children are skipped
function h(spec, props, ...children) {
    const [tag, ...classes] = spec.split(".");
    const node = SVG_TAGS.has(tag) ? document.createElementNS(SVG_NS, tag) : document.createElement(tag);
    const cls = classes.concat(props?.class ? String(props.class).split(/\s+/) : []).filter(Boolean);
    if (cls.length) node.setAttribute("class", cls.join(" "));
    for (const [key, value] of Object.entries(props || {})) {
        if (value == null || value === false || key === "class") continue;
        if (key === "style") {
            for (const [prop, v] of Object.entries(value)) node.style.setProperty(prop.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase()), v);
        } else if (key === "dataset") {
            Object.assign(node.dataset, value);
        } else if (key.startsWith("on") && typeof value === "function") {
            node.addEventListener(key.slice(2), value);
        } else if (PROPERTIES.has(key)) {
            node[key] = value;
        } else {
            node.setAttribute(key, value === true ? "" : String(value));
        }
    }
    append(node, children);
    return node;
}

// Inline icons of the mail-page banners (no emoji: they render
// differently on every system).
const ICON_PATHS = {
    shield: ["M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z"],
    shieldCheck: ["M12 3l7 3v6c0 4.5-3 7.8-7 9-4-1.2-7-4.5-7-9V6l7-3z", "M9 12l2 2 4-4"],
    alert: ["M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z", "M12 9v4M12 17h.01"],
    clip: ["M21 11l-8.6 8.6a5 5 0 01-7-7L14 4a3.5 3.5 0 015 5l-8.6 8.6a2 2 0 01-2.8-2.8L15 7.5"],
    close: ["M6 6l12 12M18 6L6 18"],
    spinner: ["M12 3a9 9 0 109 9"],
};

function icon(name) {
    return h("svg", { viewBox: "0 0 24 24", "aria-hidden": "true" },
        (ICON_PATHS[name] || []).map((d) => h("path", { d })));
}

// An icon of the popup's sprite (<symbol id="i-name"> in popup.html).
function spriteIcon(name) {
    return h("svg.i", { "aria-hidden": "true" }, h("use", { href: `#i-${name}` }));
}

// Translated texts with markup (keys ending in _html: <strong>, <em>,
// <code>, <br>, <span id>). They ship with the extension, and are still
// rebuilt from an allowlist rather than assigned as HTML.
const ALLOWED_TAGS = new Set(["STRONG", "EM", "CODE", "BR", "SPAN", "B", "I"]);

function copyAllowed(from, to) {
    for (const child of from.childNodes) {
        if (child.nodeType === 3) {
            to.append(child.textContent);
        } else if (child.nodeType === 1 && ALLOWED_TAGS.has(child.tagName)) {
            const copy = document.createElement(child.tagName.toLowerCase());
            if (child.id) copy.id = child.id;
            copyAllowed(child, copy);
            to.append(copy);
        } else if (child.nodeType === 1) {
            copyAllowed(child, to);
        }
    }
}

function setMarkup(el, markup) {
    const doc = new DOMParser().parseFromString(`<body>${markup}</body>`, "text/html");
    el.replaceChildren();
    copyAllowed(doc.body, el);
}

const PhishLensDom = Object.freeze({ h, icon, spriteIcon, setMarkup });
globalThis.PhishLensDom = PhishLensDom;

// eslint-disable-next-line no-undef
if (typeof module !== "undefined" && module.exports) module.exports = PhishLensDom;
})();
