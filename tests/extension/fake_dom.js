// A small stand-in for the DOM, enough for lib/dom.js and the banners:
// elements with attributes, classes, children, text and listeners. No
// HTML parser on purpose: nothing in the extension should need one.
"use strict";

class Node {
    constructor(nodeType) {
        this.nodeType = nodeType;
        this.parentNode = null;
        this.childNodes = [];
    }
    get parentElement() { return this.parentNode; }
    remove() {
        if (!this.parentNode) return;
        const list = this.parentNode.childNodes;
        list.splice(list.indexOf(this), 1);
        this.parentNode = null;
    }
}

class Text extends Node {
    constructor(text) {
        super(3);
        this.data = String(text);
    }
    get textContent() { return this.data; }
}

class Element extends Node {
    constructor(tagName, namespaceURI = null) {
        super(1);
        this.tagName = tagName.toUpperCase();
        this.namespaceURI = namespaceURI;
        this.attributes = {};
        this.dataset = {};
        this.listeners = {};
        const props = {};
        this.style = {
            setProperty: (k, v) => { props[k] = String(v); },
            getPropertyValue: (k) => props[k] || "",
        };
        this.classList = {
            contains: (c) => (this.attributes.class || "").split(/\s+/).includes(c),
            add: (c) => { if (!this.classList.contains(c)) this.className = `${this.className} ${c}`.trim(); },
            toggle: (c, on) => {
                const has = this.classList.contains(c);
                if (on ?? !has) this.classList.add(c);
                else this.className = this.className.split(/\s+/).filter((x) => x !== c).join(" ");
            },
        };
    }
    get className() { return this.attributes.class || ""; }
    set className(v) { this.attributes.class = String(v); }
    get id() { return this.attributes.id || ""; }
    set id(v) { this.attributes.id = String(v); }
    get children() { return this.childNodes.filter((n) => n.nodeType === 1); }
    get childElementCount() { return this.children.length; }
    get nextElementSibling() {
        const siblings = this.parentNode?.children || [];
        return siblings[siblings.indexOf(this) + 1] || null;
    }
    // Leaves out what banner.css hides ([data-pll-hidden]).
    get innerText() {
        if ("data-pll-hidden" in this.attributes) return "";
        return this.childNodes.map((c) => (c.nodeType === 3 ? c.data : c.innerText)).join("");
    }
    removeAttribute(k) { delete this.attributes[k]; }
    // Laid out by default; a test hides an element by replacing these.
    getClientRects() { return [{ width: 10, height: 10 }]; }
    getBoundingClientRect() { return { width: 10, height: 10 }; }
    getRootNode() {
        let n = this;
        while (n.parentNode) n = n.parentNode;
        return n;
    }
    contains(n) {
        for (; n; n = n.parentNode) if (n === this) return true;
        return false;
    }
    setAttribute(k, v) { this.attributes[k] = String(v); }
    getAttribute(k) { return k in this.attributes ? this.attributes[k] : null; }
    addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
    dispatch(type, ev = {}) { (this.listeners[type] || []).forEach((fn) => fn(ev)); }
    append(...nodes) {
        for (const n of nodes) {
            const node = typeof n === "string" ? new Text(n) : n;
            node.remove();
            node.parentNode = this;
            this.childNodes.push(node);
        }
    }
    appendChild(n) { this.append(n); return n; }
    prepend(n) { this.append(n); this.childNodes.unshift(this.childNodes.pop()); }
    insertBefore(n, ref) {
        this.append(n);
        const i = this.childNodes.indexOf(ref);
        if (i >= 0) this.childNodes.splice(i, 0, this.childNodes.pop());
        return n;
    }
    replaceChildren(...nodes) {
        [...this.childNodes].forEach((c) => c.remove());
        this.append(...nodes);
    }
    get textContent() { return this.childNodes.map((c) => c.textContent).join(""); }
    set textContent(v) { this.replaceChildren(String(v)); }
    // Selectors: "tag", ".class", "tag.class", "tag[attr]", "*", lists and
    // descendant combinators only, enough for tests.
    matchesCompound(one) {
        if (one === "*") return true;
        // "a[href]": attribute presence (an attribute or a property set).
        const attrs = [...one.matchAll(/\[([\w-]+)\]/g)].map((m) => m[1]);
        if (attrs.some((a) => !(a in this.attributes) && this[a] == null)) return false;
        one = one.replace(/\[[\w-]+\]/g, "");
        const [tag, ...classes] = one.split(".");
        return (!tag || this.tagName === tag.toUpperCase()) && classes.every((c) => this.classList.contains(c));
    }
    matches(sel) {
        return sel.split(",").some((complex) => {
            const parts = complex.trim().replace(/^:scope\s*>\s*/, "").split(/\s+/);
            if (!this.matchesCompound(parts.pop())) return false;
            let n = this.parentNode;
            for (let i = parts.length - 1; i >= 0; i--) {
                while (n && !n.matchesCompound?.(parts[i])) n = n.parentNode;
                if (!n) return false;
                n = n.parentNode;
            }
            return true;
        });
    }
    querySelectorAll(sel) {
        const out = [];
        const walk = (n) => n.children.forEach((c) => { if (c.matches(sel)) out.push(c); walk(c); });
        walk(this);
        return out;
    }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
    closest(sel) {
        for (let n = this; n; n = n.parentNode) if (n.matches?.(sel)) return n;
        return null;
    }
    // Every text of the subtree, attributes included: what a test checks
    // for leaked markup.
    dump() {
        const attrs = Object.entries(this.attributes).map(([k, v]) => ` ${k}="${v}"`).join("");
        return `<${this.tagName.toLowerCase()}${attrs}>` +
            this.childNodes.map((c) => (c.nodeType === 3 ? `[${c.data}]` : c.dump())).join("") + "</>";
    }
}

function makeDocument() {
    const body = new Element("body");
    return {
        body,
        documentElement: new Element("html"),
        scripts: [],
        title: "",
        createElement: (tag) => new Element(tag),
        createElementNS: (ns, tag) => new Element(tag, ns),
        createTextNode: (text) => new Text(text),
        querySelectorAll: (sel) => body.querySelectorAll(sel),
        querySelector: (sel) => body.querySelector(sel),
        getElementById: (id) => body.querySelectorAll("*").find((e) => e.id === id) || null,
    };
}

module.exports = { Node, Text, Element, makeDocument };
