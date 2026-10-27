"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { Node, makeDocument } = require("./fake_dom");
const { loadLib } = require("./helpers");

globalThis.document = makeDocument();
globalThis.Node = Node;
const { h, icon } = loadLib("dom.js");
const C = loadLib("constants.js");

test("h() builds elements with classes, attributes, styles and children", () => {
    let clicked = 0;
    const el = h("span.badge.badge--good", {
        class: "extra", title: "a \"title\"", dataset: { id: "7" }, style: { "--a": "0.30", width: "50%" },
        hidden: false, onclick: () => clicked++,
    }, "text ", h("strong", null, "bold"), null, false, ["a", "b"]);
    assert.equal(el.className, "badge badge--good extra");
    assert.equal(el.getAttribute("title"), 'a "title"');
    assert.equal(el.getAttribute("hidden"), null);
    assert.equal(el.dataset.id, "7");
    assert.equal(el.style.getPropertyValue("--a"), "0.30");
    assert.equal(el.textContent, "text boldab");
    el.dispatch("click");
    assert.equal(clicked, 1);
});

test("markup in a text child stays text", () => {
    const el = h("div", null, '<img src=x onerror="alert(1)">');
    assert.equal(el.children.length, 0);
    assert.equal(el.textContent, '<img src=x onerror="alert(1)">');
});

test("icons are SVG elements", () => {
    const svg = icon("shieldCheck");
    assert.equal(svg.namespaceURI, "http://www.w3.org/2000/svg");
    assert.equal(svg.children.length, 2);
});

test("the popup and Gmail agree on the attachment types", () => {
    assert.ok(C.ATTACHMENT_EXTS.includes("docm"));
    assert.ok(!C.ATTACHMENT_EXTS.includes("eml"));
    assert.equal(C.fileExt("Invoice.PDF"), "pdf");
    assert.equal(C.fileExt("README"), "");
    assert.equal(C.isCaution(["contains_macros", "encrypted_archive"]), true);
    assert.equal(C.isCaution(["contains_macros"]), false);
});
