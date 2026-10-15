// PhishLens site: on an English page, offer the visitor's own language
// when the site has it (from the browser's language settings). A link,
// never a redirect, so English stays one click away and nothing is stored.
(() => {
  "use strict";
  const SITE = window.PhishLensSite;
  if (!SITE || SITE.lang !== "en") return;
  const wanted = (navigator.languages || [navigator.language || ""])
    .map((l) => String(l).slice(0, 2).toLowerCase())
    .find((l) => l === "en" || SITE.langs[l]);
  if (!wanted || wanted === "en") return;
  const page = location.pathname.split("/").pop();
  const bar = document.createElement("p");
  bar.className = "lang-suggest";
  bar.lang = wanted;
  const a = document.createElement("a");
  a.href = SITE.langs[wanted].path + (page === "index.html" ? "" : page);
  a.hreflang = wanted;
  a.textContent = SITE.suggest[wanted];
  bar.append(a);
  document.querySelector(".site-head")?.after(bar);
})();
