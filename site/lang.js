// PhishLens site: on an English page, offer the visitor's own language
// when the site has it, based on the browser's language settings. It is a
// link and never a redirect, so English stays one click away. Closing the
// bar or picking a language is remembered in localStorage so the bar
// doesn't come back.
(() => {
  "use strict";
  const KEY = "phishlens.langSuggest";
  const PAGES = new Set(["", "index", "privacy", "terms"]);
  const remember = () => {
    try {
      localStorage.setItem(KEY, "done");
    } catch {
      // Storage is blocked (private mode or settings), so the bar may come back.
    }
  };
  const answered = () => {
    try {
      return localStorage.getItem(KEY) === "done";
    } catch {
      return false;
    }
  };
  // A language picked from the header menu, on any page, is an answer too.
  for (const a of document.querySelectorAll(".lang-menu a")) a.addEventListener("click", remember);

  const SITE = window.PhishLensSite;
  if (!SITE || SITE.lang !== "en" || answered()) return;
  const wanted = (navigator.languages || [navigator.language || ""])
    .map((l) => String(l).slice(0, 2).toLowerCase())
    .find((l) => l === "en" || SITE.langs[l]);
  if (!wanted || wanted === "en") return;
  // Pages serves privacy.html at /privacy, so link without .html.
  const page = location.pathname.split("/").pop().replace(/\.html$/, "");
  // Only pages that exist in every language. The 404 page (served at any
  // address) and other noindex pages get no suggestion.
  if (!PAGES.has(page) || document.querySelector('meta[name="robots"][content*="noindex"]')) return;
  const bar = document.createElement("p");
  bar.className = "lang-suggest";
  bar.lang = wanted;
  const a = document.createElement("a");
  a.href = SITE.langs[wanted].path + (page === "index" ? "" : page);
  a.hreflang = wanted;
  a.textContent = SITE.suggest[wanted];
  a.addEventListener("click", remember);
  const close = document.createElement("button");
  close.type = "button";
  close.className = "lang-suggest__close";
  close.setAttribute("aria-label", (SITE.suggestDismiss || {})[wanted] || "Close");
  close.textContent = "×";
  close.addEventListener("click", () => {
    remember();
    bar.remove();
    // The focused button is gone, so move focus back to the top of the page.
    document.querySelector(".brand")?.focus({ preventScroll: true });
  });
  bar.append(a, close);
  document.querySelector(".site-head")?.after(bar);
})();
