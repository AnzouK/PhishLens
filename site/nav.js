// The header slides away while scrolling down and comes back on any
// scroll up; a "back to top" button appears once the page is scrolled.
(() => {
  "use strict";
  const head = document.querySelector(".site-head");
  const t = (window.PhishLensSite && window.PhishLensSite.t) || {};
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");

  const top = document.createElement("button");
  top.type = "button";
  top.className = "to-top";
  top.textContent = t.js_to_top || "Back to top";
  top.addEventListener("click", () => {
    window.scrollTo({ top: 0, behavior: reduce.matches ? "auto" : "smooth" });
    document.querySelector(".brand")?.focus({ preventScroll: true });
  });
  document.body.append(top);

  let last = window.scrollY;
  let queued = false;
  const update = () => {
    queued = false;
    const y = window.scrollY;
    const menuOpen = head?.querySelector(".lang-menu[open]");
    if (head) head.classList.toggle("is-hidden", y > last && y > head.offsetHeight && !menuOpen);
    top.classList.toggle("is-visible", y > window.innerHeight);
    last = y;
  };
  window.addEventListener("scroll", () => {
    if (!queued) { queued = true; window.requestAnimationFrame(update); }
  }, { passive: true });
  // A keyboard user tabbing into the hidden header gets it back.
  head?.addEventListener("focusin", () => head.classList.remove("is-hidden"));
  update();
})();
