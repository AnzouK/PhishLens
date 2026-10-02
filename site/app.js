// PhishLens site: server status, live counters and the "try it" form.
// No cookies, no storage, no third-party scripts. The only external call
// is GitHub's public API for the latest version number.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (n) => Number(n || 0).toLocaleString("en-US");
  const pct = (v) => Math.round((Number(v) || 0) * 100);
  // Same-origin on the real site; PhishLens Cloud when the page is opened
  // elsewhere (local preview), which the server allows (CORS).
  const API = location.hostname === "anzouk.duckdns.org" ? "" : "https://anzouk.duckdns.org";

  // ---------- server status ----------
  const status = $("status");
  const setDot = (up) => { $("live-dot").className = `dot ${up ? "dot--up" : "dot--down"}`; };
  fetch(API + "/health", { cache: "no-store" })
    .then((r) => { if (!r.ok) throw new Error(); })
    .then(() => { status.innerHTML = '<span class="dot dot--up"></span> server online'; setDot(true); })
    .catch(() => { status.innerHTML = '<span class="dot dot--down"></span> server unreachable right now'; setDot(false); });

  fetch("https://api.github.com/repos/AnzouK/PhishLens/releases/latest")
    .then((r) => (r.ok ? r.json() : Promise.reject()))
    .then((d) => { if (d.tag_name) $("version").textContent = ` · version ${d.tag_name.replace(/^v/, "")}`; })
    .catch(() => {});

  // ---------- live counters, as big numbers ----------
  const cell = (big, lbl, off) => `<div class="cell"><div class="big${off ? " off" : ""}">${esc(big)}</div><div class="lbl">${esc(lbl)}</div></div>`;
  fetch(API + "/reputation/stats", { cache: "no-store" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
    .then((d) => {
      if (d.enabled === false) throw new Error("threat intelligence is off on this server");
      const c = d.cache || {}, g = d.gsb || {}, p = d.phishtank || {}, u = d.urlhaus || {};
      $("live").innerHTML =
        (g.enabled === false ? cell("Off", "Google Safe Browsing", true)
                             : cell(num(g.remaining), `Safe Browsing lookups left today (of ${num(g.limit)})`))
        + cell(num((c.hits || 0) + (c.misses || 0)), `links checked since the last restart, ${pct(c.hit_rate)}% from cache`)
        + (p.enabled === false || !p.phishtank_entries ? cell("Off", "PhishTank feed", true)
                                                       : cell(num(p.phishtank_entries), "known phishing URLs (PhishTank)"))
        + (u.enabled ? cell("On", "URLhaus malware-URL lookups") : cell("Off", "URLhaus", true));
    })
    .catch((e) => { $("live").innerHTML = cell("Unavailable", e.message || "server unreachable", true); });

  // ---------- try-it form ----------
  const form = $("demo-form");
  const text = $("demo-text"), file = $("demo-file");
  const textErr = $("demo-text-error"), fileErr = $("demo-file-error");
  const submit = $("demo-submit"), out = $("demo-result"), drop = $("drop-zone");
  const MAX_FILE = 10 * 1024 * 1024;
  const ATTACHMENT_EXTS = new Set(["pdf", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "docx", "docm", "doc",
                                   "xlsx", "xlsm", "xls", "pptx", "pptm", "ppt", "zip", "ics", "txt"]);
  const SAMPLES = {
    phish: "Dear customer,\n\nWe were unable to process your last payment and your account has been suspended. To avoid permanent closure, verify your billing details within 24 hours:\n\nhttp://secure-billing-verify.tk/login?id=48213\n\nFailure to act immediately will result in the loss of all your files.\n\nBilling Department",
    safe: "Hi team,\n\nThe sprint review moved to Thursday at 3pm, same room. I added the agenda to the shared document; please add your items before Wednesday evening.\n\nThanks,\nAmina",
  };
  let mode = "text", chosen = null, lastSubmit = 0;

  function clearErrors() {
    for (const [el, msg] of [[text, textErr], [drop, fileErr]]) { el.removeAttribute("aria-invalid"); msg.textContent = ""; }
  }
  function fail(el, msg, message) {
    el.setAttribute("aria-invalid", "true");
    msg.textContent = message;
    (el === drop ? file : el).focus();
    return null;
  }

  // tabs
  document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
    mode = tab.id === "tab-file" ? "file" : "text";
    document.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", String(t === tab)));
    $("pane-text").hidden = mode !== "text";
    $("pane-file").hidden = mode !== "file";
    clearErrors();
  }));

  // examples and clipboard
  form.querySelectorAll("[data-sample]").forEach((b) => b.addEventListener("click", () => {
    text.value = SAMPLES[b.dataset.sample]; clearErrors(); text.focus();
  }));
  $("paste-btn").addEventListener("click", async () => {
    try {
      const clip = await navigator.clipboard.readText();
      if (!clip.trim()) return fail(text, textErr, "The clipboard is empty.");
      text.value = clip.slice(0, 20000); clearErrors(); text.focus();
    } catch {
      fail(text, textErr, "The browser blocked clipboard access: paste with Ctrl + V (Cmd + V on a Mac) instead.");
    }
  });
  text.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); form.requestSubmit(); }
  });

  // file: click or drag and drop
  const setFile = (f) => {
    chosen = f || null; clearErrors();
    $("drop-title").textContent = chosen ? `${chosen.name} (${Math.max(1, Math.round(chosen.size / 1024))} KB)` : "Drop a file here, or click to choose one";
  };
  file.addEventListener("change", () => setFile(file.files[0]));
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("drop--over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("drop--over"); }));
  drop.addEventListener("drop", (e) => setFile(e.dataTransfer?.files?.[0]));

  function validate() {
    clearErrors();
    if (mode === "text") {
      const v = text.value.trim();
      if (v.length < 20) return fail(text, textErr, "Paste at least 20 characters of the email.");
      if (v.length > 20000) return fail(text, textErr, "That is more than 20,000 characters; paste the body only.");
      return { endpoint: "/analyse", body: { raw_text: v } };
    }
    if (!chosen) return fail(drop, fileErr, "Choose or drop a file first.");
    if (chosen.size > MAX_FILE) return fail(drop, fileErr, `The file is ${(chosen.size / 1048576).toFixed(1)} MB; the limit is 10 MB.`);
    const ext = (chosen.name.split(".").pop() || "").toLowerCase();
    if (ext !== "eml" && !ATTACHMENT_EXTS.has(ext)) return fail(drop, fileErr, "This file type is not supported.");
    return { file: chosen, ext };
  }

  const toB64 = (f) => new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => { const s = String(r.result || ""); res(s.slice(s.indexOf(",") + 1)); };
    r.onerror = () => rej(new Error("Could not read the file."));
    r.readAsDataURL(f);
  });

  function meter(label, v) {
    const p = pct(v), cls = p >= 70 ? " meter__fill--high" : p >= 40 ? " meter__fill--mid" : "";
    return `<div class="meter"><span>${label}</span><span class="meter__track"><span class="meter__fill${cls}" data-w="${p}"></span></span><span class="meter__v">${p}%</span></div>`;
  }

  function render(d, isEmail) {
    const bad = d.verdict === "phishing";
    const tags = [];
    const sa = d.sender_auth || {};
    if (d.trusted_sender) tags.push(["good", "Trusted sender"]);
    else if (sa.cryptographically_verified) tags.push(["good", "DKIM verified"]);
    for (const k of ["spf", "dkim", "dmarc"]) if (sa[k] === "fail") tags.push(["bad", `${k.toUpperCase()} fail`]);
    (d.url_reputation?.sources_hit || []).forEach((s) => tags.push(["bad", `Flagged by ${s.replace(/_/g, " ")}`]));
    if (d.forwarded?.detected) tags.push(["warn", "Forwarded email"]);
    if (d.shared_links?.count) tags.push(["warn", `Shared file: ${(d.shared_links.services || []).join(", ")}`]);
    const a = d.attachment;
    if (a) (a.notable_features || []).forEach((f) => tags.push(["warn", f.replace(/_/g, " ")]));
    out.innerHTML = `
      <p class="verdict verdict--${bad ? "bad" : "good"}"><svg class="ic"><use href="#i-shield"/></svg>${bad ? "Looks like phishing" : "Looks safe"}</p>
      <p class="small muted">Overall score ${pct(d.fused_score)}%.</p>
      ${meter("Wording", d.agents?.text?.phishing_probability)}
      ${meter("Links", d.agents?.url?.phishing_probability)}
      ${a ? "" : meter("Sender", d.agents?.metadata?.phishing_probability)}
      ${tags.length ? `<ul class="tags">${tags.map(([c, t]) => `<li class="${c}">${esc(t)}</li>`).join("")}</ul>` : ""}
      ${isEmail ? '<h3>Words that weighed most</h3><p class="small muted">Red pushed toward phishing, green toward safe.</p><div id="lime" class="status"><span class="spinner" aria-hidden="true"></span> computing</div>' : ""}`;
    out.querySelectorAll(".meter__fill").forEach((el) => { el.style.width = `${el.dataset.w}%`; });
  }

  function renderLime(features) {
    const slot = $("lime");
    if (!slot) return;
    features = (features || []).filter((f) => String(f.token || "").length > 2 && !/^\d+$/.test(f.token));
    if (!features.length) { slot.textContent = "No word stood out for this one."; return; }
    const max = Math.max(...features.map((f) => Math.abs(f.weight))) || 1;
    slot.className = "";
    slot.innerHTML = features.map((f) =>
      `<span class="tok ${f.supports === "phishing" ? "tok--p" : "tok--s"}" data-a="${(0.15 + (Math.abs(f.weight) / max) * 0.45).toFixed(2)}">${esc(f.token)}</span>`).join("");
    slot.querySelectorAll(".tok").forEach((el) => el.style.setProperty("--a", el.dataset.a));
  }

  function showError(title, message) {
    out.innerHTML = `<p class="verdict verdict--bad">${esc(title)}</p><p class="muted">${esc(message)}</p>`;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if ($("website").value) return;                    // honeypot filled: a bot
    const now = Date.now();
    if (now - lastSubmit < 4000) return;               // one check every few seconds
    const v = validate();
    if (!v) return;
    lastSubmit = now;

    let endpoint = v.endpoint, body = v.body;
    if (v.file) {
      try {
        const b64 = await toB64(v.file);
        if (v.ext === "eml") { endpoint = "/analyse"; body = { raw_email_b64: b64 }; }
        else { endpoint = "/analyse_attachment"; body = { content_b64: b64, filename: v.file.name, mime_type: v.file.type || null }; }
      } catch (err) { return fail(drop, fileErr, err.message); }
    }

    submit.disabled = true;
    submit.innerHTML = '<span class="spinner" aria-hidden="true"></span> Checking…';
    out.innerHTML = '<p class="status"><span class="spinner" aria-hidden="true"></span> analysing; the first check after a quiet period can take a few seconds</p>';
    try {
      const r = await fetch(API + endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await r.json().catch(() => ({}));
      if (r.status === 429) throw new Error("Too many checks from your network. Try again in a minute.");
      if (!r.ok) throw new Error(d.detail || `The server answered ${r.status}.`);
      const isEmail = endpoint === "/analyse";
      render(d, isEmail);
      if (isEmail && d.text_agent_used !== false) {
        fetch(API + "/explain", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
          .then((x) => (x.ok ? x.json() : Promise.reject(new Error(`HTTP ${x.status}`))))
          .then((x) => renderLime(x.features))
          .catch(() => { const s = $("lime"); if (s) s.textContent = "Explanation unavailable right now."; });
      } else if (isEmail) {
        const s = $("lime"); if (s) s.textContent = "Too little text to explain; the verdict rests on the links and sender.";
      }
    } catch (err) {
      showError("The check failed", err.message || String(err));
    } finally {
      submit.disabled = false;
      submit.textContent = "Check this email";
    }
  });
})();
