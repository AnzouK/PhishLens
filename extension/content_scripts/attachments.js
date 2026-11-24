// Gmail attachments. Each email gets one "Scan attachments" button; each
// file is downloaded from the same origin, so Gmail's session cookie goes
// with it, and gets a result card below the attachment strip.
(function () {
"use strict";

const PL = globalThis.PhishLensPage;
const { t, tn, flagLabel, reasonLabel } = PhishLensI18n;
const { h, icon } = PhishLensDom;
const { ATTACHMENT_EXTS, DANGEROUS_EXTS, MAX_FILE_MB, SOURCE_LABELS, fileExt, isCaution } = PhishLensConstants;
const { debug } = PhishLensShared;
const G = PhishLensGmail;
const { SEL } = G;

const MAX_PER_EMAIL = 15;
// An attached email is scanned as an email and everything else as an
// attachment, including programs, scripts and disk images, which the
// server flags by type.
const SUPPORTED = new Set([...ATTACHMENT_EXTS, ...DANGEROUS_EXTS, "eml"]);
// The size Gmail writes after a tile's name ("Checklist.pdf 320 KB",
// "Facture.pdf 1,2 Mo", "scan.png 500 octets"). Only the size is removed.
// The name itself is kept whole, in any script and with any character
// ("Facture_février [1].pdf", "scan.jpg   .js", "invoice.exe .").
const TRAILING_SIZE_RE = /\s+\d+(?:[.,]\d+)?\s*(?:[KMGT]i?B|[KMGT]o|B|o|bytes?|octets?|[КМГТ]?Б)\s*$/iu;

// A tile's text as a file name, with only the size cut. Characters that
// reorder a name are kept for the server's checks and for safeName, and
// fileExt reads past invisible ones.
function tileName(text) {
    return String(text || "").trim().replace(TRAILING_SIZE_RE, "").trim();
}
PL.tileName = tileName;
// Ways Gmail has marked an attachment tile. They are only looked up inside
// a strip, because stray matches elsewhere put buttons over the message
// body.
const TILE_HINTS = ['a[download]', 'div[data-attachmentid]', 'div[data-tooltip*="oad"]', 'div[role="listitem"]', ".aZo"];
const hooked = new WeakSet();

PL.installAttachmentButtons = function installAttachmentButtons(emailView) {
    if (!emailView || !PL.alive()) return;
    const strips = emailView.querySelectorAll(SEL.attachmentStrip);
    if (!strips.length) return;

    const candidates = new Set();
    strips.forEach((strip) => {
        for (const sel of TILE_HINTS) strip.querySelectorAll(sel).forEach((el) => candidates.add(el));
        // Newer layouts may match none of the hints, so fall back to any
        // element whose text ends with a supported extension.
        strip.querySelectorAll("span, div").forEach((el) => {
            const label = tileName(el.textContent);
            if (label.length > 3 && label.length < 260 && SUPPORTED.has(fileExt(label))) candidates.add(el);
        });
    });

    const found = [];
    const seen = new Set();
    candidates.forEach((el) => {
        const strip = el.closest(SEL.attachmentStrip);
        const tile = strip && findTile(el, strip);
        if (!tile || hooked.has(tile) || seen.has(tile) || !strip.contains(tile) || tile.dataset.pllScanned === "1") return;
        seen.add(tile);
        // A real tile is roughly 100x80 to 350x280 px. Anything smaller is
        // a stray hit and anything much bigger a container.
        const r = tile.getBoundingClientRect();
        if (r.width < 80 || r.height < 60 || r.width > 400 || r.height > 400) return;
        const info = attachmentInfo(tile);
        if (!info) return;
        if (!SUPPORTED.has(info.ext)) {
            // Unreadable types are only reported for certain tiles.
            if (!tile.matches?.(".aZo, [data-attachmentid]") && !tile.querySelector("a[download]")) return;
            info.unsupported = true;
        }
        hooked.add(tile);
        found.push({ tile, ...info, emailView });
    });

    if (!found.some((f) => !f.unsupported)) {
        found.forEach(renderNotice);
        return;
    }
    installScanAllButton(emailView, found);
};

// The tile around `node`. The walk stops at the strip because Gmail also
// marks whole messages role="listitem" in a conversation.
function findTile(node, strip) {
    for (const selector of [SEL.attachmentTile, '[role="listitem"]']) {
        for (let cur = node; cur && cur !== strip && cur !== document.body; cur = cur.parentElement) {
            if (cur.matches?.(selector)) return cur;
        }
    }
    return node !== strip ? node : null;
}

// File name, extension and download link of a tile, or null.
function attachmentInfo(tile) {
    const dlAnchor = tile.querySelector("a[download]");
    const filename = tileName(dlAnchor?.getAttribute("download")
        || tile.querySelector(SEL.attachmentName)?.textContent
        || (tile.textContent || "").trim().split("\n")[0]);
    if (!filename || filename.length > 260) return null;
    const ext = fileExt(filename);
    if (!ext) return null;
    const anchor = dlAnchor
        || tile.querySelector('a[href*="&view=att"], a[href*="ui=2"]')
        || tile.querySelector("a[href]");
    return { filename, ext, anchor };
}

const scanLabel = (n) => (n > 1 ? t("att_scan_n", { count: n }) : t("att_scan_single"));

function installScanAllButton(emailView, targets) {
    let existing = emailView.querySelector(".pll-scan-btn--all");
    // A button left by an older copy of the scripts, or one whose scan has
    // ended (shown 2.5 s more, then removed), gets no new tiles: a new
    // button takes them.
    if (existing && (existing.dataset.pllInstance !== PL.instance || existing.dataset.pllDone === "1")) {
        existing.remove();
        existing = null;
    }
    if (existing) {
        // More tiles were lazy-loaded since. Add them to the ones still on
        // the page and not scanned yet (hooked tiles are not found again).
        const kept = (existing._pllTargets || []).filter((f) =>
            !targets.includes(f) && f.tile?.isConnected && f.tile.dataset.pllScanned !== "1");
        existing._pllTargets = kept.concat(targets);
        if (!existing.disabled) {
            existing.querySelector(".pll-scan-btn__label").textContent = scanLabel(existing._pllTargets.length);
        }
        return;
    }
    const wrap = emailView.querySelector(SEL.subject)?.parentElement;
    if (!wrap) return;
    const btn = PL.scanButton({
        extraClass: "pll-scan-btn--all",
        iconName: "clip",
        label: scanLabel(targets.length),
        onClick: () => scanAll(btn),
    });
    btn.dataset.pllInstance = PL.instance;
    btn._pllTargets = targets;
    wrap.appendChild(btn);
}

async function scanAll(btn) {
    // Disabled at once: a second click while the privacy notice is open
    // would open a second notice and start a second scan.
    if (btn.disabled) return;
    btn.disabled = true;
    const view = (btn._pllTargets || [])[0]?.emailView;
    const stop = () => {
        btn.disabled = false;
    };
    if (view && !(await PL.confirmCloudUse(view))) return stop();
    // Read after the notice: tiles Gmail loaded meanwhile are counted.
    const targets = btn._pllTargets || [];
    if (targets.length >= 5 && !confirm(t("att_confirm_many", { count: targets.length }))) return stop();
    if (targets.length > MAX_PER_EMAIL) {
        alert(t("att_too_many", { count: targets.length, max: MAX_PER_EMAIL }));
        return stop();
    }
    const label = btn.querySelector(".pll-scan-btn__label");
    // Read from btn._pllTargets at each step: tiles Gmail loads during the
    // scan are added there (installScanAllButton) and scanned in the same
    // run, up to MAX_PER_EMAIL in all.
    const done = new Set();
    for (;;) {
        const pending = (btn._pllTargets || []).filter((f) => !done.has(f));
        if (!pending.length || done.size >= MAX_PER_EMAIL) break;
        const n = done.size + pending.length;
        label.textContent = n > 1 ? t("att_scanning_progress", { i: done.size + 1, n }) : t("scanning");
        done.add(pending[0]);
        // scanAttachment shows its own errors in the file's card.
        await scanAttachment(pending[0]);
    }
    btn.dataset.pllDone = "1";
    label.textContent = t("att_done");
    setTimeout(() => btn.remove(), 2500);
}

// The cards go in a container after the whole strip, since Gmail's layout
// mangles them inside a tile (styles in .pll-att-stack, banner.css).
function bannerStack(tile, emailView) {
    const strip = tile?.closest(SEL.attachmentStrip) || emailView.querySelector(SEL.attachmentStrip);
    const anchor = strip || emailView.querySelector(SEL.body) || emailView;
    const parent = anchor.parentElement || emailView;
    let stack = parent.querySelector(":scope > .pll-att-stack");
    if (!stack) {
        stack = h("div.pll-att-stack");
        anchor.insertAdjacentElement("afterend", stack);
    }
    return stack;
}

// One card per attachment tile (or per target when Gmail gave no tile),
// updated on a new scan. Cards are not keyed by file name, because two
// names such as "invoice.pdf" and "invoice .pdf" could share a card and
// the last verdict would replace the other (a phishing result shown as
// safe).
const cards = new WeakMap();

function cardFor(target) {
    const { tile, emailView } = target;
    const key = tile || target;
    let card = cards.get(key);
    if (!card || !card.isConnected) {
        card = h("div.pll-att-banner");
        bannerStack(tile, emailView).appendChild(card);
        cards.set(key, card);
    }
    return card;
}
PL.attachmentCardFor = cardFor;

function cardHead(iconName, title, filename, spin = false) {
    return h("div.pll-att-banner__row", null,
        h(`span.pll-att-banner__icon${spin ? ".pll-spin" : ""}`, null, icon(iconName)),
        h("div.pll-att-banner__main", null,
            h("div.pll-att-banner__title", { title: PhishLensShared.safeName(filename) }, title),
            h("div.pll-att-banner__file", { title: PhishLensShared.safeName(filename) }, PhishLensShared.safeName(filename))));
}

function setCard(card, state, ...children) {
    card.className = `pll-att-banner pll-att-banner--${state}`;
    card.replaceChildren(...children.filter(Boolean));
}

// For a file PhishLens cannot read, say that it was not checked instead
// of showing nothing.
function renderNotice(target) {
    const { filename, tile } = target;
    const card = cardFor(target);
    if (card.childElementCount) return;
    setCard(card, "error", cardHead("alert", t("att_not_checked"), filename),
        h("div.pll-att-banner__sub", null, t("att_not_checked_sub")));
    if (tile) tile.dataset.pllScanned = "1";
}

// Gmail adds the download link on hover, so the tile is hovered when the
// link is missing.
async function downloadUrl(anchor, tile) {
    if (anchor?.href) return anchor.href;
    if (!tile) return "";
    tile.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 200));
    return tile.querySelector("a[download], a[href*='view=att']")?.href || "";
}

async function download(anchor, tile) {
    const url = await downloadUrl(anchor, tile);
    if (!url) throw new Error(t("att_err_no_url"));
    // The session cookie goes only to Gmail's own download links, never to
    // an address found elsewhere in the tile.
    if (new URL(url, location.href).origin !== location.origin) throw new Error(t("att_err_no_url"));
    const resp = await fetch(url, { credentials: "include" });
    if (!resp.ok) throw new Error(t("att_err_download", { status: resp.status }));
    // A file too large by its announced size is not downloaded at all.
    const announced = Number(resp.headers?.get?.("content-length")) || 0;
    if (announced > MAX_FILE_MB * 1024 * 1024) {
        resp.body?.cancel?.().catch?.(() => {});
        throw new Error(t("att_err_too_large", { size: (announced / 1024 / 1024).toFixed(1), max: MAX_FILE_MB }));
    }
    const buf = await resp.arrayBuffer();
    if (buf.byteLength > MAX_FILE_MB * 1024 * 1024) {
        throw new Error(t("att_err_too_large", { size: (buf.byteLength / 1024 / 1024).toFixed(1), max: MAX_FILE_MB }));
    }
    return PL.bytesToBase64(new Uint8Array(buf));
}

async function scanAttachment(target) {
    const { anchor, filename, ext, tile, emailView, unsupported } = target;
    if (unsupported) {
        renderNotice(target);
        return;
    }
    const card = cardFor(target);
    setCard(card, "loading", cardHead("spinner", t("scanning"), filename, true));
    try {
        const b64 = await download(anchor, tile);
        const senderEl = emailView.querySelector(SEL.sender);
        const data = ext === "eml"
            // An attached email's headers, Authentication-Results included,
            // were written by whoever attached it and prove nothing.
            ? await PhishLensApi.analyse({ raw_email_b64: b64, client_context: { headers_source: "attachment" } })
            : await PhishLensApi.analyseAttachment({
                content_b64: b64,
                filename,
                mime_type: null,          // the server reads the real type from the bytes
                parent_email: {
                    sender_email: senderEl?.getAttribute("email") || null,
                    subject: emailView.querySelector(SEL.subject)?.textContent?.trim() || null,
                    // Outside Spam, Gmail's own checks passed, so the server
                    // scores the attachment with the parent's trust.
                    gmail_delivered: G.inInbox(location.hash),
                },
            });
        renderResult(card, data, filename);
        if (tile) tile.dataset.pllScanned = "1";
        PL.saveScan(data, {
            source: "gmail-attachment", subject: filename,
            sender: senderEl?.getAttribute("email") || senderEl?.textContent?.trim() || "",
        });
    } catch (e) {
        debug("attachment scan", e);
        setCard(card, "error", cardHead("alert", t("att_could_not_scan"), filename),
            h("div.pll-att-banner__sub", null, e.message || String(e)),
            h("button.pll-att-btn", { type: "button", onclick: () => scanAttachment(target) }, t("retry")));
    }
}

function renderResult(card, data, filename) {
    const bad = data.verdict === "phishing";
    const a = data.attachment || {};
    const flags = a.notable_features || [];
    // Same rule as the email banner and the popup: a safe verdict next to
    // a high score, a flagged link or a warning flag (orange chip) is
    // shown with caution (PhishLensShared.displayVerdict).
    const caution = PhishLensShared.displayVerdict(data) === "caution";
    const notRead = caution && isCaution(flags);
    const isEmail = !data.attachment && !!data.agents?.metadata;   // an attached .eml
    const pct = (v) => Math.round((Number(v) || 0) * 100);
    const meta = [
        isEmail ? t("att_kind_email") : a.kind ? a.kind.toUpperCase() : "",
        a.size_bytes ? t("att_size_kb", { size: (a.size_bytes / 1024).toFixed(0) }) : "",
        a.page_count ? t("att_pages", { read: a.pages_read || a.page_count, total: a.page_count }) : "",
        a.entry_count ? tn("att_files_inside", a.entry_count) : "",
        a.organizer ? t("att_from", { organizer: a.organizer }) : "",
        a.extracted_urls_count ? tn("att_urls", a.extracted_urls_count) : "",
    ].filter(Boolean).join(" · ");
    const score = (label, value) => [`${label} `, h("strong", null, `${pct(value)}%`)];
    const chips = [
        data.parent_trusted && h("span.pll-att-chip.pll-att-chip--good", { title: t("att_trusted_email_title") }, t("att_trusted_email")),
        ...flags.map((f) => h(`span.pll-att-chip${PhishLensShared.isWarningFlag(f) ? ".pll-att-chip--warn" : ""}`, null, flagLabel(f))),
        ...(data.url_reputation?.sources_hit || []).map((s) => h("span.pll-att-chip.pll-att-chip--bad", null, SOURCE_LABELS[s] || s)),
    ].filter(Boolean);

    setCard(card, bad ? "danger" : caution ? "caution" : "safe",
        cardHead(bad || caution ? "alert" : "shieldCheck",
            t(bad ? "att_looks_phishing" : notRead ? "att_cannot_look" : caution ? "verdict_caution" : "att_looks_safe"), filename),
        h("div.pll-att-banner__sub", null,
            meta && [meta, h("br")],
            caution && [t(notRead ? "att_caution_text" : "lead_caution"), h("br")],
            score(t("meter_wording"), data.agents?.text?.phishing_probability), " · ",
            score(t("meter_links"), data.agents?.url?.phishing_probability),
            isEmail && [" · ", score(t("meter_sender"), data.agents?.metadata?.phishing_probability)]),
        chips.length && h("div.pll-att-banner__chips", null, chips),
        ...archiveFiles(a, bad));
}

// Files inside an archive. Those that explain the verdict ("Do not open")
// come first, then the full list, folded.
function archiveFiles(a, bad) {
    // Archives, and Office files that hold other files read as members.
    if (a.kind !== "archive" && !Array.isArray(a.entries)) return [];
    const risky = Array.isArray(a.suspicious_files) ? a.suspicious_files : [];
    const entries = Array.isArray(a.entries) ? a.entries : [];
    const name = (n) => h("span.pll-att-files__name", { title: PhishLensShared.safeName(n) }, PhishLensShared.safeName(n));
    const out = [];
    if (risky.length) {
        out.push(h(`div.pll-att-files.pll-att-files--${bad ? "bad" : "warn"}`, null,
            h("div.pll-att-files__title", null, t(bad ? "att_do_not_open" : "att_check_before")),
            h("ul", null, risky.map((f) => h("li", null, name(f.name),
                h("span.pll-att-files__why", null, (f.reasons || []).map(reasonLabel).join(", ")))))));
    }
    if (entries.length) {
        out.push(h("details.pll-att-files.pll-att-files--all", null,
            h("summary", null, t("att_files_list", { count: a.entry_count || entries.length })),
            h("ul", null,
                entries.map((n) => h("li", null, name(n))),
                a.entry_count > entries.length &&
                    h("li.pll-att-files__more", null, t("att_and_more", { count: a.entry_count - entries.length })))));
    }
    return out;
}
})();
