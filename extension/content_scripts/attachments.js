// Gmail attachments: one "Scan attachments" button per email, a download
// of each file (same origin, so Gmail's session cookie goes with it) and
// one result card per file below the attachment strip.
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
// An attached email is scanned as an email, the rest as attachments;
// programs, scripts and disk images too (the server flags them by type).
const SUPPORTED = new Set([...ATTACHMENT_EXTS, ...DANGEROUS_EXTS, "eml"]);
// The size Gmail writes after a tile's name ("Checklist.pdf 320 KB",
// "Facture.pdf 1,2 Mo", "scan.png 500 octets"). Only that is removed: the
// name itself is kept whole, in any script and with any character
// ("Facture_février [1].pdf", "scan.jpg   .js", "invoice.exe .").
const TRAILING_SIZE_RE = /\s+\d+(?:[.,]\d+)?\s*(?:[KMGT]i?B|[KMGT]o|B|o|bytes?|octets?|[КМГТ]?Б)\s*$/iu;

// A tile's text as a file name: the size cut, nothing else (the
// characters that reorder a name stay, for the server's checks and for
// safeName; fileExt reads past invisible ones).
function tileName(text) {
    return String(text || "").trim().replace(TRAILING_SIZE_RE, "").trim();
}
PL.tileName = tileName;
// Ways Gmail has marked an attachment tile, all looked up inside a strip
// only: outside it, stray matches put buttons over the message body.
const TILE_HINTS = ['a[download]', 'div[data-attachmentid]', 'div[data-tooltip*="oad"]', 'div[role="listitem"]', ".aZo"];
const hooked = new WeakSet();

PL.installAttachmentButtons = function installAttachmentButtons(emailView) {
    if (!emailView || !PL.alive()) return;
    const strips = emailView.querySelectorAll(SEL.attachmentStrip);
    if (!strips.length) return;

    const candidates = new Set();
    strips.forEach((strip) => {
        for (const sel of TILE_HINTS) strip.querySelectorAll(sel).forEach((el) => candidates.add(el));
        // Newer layouts may use none of the hints: any element whose text
        // ends with a supported extension.
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
        // A real tile is roughly 100x80 to 350x280 px: smaller is a stray
        // hit, much bigger a container.
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

// The tile around `node`, never walking past the strip: Gmail also marks
// whole messages role="listitem" in a conversation.
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
    if (existing && existing.dataset.pllInstance !== PL.instance) {
        existing.remove();          // left by an older copy of the scripts
        existing = null;
    }
    if (existing) {
        // More tiles were lazy-loaded since: update the count.
        if (!existing.disabled) existing.querySelector(".pll-scan-btn__label").textContent = scanLabel(targets.length);
        existing._pllTargets = targets;
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
    const targets = btn._pllTargets || [];
    const view = targets[0]?.emailView;
    if (view && !(await PL.confirmCloudUse(view))) return;
    if (targets.length >= 5 && !confirm(t("att_confirm_many", { count: targets.length }))) return;
    if (targets.length > MAX_PER_EMAIL) {
        alert(t("att_too_many", { count: targets.length, max: MAX_PER_EMAIL }));
        return;
    }
    btn.disabled = true;
    const label = btn.querySelector(".pll-scan-btn__label");
    for (let i = 0; i < targets.length; i++) {
        label.textContent = targets.length > 1 ? t("att_scanning_progress", { i: i + 1, n: targets.length }) : t("scanning");
        // scanAttachment shows its own errors in the file's card.
        await scanAttachment(targets[i]);
    }
    label.textContent = t("att_done");
    setTimeout(() => btn.remove(), 2500);
}

// The cards go in a container after the whole strip: inside a tile,
// Gmail's own layout mangles them (styles: .pll-att-stack in banner.css).
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

// The same file always gets the same card, updated on a new scan.
function cardFor(filename, tile, emailView) {
    const id = "pll-att-" + String(filename || "").replace(/[^a-z0-9]+/gi, "-").slice(0, 60).toLowerCase();
    const stack = bannerStack(tile, emailView);
    let card = stack.querySelector(`#${CSS.escape(id)}`);
    if (!card) {
        card = h("div.pll-att-banner", { id });
        stack.appendChild(card);
    }
    return card;
}

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

// A file PhishLens cannot read: say it was not checked, not nothing.
function renderNotice({ filename, tile, emailView }) {
    const card = cardFor(filename, tile, emailView);
    if (card.childElementCount) return;
    setCard(card, "error", cardHead("alert", t("att_not_checked"), filename),
        h("div.pll-att-banner__sub", null, t("att_not_checked_sub")));
    if (tile) tile.dataset.pllScanned = "1";
}

// Gmail adds the download link on hover: hover the tile when it is missing.
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
    const card = cardFor(filename, tile, emailView);
    setCard(card, "loading", cardHead("spinner", t("scanning"), filename, true));
    try {
        const b64 = await download(anchor, tile);
        const senderEl = emailView.querySelector(SEL.sender);
        const data = ext === "eml"
            // An attached email's headers were written by whoever attached
            // it, its Authentication-Results included: they prove nothing.
            ? await PhishLensApi.analyse({ raw_email_b64: b64, client_context: { headers_source: "attachment" } })
            : await PhishLensApi.analyseAttachment({
                content_b64: b64,
                filename,
                mime_type: null,          // the server reads the real type from the bytes
                parent_email: {
                    sender_email: senderEl?.getAttribute("email") || null,
                    subject: emailView.querySelector(SEL.subject)?.textContent?.trim() || null,
                    // Outside Spam, Gmail's own checks passed: the server
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
    const caution = !bad && isCaution(flags);
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
        ...flags.map((f) => h("span.pll-att-chip.pll-att-chip--warn", null, flagLabel(f))),
        ...(data.url_reputation?.sources_hit || []).map((s) => h("span.pll-att-chip.pll-att-chip--bad", null, SOURCE_LABELS[s] || s)),
    ].filter(Boolean);

    setCard(card, bad ? "danger" : caution ? "error" : "safe",
        cardHead(bad || caution ? "alert" : "shieldCheck",
            t(bad ? "att_looks_phishing" : caution ? "att_cannot_look" : "att_looks_safe"), filename),
        h("div.pll-att-banner__sub", null,
            meta && [meta, h("br")],
            caution && [t("att_caution_text"), h("br")],
            score(t("meter_wording"), data.agents?.text?.phishing_probability), " · ",
            score(t("meter_links"), data.agents?.url?.phishing_probability),
            isEmail && [" · ", score(t("meter_sender"), data.agents?.metadata?.phishing_probability)]),
        chips.length && h("div.pll-att-banner__chips", null, chips),
        ...archiveFiles(a, bad));
}

// Inside an archive: the files that explain the verdict ("Do not open"),
// then the full list, folded.
function archiveFiles(a, bad) {
    if (a.kind !== "archive") return [];
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
