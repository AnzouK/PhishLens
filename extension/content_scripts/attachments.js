// =====================================================================
// PhishLens content script: Gmail, attachments.
// =====================================================================
// Finds the attachment tiles, adds a scan button, downloads each file
// (same-origin, with the Gmail session) and shows one result card per
// file.
// =====================================================================

// =====================================================================
// Attachment scanning.
// =====================================================================
// Gmail renders each attachment as an anchor with a download attribute
// pointing to its per-attachment fetch URL. Since we run in the Gmail
// page context, a same-origin fetch on that URL sends the session
// cookies automatically, no need to shuttle through the background
// service worker just to authenticate.
//
// UX:
//   - one "Scan" pill per supported attachment, injected next to the
//     download control
//   - if the mail has >1 supported attachment we ALSO inject a header
//     button that scans all of them sequentially
//   - each scan produces a mini-banner right below the attachment tile,
//     using the same colour language as the main verdict banner
// =====================================================================

const ATT_MAX          = 15;                   // hard limit per mail
const ATT_MAX_SIZE_MB  = 10;
// PDF, HTML, images (OCR + QR), Office documents (macros, links),
// archives, calendar invites, attached emails and plain text.
const ATT_SUPPORTED    = new Set(["pdf", "html", "htm", "png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "docx", "docm", "doc", "xlsx", "xlsm", "xls", "pptx", "pptm", "ppt",
                                  "zip", "rar", "7z", "ics", "eml", "txt"]);
// Any "name.ext" (for attachments PhishLens cannot read, to say so).
const ATT_ANY_EXT_RE   = /([\w \-.()]+\.([a-z0-9]{1,5}))(?=\s|$)/i;
// Attachment flags meaning "we could not look inside": a safe score is
// not reassuring, so these get a caution banner instead of "Looks safe".
const ATT_CAUTION_FLAGS = new Set(["encrypted_archive", "encrypted_document", "uninspectable_archive",
                                   "disk_image_attachment", "disk_image_in_archive", "zip_bomb_suspected", "inner_files_not_extracted"]);
// Longest extensions first so "html" wins over "htm" in the regex.
const ATT_EXT_RE       = new RegExp(
    "([\\w \\-.()]+\\.(" + [...ATT_SUPPORTED].sort((a, b) => b.length - a.length).join("|") + "))",
    "i");
const ATT_HOOKED       = new WeakSet();

// Gmail attachment strip container. Everything below must be scoped
// to an .aQH (or .aQe / .hq in older layouts): the strip is the ONLY
// place attachments live, so scanning outside of it is what caused
// orphan "Scan" buttons to appear over random spans in the message body
// or sidebar.
const ATT_STRIP_SEL = '.aQH, .aQe, .hq';

// Tile-level selectors: must all be scoped to a strip when queried.
const ATT_TILE_HINT_SELECTORS_IN_STRIP = [
    'a[download]',
    'div[data-attachmentid]',
    'div[data-tooltip*="oad"]',              // 'Download' / 'Télécharger le fichier'
    'div[role="listitem"]',
    '.aZo',                                   // classic Gmail attachment tile
];

function installAttachmentButtons(emailView) {
    if (!emailView || !pllAlive()) return;

    // Attachments only live inside an attachment strip. Everything else
    // is out of bounds; this is what prevented orphan "Scan" buttons
    // from appearing over random spans in the message body / sidebar.
    const strips = emailView.querySelectorAll(ATT_STRIP_SEL);
    if (!strips.length) return;

    const candidates = new Set();
    strips.forEach((strip) => {
        // Try each tile-shape hint inside this strip.
        for (const sel of ATT_TILE_HINT_SELECTORS_IN_STRIP) {
            strip.querySelectorAll(sel).forEach((el) => candidates.add(el));
        }
        // Fallback: any element inside the strip whose text ends with
        // a supported extension (Gmail sometimes doesn't use any of
        // the classes above in newer redesigns).
        strip.querySelectorAll("span, div").forEach((el) => {
            const label = (el.textContent || "").trim();
            if (label.length > 3 && label.length < 260) {
                const ext = (label.split(".").pop() || "").toLowerCase();
                if (ATT_SUPPORTED.has(ext)) candidates.add(el);
            }
        });
    });

    const found = [];
    const seenTiles = new Set();
    candidates.forEach((el) => {
        // Constrain the tile walk to the enclosing strip, otherwise
        // .closest('[role="listitem"]') can escape past .aQH and match
        // the whole-message container that Gmail also marks as
        // role="listitem" in the thread view. That's what caused the
        // orphan "Scan" button below the attachment banners.
        const strip = el.closest(ATT_STRIP_SEL);
        if (!strip) return;

        const tile = _findAttachmentTile(el, strip);
        if (!tile || ATT_HOOKED.has(tile) || seenTiles.has(tile)) return;
        // Belt & braces: reject anything that ended up outside the strip
        // or already scanned (attachment banner is now the source of truth).
        if (!strip.contains(tile)) return;
        if (tile.dataset.pllScanned === "1") return;
        seenTiles.add(tile);

        // Sanity check: a real Gmail attachment tile is between roughly
        // 100x80 and 350x280 px. Anything smaller is a stray hit and
        // anything much bigger is a container we shouldn't hook.
        const r = tile.getBoundingClientRect();
        if (r.width < 80 || r.height < 60 || r.width > 400 || r.height > 400) return;

        const info = _extractAttachmentInfo(tile);
        if (!info) return;
        if (!ATT_SUPPORTED.has(info.ext)) {
            // Only report unreadable types for real attachment tiles, so a
            // stray element in the strip never produces a notice.
            const strong = tile.matches?.(".aZo, [data-attachmentid]") || tile.querySelector("a[download]");
            if (!strong) return;
            info.unsupported = true;
        }
        ATT_HOOKED.add(tile);
        found.push({ tile, ...info, emailView });
    });

    if (!found.some((f) => !f.unsupported)) {
        // Only unreadable attachments: say so once, without a scan button.
        found.forEach((f) => renderAttachmentNotice(f));
        return;
    }

    // Single central button, no per-tile pills. Way cleaner visually,
    // no alignment mismatch between the tile row and the banner grid.
    installScanAllButton(emailView, found);
}

// Walk up from a node until we hit something that looks like an
// attachment tile boundary, but NEVER past `strip` (the .aQH container).
// Without the strip clamp, closest() would happily walk out of the
// attachment area and grab a whole-message row (which Gmail also marks
// as role="listitem" in thread view).
function _findAttachmentTile(node, strip) {
    const selector = '.aZo, [data-attachmentid], .aQw';   // strong tile hints only
    let cur = node;
    while (cur && cur !== strip && cur !== document.body) {
        if (cur.matches?.(selector)) return cur;
        cur = cur.parentElement;
    }
    // No strong match: walk up again looking for role="listitem" but
    // stop at the strip boundary.
    cur = node;
    while (cur && cur !== strip && cur !== document.body) {
        if (cur.matches?.('[role="listitem"]')) return cur;
        cur = cur.parentElement;
    }
    // Last resort: the node itself (if it's not the strip)
    return (node !== strip) ? node : null;
}

// Given a tile, extract the filename, extension, and best downloadable
// anchor. Returns null when the tile doesn't look like a supported
// attachment.
function _extractAttachmentInfo(tile) {
    // 1. Filename: prefer an `a[download]` value, else fall back to the
    //    first .aV3-ish span, else the tile's visible text.
    let filename = "";
    const dlAnchor = tile.querySelector("a[download]");
    if (dlAnchor && dlAnchor.getAttribute("download")) {
        filename = dlAnchor.getAttribute("download").trim();
    }
    if (!filename) {
        const nameSpan = tile.querySelector(".aV3, .aQw, .aQA, .a1V");
        if (nameSpan) filename = (nameSpan.textContent || "").trim();
    }
    if (!filename) {
        // last resort: the tile's own text (short first line)
        const txt = (tile.textContent || "").trim().split("\n")[0].trim();
        if (txt.length < 260) filename = txt;
    }
    if (!filename || filename.length > 260) return null;

    // Strip trailing size text: Gmail sometimes suffixes tile text with
    // "Checklist.pdf 320 KB". Keep only the first .ext-ending chunk.
    const extMatch = filename.match(ATT_EXT_RE) || filename.match(ATT_ANY_EXT_RE);
    if (extMatch) filename = extMatch[1].trim();

    const ext = (filename.split(".").pop() || "").toLowerCase();
    if (!ext || ext === filename.toLowerCase()) return null;

    // 2. Anchor: anything inside the tile with an href we can fetch.
    const anchor = dlAnchor
        || tile.querySelector('a[href*="&view=att"], a[href*="ui=2"]')
        || tile.querySelector("a[href]");

    return { filename, ext, anchor };
}

function installScanAllButton(emailView, targets) {
    // Idempotent: install once per email view. If a previous pass
    // already installed the button with a different attachment count
    // (Gmail lazy-loaded more tiles), update the label instead of
    // duplicating.
    let existing = emailView.querySelector(".pll-scan-btn--all");
    if (existing && existing.dataset.pllInstance !== PLL_INSTANCE) {
        existing.remove();          // left by an older copy of the script
        existing = null;
    }
    if (existing) {
        const label = existing.querySelector(".pll-scan-btn__label");
        if (label && !existing.disabled) {
            label.textContent = targets.length > 1
                ? t("att_scan_n", { count: targets.length })
                : t("att_scan_single");
        }
        existing._pllTargets = targets;
        return;
    }

    const subjectEl = emailView.querySelector(SUBJECT_SEL);
    const wrap = subjectEl?.parentElement;
    if (!wrap) return;

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "pll-scan-btn pll-scan-btn--all";
    btn.dataset.pllInstance = PLL_INSTANCE;
    btn._pllTargets = targets;
    btn.innerHTML = `<span class="pll-scan-btn__icon">${PLL_ICON.clip}</span>` +
                    `<span class="pll-scan-btn__label">${escapeHTML(
                        targets.length > 1 ? t("att_scan_n", { count: targets.length }) : t("att_scan_single")
                    )}</span>`;
    btn.addEventListener("click", async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();

        // Use the latest target list (may have been updated by a later
        // MutationObserver pass if more tiles lazy-loaded).
        const currentTargets = btn._pllTargets || targets;

        if (currentTargets.length >= 5 &&
            !confirm(t("att_confirm_many", { count: currentTargets.length }))) {
            return;
        }
        if (currentTargets.length > ATT_MAX) {
            alert(t("att_too_many", { count: currentTargets.length, max: ATT_MAX }));
            return;
        }
        btn.disabled = true;
        const labelEl = btn.querySelector(".pll-scan-btn__label");
        for (let i = 0; i < currentTargets.length; i++) {
            labelEl.textContent = currentTargets.length > 1
                ? t("att_scanning_progress", { i: i + 1, n: currentTargets.length })
                : t("scanning");
            try { await scanOneAttachment(currentTargets[i]); } catch {}
        }
        labelEl.textContent = t("att_done");
        setTimeout(() => btn.remove(), 2500);
    });
    wrap.appendChild(btn);
}

// Fetch the attachment, base64-encode it, POST to /analyse_attachment
// via the background service worker (CSP-bypass proxy).
// Attachments PhishLens cannot read (unknown type): a neutral notice so
// the user knows it was not checked, instead of silence.
function renderAttachmentNotice({ filename, tile, emailView }) {
    const stack = _getAttachmentBannerStack(tile, emailView);
    const id = "pll-att-" + _fileKey(filename);
    if (stack.querySelector(`#${CSS.escape(id)}`)) return;
    const banner = document.createElement("div");
    banner.id = id;
    banner.className = "pll-att-banner pll-att-banner--error";
    banner.innerHTML = `
        <div class="pll-att-banner__row"><span class="pll-att-banner__icon">${PLL_ICON.alert}</span>
        <div class="pll-att-banner__main"><div class="pll-att-banner__title">${escapeHTML(t("att_not_checked"))}</div>
        <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div></div></div>
        <div class="pll-att-banner__sub">${escapeHTML(t("att_not_checked_sub"))}</div>`;
    stack.appendChild(banner);
    if (tile) tile.dataset.pllScanned = "1";
}

async function scanOneAttachment({ anchor, filename, ext, tile, emailView, btn, unsupported }) {
    if (unsupported) {
        renderAttachmentNotice({ filename, tile, emailView });
        return;
    }
    // Banner placement: Gmail's attachment tiles have their own font
    // scaling and flex layout that mangle anything appended inside. We
    // instead find (or create) a dedicated stack container placed AFTER
    // the whole attachment strip, and put one banner per attachment
    // in there.
    const stack = _getAttachmentBannerStack(tile, emailView);
    const bannerId = "pll-att-" + _fileKey(filename);
    let banner = stack.querySelector(`#${CSS.escape(bannerId)}`);
    if (!banner) {
        banner = document.createElement("div");
        banner.id = bannerId;
        banner.className = "pll-att-banner pll-att-banner--loading";
        stack.appendChild(banner);
    }
    banner.className = "pll-att-banner pll-att-banner--loading";
    banner.innerHTML = `<div class="pll-att-banner__row"><span class="pll-att-banner__icon pll-spin">${PLL_ICON.spinner}</span>` +
        `<div class="pll-att-banner__main"><div class="pll-att-banner__title">${escapeHTML(t("scanning"))}</div>` +
        `<div class="pll-att-banner__file">${escapeHTML(filename)}</div></div></div>`;
    // Drop the Scan pill immediately when the loading banner shows:
    // the banner itself is the ongoing feedback. On error we'll offer
    // a Retry inside the banner rather than resurrect the pill.
    if (tile) {
        tile.querySelectorAll(".pll-att-btn").forEach((el) => el.remove());
    } else if (btn && btn.isConnected) {
        btn.remove();
    }

    try {
        // Resolve a download URL. Gmail lazy-loads the download anchor
        // on hover, so if we don't have one, dispatch a mouseover to
        // reveal it, wait a beat, then re-scan the tile.
        let url = anchor?.href || "";
        if (!url && tile) {
            tile.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
            await new Promise((r) => setTimeout(r, 200));
            const late = tile.querySelector("a[download], a[href*='view=att']");
            if (late) url = late.href;
        }
        if (!url) throw new Error(t("att_err_no_url"));

        // Same-origin fetch: Gmail's session cookie is sent automatically.
        const resp = await fetch(url, { credentials: "include" });
        if (!resp.ok) throw new Error(t("att_err_download", { status: resp.status }));
        const buf = await resp.arrayBuffer();
        if (buf.byteLength > ATT_MAX_SIZE_MB * 1024 * 1024) {
            throw new Error(t("att_err_too_large", { size: (buf.byteLength / 1024 / 1024).toFixed(1), max: ATT_MAX_SIZE_MB }));
        }
        const b64 = arrayBufferToBase64(buf);

        // Route through background for CSP-bypass + backend selection.
        const senderEl = emailView.querySelector(SENDER_SEL);
        // An email attached to an email (.eml): run the full email
        // pipeline on it, headers included.
        const r = ext === "eml"
            ? await chrome.runtime.sendMessage({ type: "phishlens.analyse", payload: { raw_email_b64: b64 } })
            : await chrome.runtime.sendMessage({
            type: "phishlens.analyse_attachment",
            payload: {
                content_b64: b64,
                filename,
                // The backend sniffs the real type from the bytes; the
                // extension only sends the filename-based hint.
                mime_type: null,
                parent_email: {
                    sender_email:    senderEl?.getAttribute("email") || null,
                    subject:         emailView.querySelector(SUBJECT_SEL)?.textContent?.trim() || null,
                    // The mail is currently open in this Gmail account's
                    // Inbox: SPF/DKIM/DMARC already passed on Google's
                    // side, otherwise it would have landed in Spam.
                    // We forward this to the backend so the attachment
                    // scoring inherits the parent's trust context
                    // (softer weights, higher threshold).
                    gmail_delivered: !window.location.hash.toLowerCase().includes("spam"),
                },
            },
        });
        if (!r?.ok) throw new Error(r?.error || t("att_err_backend"));
        renderAttachmentBanner(banner, r.data, filename);
        // Mark the tile as scanned so the MutationObserver doesn't
        // resurrect a Scan pill on the next DOM tick.
        if (tile) tile.dataset.pllScanned = "1";

        // Attachment scans go to the local history too, like email scans.
        chrome.runtime.sendMessage({
            type: "phishlens.history.save",
            entry: {
                source:  "gmail-attachment",
                subject: filename,
                sender:  senderEl?.getAttribute("email") || senderEl?.textContent?.trim() || "",
                verdict: r.data.verdict,
                score:   Number(r.data.fused_score) || 0,
                agents: {
                    text: Number(r.data.agents?.text?.phishing_probability) || 0,
                    url:  Number(r.data.agents?.url?.phishing_probability)  || 0,
                    metadata: 0,
                },
                trusted: !!r.data.parent_trusted,
            },
        }).catch(() => {});
    } catch (e) {
        banner.className = "pll-att-banner pll-att-banner--error";
        banner.innerHTML = `
            <div class="pll-att-banner__row"><span class="pll-att-banner__icon">${PLL_ICON.alert}</span>
            <div class="pll-att-banner__main"><div class="pll-att-banner__title">${escapeHTML(t("att_could_not_scan"))}</div>
            <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div></div></div>
            <div class="pll-att-banner__sub">${escapeHTML(e.message || String(e))}</div>
            <button type="button" class="pll-att-btn">${escapeHTML(t("retry"))}</button>
        `;
        banner.querySelector("button")?.addEventListener("click", () => {
            scanOneAttachment({ anchor, filename, ext, tile, emailView });
        });
    }
}

function renderAttachmentBanner(banner, data, filename) {
    const bad = data.verdict === "phishing";
    const flags = data.attachment?.notable_features || [];
    const caution = !bad && flags.some((f) => ATT_CAUTION_FLAGS.has(f));
    banner.className = "pll-att-banner " + (bad ? "pll-att-banner--danger" : caution ? "pll-att-banner--error" : "pll-att-banner--safe");
    const pct = (v) => Math.round((Number(v) || 0) * 100);
    const chips = [];
    if (data.parent_trusted) {
        chips.push(`<span class="pll-att-chip pll-att-chip--good" title="${escapeHTML(t("att_trusted_email_title"))}">${escapeHTML(t("att_trusted_email"))}</span>`);
    }
    (data.attachment?.notable_features || []).forEach((f) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--warn">${escapeHTML(flagLabel(f))}</span>`);
    });
    (data.url_reputation?.sources_hit || []).forEach((s) => {
        chips.push(`<span class="pll-att-chip pll-att-chip--bad">${escapeHTML(_SOURCE_LABEL_GMAIL[s] || s)}</span>`);
    });
    const a = data.attachment || {};
    const isEmail = !data.attachment && !!data.agents?.metadata;   // attached .eml
    const meta = [
        isEmail ? t("att_kind_email") : a.kind ? a.kind.toUpperCase() : "",
        a.size_bytes ? t("att_size_kb", { size: (a.size_bytes / 1024).toFixed(0) }) : "",
        a.page_count ? t("att_pages", { read: a.pages_read || a.page_count, total: a.page_count }) : "",
        a.entry_count ? tn("att_files_inside", a.entry_count) : "",
        a.organizer ? t("att_from", { organizer: a.organizer }) : "",
        a.extracted_urls_count ? tn("att_urls", a.extracted_urls_count) : "",
    ].filter(Boolean).join(" · ");

    banner.innerHTML = `
        <div class="pll-att-banner__row">
            <span class="pll-att-banner__icon">${bad || caution ? PLL_ICON.alert : PLL_ICON.shieldCheck}</span>
            <div class="pll-att-banner__main">
                <div class="pll-att-banner__title" title="${escapeHTML(filename)}">
                    ${escapeHTML(bad ? t("att_looks_phishing") : caution ? t("att_cannot_look") : t("att_looks_safe"))}
                </div>
                <div class="pll-att-banner__file" title="${escapeHTML(filename)}">${escapeHTML(filename)}</div>
            </div>
        </div>
        <div class="pll-att-banner__sub">
            ${meta ? `${escapeHTML(meta)}<br>` : ""}
            ${caution ? `${escapeHTML(t("att_caution_text"))}<br>` : ""}
            ${escapeHTML(t("meter_wording"))} <strong>${pct(data.agents?.text?.phishing_probability)}%</strong> ·
            ${escapeHTML(t("meter_links"))} <strong>${pct(data.agents?.url?.phishing_probability)}%</strong>
            ${isEmail ? ` · ${escapeHTML(t("meter_sender"))} <strong>${pct(data.agents?.metadata?.phishing_probability)}%</strong>` : ""}
        </div>
        ${chips.length ? `<div class="pll-att-banner__chips">${chips.join("")}</div>` : ""}
        ${archiveFilesHTML(a, bad)}
    `;
}

// Inside an archive, name the files that explain the verdict
// ("Do not open"), then the full list of files, folded.
function archiveFilesHTML(a, bad) {
    if (a.kind !== "archive") return "";
    const risky = Array.isArray(a.suspicious_files) ? a.suspicious_files : [];
    const entries = Array.isArray(a.entries) ? a.entries : [];
    let html = "";
    if (risky.length) {
        const rows = risky.map((f) =>
            `<li><span class="pll-att-files__name" title="${escapeHTML(f.name)}">${escapeHTML(f.name)}</span>`
            + `<span class="pll-att-files__why">${escapeHTML((f.reasons || []).map(reasonLabel).join(", "))}</span></li>`).join("");
        html += `<div class="pll-att-files pll-att-files--${bad ? "bad" : "warn"}">
            <div class="pll-att-files__title">${escapeHTML(bad ? t("att_do_not_open") : t("att_check_before"))}</div>
            <ul>${rows}</ul></div>`;
    }
    if (entries.length) {
        const more = a.entry_count > entries.length ? `<li class="pll-att-files__more">${escapeHTML(t("att_and_more", { count: a.entry_count - entries.length }))}</li>` : "";
        html += `<details class="pll-att-files pll-att-files--all">
            <summary>${escapeHTML(t("att_files_list", { count: a.entry_count || entries.length }))}</summary>
            <ul>${entries.map((n) => `<li><span class="pll-att-files__name" title="${escapeHTML(n)}">${escapeHTML(n)}</span></li>`).join("")}${more}</ul>
        </details>`;
    }
    return html;
}

// Find or create a container to stack attachment banners. Instead of
// walking the DOM looking for a "nice" parent (fragile: Gmail changes
// its layout constantly), we anchor to the strip and rely on CSS to
// force the stack to full width regardless of the parent's display
// mode (flex row / grid / whatever). See .pll-att-stack in banner.css.
function _getAttachmentBannerStack(tile, emailView) {
    const strip = (tile && tile.closest(ATT_STRIP_SEL))
               || emailView.querySelector(ATT_STRIP_SEL);
    const anchor = strip || emailView.querySelector(BODY_SEL) || emailView;
    const parent = anchor.parentElement || emailView;

    let stack = parent.querySelector(":scope > .pll-att-stack");
    if (!stack) {
        stack = document.createElement("div");
        stack.className = "pll-att-stack";
        anchor.insertAdjacentElement("afterend", stack);
    }
    return stack;
}
