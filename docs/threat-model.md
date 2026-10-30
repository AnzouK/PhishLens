# Threat model

Scope: the PhishLens runtime (Chrome extension, FastAPI backend,
PhishLens Cloud at phishlens.dev). The training pipeline in PhishingDetector is
covered only where it affects the runtime (the published models).
Method: STRIDE per trust boundary, then a list of the risks we accept.

## Assets

| Asset | Why it matters |
| --- | --- |
| Email content sent for scanning | Private user data (body, sender, attachments) |
| Correctness of the verdict | A wrong "safe" on a phishing email is the main harm the tool can cause |
| Google Safe Browsing API key and daily quota | Leaking or exhausting it silently removes the strongest URL signal |
| Backend availability | PhishLens Cloud is shared by every extension user on the Cloud setting |
| Published models on Hugging Face | Loaded by every backend at startup; the text model decides the wording score |
| Hugging Face read token (`HF_TOKEN`, only when the text model is in a private repository) | Read access to that repository |
| The server and its secrets (`.phishlens.env`) | Host compromise exposes all of the above |
| Reports users send (`FEEDBACK_DIR`) | Redacted email text: still private content, and future training data |

## Trust boundaries

```mermaid
flowchart LR
    U["Gmail page<br/>(untrusted content)"] -->|B1| E["Extension"]
    E -->|B2 HTTPS| P["Caddy"] --> A["Backend API"]
    X["Anyone on the internet"] -->|B2| P
    A -->|B3| I["Threat intel APIs<br/>and DNS"]
    H["Hugging Face Hub"] -->|B4| A
    A --- C[("SQLite URL cache")]
    E -->|B6 reports, redacted| P
    X -->|B6| P
    A --- F[("Reports<br/>FEEDBACK_DIR")]
```

B1: email content controlled by the attacker reaches the extension.
B2: any HTTP client can reach the public API, not only the extension.
B3: the backend trusts answers from external intel services.
B4: the backend downloads and deserialises model files at startup.
B5: the extension's own interface texts (translations) are shipped with
the extension and never come from the network.
B6: anyone can post a report to `/feedback`, not only the extension.

## STRIDE analysis

| # | Threat | Boundary | Mitigation in place | Status |
| --- | --- | --- | --- | --- |
| S1 | **Spoofing** the sender: `From: paypal.com` sent from attacker infrastructure to borrow trust | B1 | Trust comes from DKIM alignment with the From: organisational domain, not from the header text. Misaligned `signed-by` stays on the strict path. A brand's name over another domain's address ("Chronopost <x@random.us>") cancels the softer paths and raises the sender score (`test_impersonation_and_links.py`). Tested in `test_auth_headers.py` and `test_extension_backend.py` | Mitigated |
| S2 | Spoofing the client context: a caller claims `gmail_in_inbox` or `gmail_delivered` to soften its own scan | B2 | The flags only soften the caller's own result, never shared state; a Safe Browsing hit still forces phishing; documented as a SECURITY NOTE in code | Accepted (limited impact) |
| S3 | Trusted-domain abuse: a compromised account at an allowlisted bank sends phishing | B1 | A Safe Browsing hit forces phishing on every path, the allowlist included; allowlist is small and documented as a regional fallback | Partially mitigated |
| T1 | **Tampering** with the model: a malicious joblib on Hugging Face (pickle executes code on load) | B4 | The agents load from skops files with a type allowlist (scikit-learn, NumPy, SciPy, builtins only); pickle is refused unless `AGENTS_ALLOW_PICKLE=1` | Mitigated |
| T2 | Cache poisoning: a wrong verdict stored in the reputation cache | B3 | Cache key is the normalised URL, values only come from the cascade itself, 24 h TTL | Mitigated |
| T4 | A tampered PhishTank feed, or a PhishTank entry on a shared host (`bit.ly`, `storage.googleapis.com`) flagging every link of that host | B3 | Feed downloaded over HTTPS only; on hosts that serve many unrelated users, only the exact URL matches, never the whole domain (`SHARED_PATH_HOSTS`) | Mitigated |
| T5 | A replaced or wrong text model: `HF_MODEL_REPO` changed, a new revision pushed to the repository | B4 | Weights loaded through `transformers`, which prefers safetensors files (data only) when the repository provides them; one folder per repository so a switch never mixes models; `/health` reports the repository, revision, name and settings in use; `HF_MODEL_REVISION` and `HF_AGENTS_REVISION` pin the exact commits (a warning is logged when they are not set); only the maintainer can push to the repository | Mitigated when the revisions are pinned |
| T3 | Adversarial text: wording crafted to push the text model towards "safe" | B1 | Three independent agents plus threat intel; a clean text score does not hide a blocklisted URL or failed DMARC | Partially mitigated |
| R1 | **Repudiation**: no record of what was scanned | B2 | By design: the backend keeps no email content. Aggregate verdict counts only (`/metrics`) | Accepted |
| I5 | A report carries personal data the redaction missed (a name without greeting, a street address) | B6 | Redaction in the browser and again on the server, preview with edit and confirmation before sending, no IP stored, private folder, two-year limit, deletion by reference, human review before any use | Partially mitigated (redaction is rule-based) |
| T6 | Poisoning: fake reports pushing the next model towards wrong labels | B6 | Rate limit per IP, size and storage caps, strict validation; reports are never used for training without being read and relabelled by hand | Mitigated |
| I1 | **Information disclosure**: users paste sensitive mail into the shared PhishLens Cloud test box | B2 | HTTPS only; no server-side storage of bodies; README warns not to send sensitive content to the demo; self-hosting is documented | Mitigated for transport, user choice otherwise |
| I2 | Error messages leak internals | B2 | Errors return a one-line message with a short reference; the stack trace is logged on the server under that reference and never returned | Mitigated |
| I3 | Secrets in the repository or its history | n/a | `.phishlens.env` and `.env` are git-ignored; the GSB key only lives on the VM; history rewritten once to remove personal data | Mitigated |
| I4 | `/metrics` and `/reputation/stats` reveal traffic and quota usage | B2 | Contain counts only; operations guide shows how to block `/metrics` at Caddy | Mitigated when proxy rule applied |
| D1 | **Denial of service** by request flooding, or burning the 10k/day GSB quota | B2 | Per-IP rate limits (30/min analyse, 20/min attachments, 15/min explain); GSB quota tracked in process with a 500-request safety buffer; cache absorbs repeats | Mitigated |
| D6 | Oversized requests, or CPU-bound inference blocking the server for everyone | B2 | Bodies above 45 MB refused with 413 before parsing; every field has a maximum length; model inference and attachment parsing run in a worker thread so the event loop keeps serving `/health` and other requests | Mitigated |
| D2 | Oversized or malformed attachments exhausting CPU or memory | B2 | 10 MB cap, magic-byte sniffing, page limit on PDFs, unsupported types rejected with 400; OCR limited to 3 pages with a 10 s timeout each, images downscaled and guarded against decompression bombs; Office files capped on part count, uncompressed size (zip bombs) and part size | Mitigated |
| D5 | XML entity expansion or external entities in an Office file | B2 | Any XML part that declares a DOCTYPE is skipped and flagged `suspicious_xml_doctype`; parts are parsed with `defusedxml`, which refuses entity tricks | Mitigated |
| D3 | ReDoS through crafted headers or URLs | B1, B2 | CodeQL `py/polynomial-redos` enabled; the three findings fixed (bounded quantifiers, anchored matches, `email.utils.parseaddr` instead of a regex); regression test with a 50k-character From: header | Mitigated |
| D4 | Intel APIs slow or down | B3 | 3 s HTTP timeout per tier; each tier fails open to "no hit"; lookups run in parallel with inference | Mitigated |
| E1 | **Elevation of privilege** via the extension: a Gmail page scripting the extension | B1 | Content script reads the DOM but never evaluates page content; no HTML is built from strings: every backend or email value, translated texts included (they can carry the sender or a file name), becomes a text node or an attribute value (`h()` in `lib/dom.js`); a unit test fails on any `innerHTML`; host permissions limited to Gmail, Outlook and the configured backends | Mitigated |
| E2 | Code execution through a malicious attachment | B2 | Parsing only (pdfplumber, BeautifulSoup, zipfile + defusedxml for Office); macros are detected, never run; PDF pages are rasterised by PDFium without JavaScript; container runs as a non-root user | Mitigated |
| E4 | CSV formula injection through the history export (an attacker-controlled subject such as `=HYPERLINK(...)`) | B1 | Cells starting with `= + - @` are prefixed with a quote in the export, covered by a unit test | Mitigated |
| E3 | Supply chain: a compromised dependency or GitHub Action | n/a | Dependabot alerts and weekly updates, CI token limited to `contents: read`, CodeQL on every push | Mitigated |

## Residual risks and known limitations

**R1. False negatives are possible.** On 2,000 recent phishing emails
nobody had looked at, the whole system caught 90.6%; new campaigns and
wording written against it will do worse. PhishLens is an assistant,
not a filter: the explanation is there so the user can judge.

**R2. Not every language is read equally well.** The text model was
trained on 22 languages but measured on real phishing in 6; a
self-hosted server uses the English model unless told otherwise. The
link, sender and threat-intelligence checks do not depend on the
language ([languages.md](languages.md#text-model)).

**R3. A phishing domain that signs its own mail gets the softer path.**
DKIM proves who sent the email, not that the sender is honest. Treating
signed senders like unsigned ones catches about 7 points more phishing
but doubles the false alarms on real inbox mail. The compromise: a
signed sender whose links all lead elsewhere, with phishing-like
wording, is flagged anyway. A link to a public file host counts
even next to a decoy link to the sender's own domain. Signed phishing
that also links to its own domain while its lure is on an ordinary
site, sends no link, or goes through known click tracking still gets
the discount ([evaluation](evaluation.md#results)).

**R4. The false-alarm rate rests on 414 legitimate emails.** One
person's inboxes and technical mailing lists: other inboxes, banks and
languages may see more. User reports are how this gets measured.

**R5. Soft trust signals can be claimed by any API caller.** Accepted:
the effect is confined to that caller's own response.

**R6. Shared open API.** No accounts: rate limits are per IP and in
memory, reset on restart and can be spread over many addresses. With a
public store release, per-install keys or a shared limiter become
worthwhile.

**R7. The allowlist trusts authenticated domains, not messages.** A
compromised account at a listed institution is caught only by threat
intelligence or the link checks.

**R8. OCR and QR decoding are best effort.** Poor scans, stylised fonts
or damaged QR codes defeat them; an image-only PDF still raises the
score a little.

**R9. The Hausa interface is a draft translation**, marked for review by
a native speaker; English stays available in Settings.

## Review triggers

Revisit this document when an endpoint, an input type or an extension
permission is added, when the text model changes, or when the
deployment moves off a single server. Last review: 2.0.11 (pinned model
revisions, no HTML built from strings in the extension).
