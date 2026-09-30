# Changelog

All notable changes to PhishLens are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/). The extension and the
backend share one version number.

## [Unreleased]

### Added
- **Conversations:** in a Gmail thread, the scan reads the last
  expanded message only (body, sender, links, mailed-by / signed-by),
  so text and sender can no longer come from two different emails. The
  banner says "Latest message of N".
- **Forwarded emails:** a forward marker ("Forwarded message", "Begin
  forwarded message:", "Message transféré", ...) or a Fwd:/TR: subject
  switches off the sender-trust discounts, since the forwarder is not
  the author. Response field `forwarded` with the original sender, and
  a "Forwarded" chip in Gmail.
- **Image-only emails:** with fewer than 3 words the text agent is left
  out of the fusion (`text_agent_used: false`) and the verdict rests on
  the links and the sender; Gmail scans the links of such emails
  instead of stopping.
- **Shared-file links:** links to Google Drive / Docs / Forms, OneDrive,
  SharePoint, Dropbox, WeTransfer and similar services are listed in
  `shared_links` and shown as a warning (no score change).
- **Attachments:** ZIP archives (entries listed, password protection,
  executables, scripts, shortcuts, disk images and double extensions
  flagged, supported files inside analysed one level deep, zip-bomb
  guard), RAR / 7z (recognised, reported as not inspectable), calendar
  invites (`.ics`: text, links, organizer), attached emails (`.eml`,
  full email pipeline), password-protected PDFs, and executables /
  disk images attached directly. Executables, scripts, shortcuts and
  double extensions force the phishing verdict. When PhishLens cannot
  look inside a file (encrypted, disk image, RAR / 7z), Gmail and the
  popup show "Could not look inside" instead of "Looks safe", and
  unknown file types get a "Not checked" notice.

### Fixed
- **Trained URL agent and hidden links:** the Random Forest extracts its
  features from text, so link targets and QR-code URLs that were not in
  the visible text are now appended to it before scoring.
- **Hidden links in Gmail:** the Gmail scan sent only the visible text,
  so a link written as "Click here" was never checked. The extension now
  sends the real link targets (`client_context.link_urls`, max 50) and
  the backend adds them to the URL agent and the threat-intel lookups.
- **Attachment-only emails:** scanning an email with no body text no
  longer ends in "could not read the email body". PhishLens now says the
  email only carries attachments, scans them automatically and warns
  that attachment-only emails are a common phishing trick.
- **History:** attachment scans run from Gmail are now saved in the
  scan history (source "Gmail attachment"), and attachments dropped in
  the popup are labelled "attachment" instead of ".eml file".

## [1.13.0] - 2026-09-30

Interface release: new landing page, Gmail UI and popup polish.

### Changed
- **Landing page rewritten** (`site/index.html`): navigation, a hero
  with a mock Gmail verdict, results up front, "how it works" and
  feature sections, an install guide, and a better live demo (sample
  emails, a score bar per agent, sender and threat-intel pills, LIME
  words shaded by influence, rate-limit message). Live stats show
  "Off" for threat-intel sources that are disabled instead of 0.
- **Gmail UI redesigned** to match Gmail: outlined "Scan with
  PhishLens" pill, a verdict card with a coloured edge, a meter per
  agent, a plain-language recommendation, chips without emoji and a
  "Why this verdict?" section. Light by default, dark with the OS or
  the popup toggle, through a single set of colour variables.
- **Popup**: emoji replaced by an SVG icon set, clearer labels and
  error messages.
- **README illustrations** are now SVG (`docs/gmail-verdicts.svg`,
  `docs/attachments.svg`, `docs/popup.svg`): sharp at any size and in
  sync with the new interface. The old PNG screenshots are removed.
- A safe verdict with a high agent score now explains why (trusted
  sender, DKIM or Gmail delivery lowered the weight), instead of showing
  red meters under "looks safe" without context.
- Single characters and bare numbers are no longer shown among the
  LIME words.
- Roadmap: Chrome Web Store release, Outlook Web, automatic scanning,
  live evaluation.

### Fixed
- LIME words showed a weight of "0.00" (the real weights are below
  0.01). Colour intensity now reflects each word's influence relative
  to the strongest one, in the popup, the Gmail banner and the site.
- Attachment chips were unreadable in Gmail's light theme (dark-theme
  colours were always applied).
- The scan history stored the text-agent score as the overall score;
  it now stores the fused score.

### Security
- Threat model: R4 (pickled models) and T1 marked closed, the
  production backend runs with `AGENTS_ALLOW_PICKLE=0`.

## [1.12.0] - 2026-09-30

Attachment analysis, phase 2, and the end of pickle.

### Added
- **Scanned PDFs and images.** A PDF with almost no text layer is
  flagged `image_only_pdf`, its first 3 pages are rendered (pypdfium2)
  and read with Tesseract OCR, and the text goes through the text agent
  like any other attachment. PNG, JPEG, GIF, WebP, BMP and TIFF
  attachments are OCR'd the same way (`ocr.py`).
- **QR codes ("quishing").** QR codes in images and in the first pages
  of every PDF are decoded (OpenCV); their links go to the URL agent and
  the threat-intel cascade, and the file is flagged `contains_qr_code`.
- **Word, Excel and PowerPoint** (`.docx .docm .xlsx .xlsm .pptx .pptm`
  and legacy `.doc .xls .ppt`), parsed with the standard library
  (`office_analysis.py`): text, external links and the dropper flags
  `contains_macros`, `remote_template`, `dde_field`,
  `embedded_ole_object`, `contains_activex`, `external_data_connection`,
  `encrypted_document`, `legacy_office_format`,
  `suspicious_xml_doctype`, each with a score bonus. Macros, remote
  templates and DDE fields force the phishing verdict, even when the
  parent email is trusted.
- **Random Forest agents in the skops format** (`agent_io.py`), loaded
  with a type allowlist so a tampered file cannot run code, plus a
  one-time converter (`convert_agents_to_skops.py`). Pickle remains a
  fallback until the skops files are published (`AGENTS_ALLOW_PICKLE`).
- Extension, popup and landing page accept all the new attachment types.
- Tests: OCR / QR / scanned PDFs, Office parsing (macros, template
  injection, DDE, zip bombs, XXE, legacy and encrypted files), skops
  round trip and allowlist, extension libraries with `node:test`, popup
  UI with Playwright (new CI job, not required yet).

### Changed
- Docker images and CI on **Python 3.12** (unblocks numpy 2.5); the
  images install `tesseract-ocr` and copy every backend module.
- The CI job "Requirements resolve (Python 3.11)" is now
  "Requirements resolve (Docker Python)".
- ESLint: every rule now fails the build (`--max-warnings 0`); the
  remaining warnings were fixed (dead Gmail helpers from v1.6.2 removed,
  unused popup variables removed).
- GitHub Actions bumped to `checkout@v7` and `setup-python@v7` (the v4
  / v5 ones ran on the deprecated Node 20).

### Fixed
- **CSV formula injection in the history export.** A subject such as
  `=HYPERLINK("http://evil","click")` from a phishing email was written
  as is, and Excel would run it on opening. Cells starting with
  `= + - @` are now prefixed with a quote.
- The popup file picker went back to accepting only `.eml` after the
  first file was chosen.
- `.dockerignore` had an inline comment that disabled its pattern.

## [1.11.0] - 2026-09-29

### Security
- A Google Safe Browsing hit now forces the phishing verdict on the
  `trusted_sender` path too. Before, an allowlisted sender (for example
  a compromised bank account) carrying a blocklisted link stayed "safe"
  because that path disabled every override; the README and the threat
  model already claimed otherwise. Regression test added.

### Added
- CI job for the Chrome extension: `node --check` on every script, then
  ESLint (`eslint.config.mjs`). Bug-class rules (unreachable code,
  duplicate keys, assignment to a const, broken `typeof` checks) fail
  the job; hygiene rules (undefined names, unused variables) annotate
  without blocking.
- Branch protection on `main`: the three CI jobs must pass before a
  pull request can merge.
- "Scoring reference" section in `docs/architecture.md` (weights, trust
  paths, allowlist precedence, why the discounts exist).

### Changed
- README rewritten: 435 to about 190 lines, results (accuracy, F1,
  latency) up front, a small diagram instead of the ASCII art, scoring
  details moved to the architecture doc, release history left to this
  changelog.
- Em dashes removed from the whole repository (code comments, docs, UI
  strings).
- Dependabot also ignores major versions of pandas and numpy (their
  objects live inside the pickled Random Forest agents).

### Fixed
- `.gitignore` had two patterns followed by inline comments, which git
  does not support: `.phishlens.env` and `extension/dist/` were not
  actually ignored.
- Manual install instructions (README, CONTRIBUTING) now install the
  CPU build of torch, which `requirements.txt` deliberately leaves out.

## [1.10.2] - 2026-09-29

### Added
- CI job that resolves `backend/requirements.txt` on Python 3.11 (the
  Docker base) with `pip install --dry-run`, so dependency bumps that
  cannot install in the image fail in CI instead of at deploy time.
- DistilBERT checkpoint and Random Forest joblibs persisted on host
  volumes (see `docs/operations.md`), so re-creating the container no
  longer re-downloads them.

### Changed
- Dependabot ignores major versions of transformers, huggingface-hub
  and scikit-learn; those are upgraded by hand after a real model test.
- Dependabot keeps patch updates of the `python` Docker base image but
  ignores minor and major ones (3.11 to 3.14 changes which wheels exist
  for torch, lime and scikit-image).

- Dependency minimums raised (Dependabot, all within the current major
  except prometheus-fastapi-instrumentator 7 to 8, which the `/metrics`
  test already runs against): transformers 4.57.6, scikit-learn 1.9.1,
  beautifulsoup4 4.15.0, pdfplumber 0.11.10, slowapi 0.1.10.
- README latency figure updated from the old "3 to 5 s" (Render era) to
  the measured value.

### Fixed
- Mermaid sequence diagram in `docs/architecture.md` did not render on
  GitHub.

### Measured
- First load test on the Oracle A1 VM: 454 requests, 0 failures,
  `/analyse` text median 77 ms and p95 280 ms, all endpoints p99 under
  0.5 s at about 4 requests per second. Details in
  `docs/operations.md`.

## [1.10.1] - 2026-09-29

### Fixed
- Link-free emails could be flagged as phishing on the default path.
  The trained URL Random Forest ran even when the body had no URL and
  returned about 0.9 on the all-zero feature vector, which fired the
  single-agent override (seen on "Hi team, the meeting moved to 3pm.").
  The URL agent now returns 0.05 when there are no links, before the
  trained model is consulted. Regression tests added.

## [1.10.0] - 2026-09-29

Engineering-process release: tests, observability and documentation.
No change to detection behaviour or to the extension's features.

### Added
- Prometheus metrics on `GET /metrics`: request count, latency and
  in-flight requests per endpoint, plus `phishlens_verdicts_total` by
  endpoint, verdict and trust path. Turn off with `METRICS_ENABLED=0`.
- `trust_path` field in the `/analyse` response (`trusted_sender`,
  `crypto_verified`, `gmail_inbox_soft` or `default`). Additive, no
  breaking change for existing clients.
- Tests for `feature_extraction`, `reputation` and the FastAPI endpoints
  (`/health`, `/analyse`, `/analyse_attachment`, `/metrics`), covering
  all four trust paths and the attachment trust inheritance. The suite
  runs offline: `conftest.py` stubs the heavy ML imports.
- Coverage report in CI (`pytest-cov`).
- Locust load test (`scripts/locustfile.py`).
- Documentation: `docs/project-overview.md` (hub for both repositories,
  models and report), `docs/architecture.md` (diagrams and design
  decisions), `docs/threat-model.md` (STRIDE), `docs/operations.md`
  (deploy, logging, metrics, load testing), `CONTRIBUTING.md`, this
  changelog, and a pull request template.

### Fixed
- About 20 log calls printed the literal text `{e}` instead of the error
  (missing `f` prefix). They now show the real message.
- The remaining `print()` calls in the runtime were moved to the logger,
  and the `phishlens.*` loggers now get a handler, so INFO lines (model
  loaded, agents loaded, PhishTank feed size) actually reach
  `docker logs`. Level is configurable with `LOG_LEVEL`.

### Changed
- Extension manifest description no longer uses an em dash.

## [1.9.0] - 2026-09-21

### Added
- Per-IP rate limiting with `slowapi` on `/analyse`, `/explain` and
  `/analyse_attachment`, tunable per endpoint.
- First pytest suite (`auth_headers`, `attachment_analysis`) and a
  GitHub Actions CI job (compile, ruff, pytest).
- CodeQL code scanning, Dependabot version updates, `SECURITY.md`
  (reports through GitHub Security Advisories).

### Changed
- `space/` merged into `backend/`, with `Dockerfile.local` and
  `Dockerfile.cloud`.
- Runtime `print()` warnings moved to `logging`.

### Fixed
- Three CodeQL `py/polynomial-redos` findings (domain IP check, PDF URI
  scan, From: display-name parsing).
- CI workflow now declares least-privilege `permissions`.

## 1.8.1 - 2026-09-21 (untagged, released as part of 1.9.0)

### Fixed
- Popup "Test connection" now calls `/health` (the root path serves the
  landing page since 1.7.0).
- Global-scope name collision between `history.js` and `lime_cache.js`.
- Gmail attachment UI: one "Scan N attachments" button and a compact
  card grid; attachments inherit the parent email's trust.

## [1.8.0] - 2026-09-20

### Added
- `POST /analyse_attachment` for PDF (pdfplumber) and HTML
  (BeautifulSoup) attachments, 10 MB cap, magic-byte sniffing, risky
  feature flags with a bounded score bonus.
- Attachment scanning from Gmail, the popup and the landing page.

## [1.7.0] - 2026-09-20

### Added
- HTTPS on `anzouk.duckdns.org` through Caddy and Let's Encrypt.
- Landing page with live status, backend stats and a try-it widget.

## [1.6.2] - 2026-09-11

### Added
- Gmail Inbox delivery used as a soft trust signal when the
  authentication details cannot be scraped.

### Fixed
- Removed the intrusive auto-toggle of Gmail's details panel.

## [1.6.1] - 2026-09-11

### Added
- Client-side LIME cache keyed by SHA-256.

### Fixed
- Gmail-injected scans and `.eml` scans of the same message now agree
  (Gmail's `mailed-by` / `signed-by` forwarded as a synthesized
  `Authentication-Results`).
- Fewer false positives on DKIM-verified senders.

## [1.6.0] - 2026-09-11

### Added
- RFC 7489 sender authentication (SPF, DKIM, DMARC, organisational
  alignment) and Spamhaus DBL.
- URL reputation cascade: SQLite cache, Google Safe Browsing, PhishTank,
  URLhaus, Spamhaus DBL.
- `sender_auth` and `url_reputation` in the `/analyse` response,
  `GET /reputation/stats`, and matching UI chips.

## [1.5.0] - 2026-09-11

### Added
- Trained URL and metadata Random Forest agents loaded from Hugging Face.
- Scan history and analytics dashboard in the popup, CSV and JSON export.

## [1.4.0] - 2026-09-11

### Changed
- Cloud backend moved to an Oracle Cloud Always Free VM.
- FP32 inference by default, LIME budget reduced to 100 samples.

### Added
- `/health` endpoint used for warm-up pings.

## Earlier versions (untagged)

2026-06-14 to 2026-09-11: initial release of the extension and backend,
backend URL selector, Hugging Face Hub model fallback, and hosting on
Hugging Face Spaces then Render before the Oracle Cloud move.

[1.13.0]: https://github.com/AnzouK/PhishLens/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/AnzouK/PhishLens/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/AnzouK/PhishLens/compare/v1.10.2...v1.11.0
[1.10.2]: https://github.com/AnzouK/PhishLens/compare/v1.10.1...v1.10.2
[1.10.1]: https://github.com/AnzouK/PhishLens/compare/v1.10.0...v1.10.1
[1.10.0]: https://github.com/AnzouK/PhishLens/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/AnzouK/PhishLens/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/AnzouK/PhishLens/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/AnzouK/PhishLens/compare/v1.6.2...v1.7.0
[1.6.2]: https://github.com/AnzouK/PhishLens/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/AnzouK/PhishLens/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/AnzouK/PhishLens/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/AnzouK/PhishLens/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/AnzouK/PhishLens/releases/tag/v1.4.0
