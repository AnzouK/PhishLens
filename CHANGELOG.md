# Changelog

All notable changes to PhishLens are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/). The extension and the
backend share one version number.

## [Unreleased]

### Security
Fixes from several rounds of outside review; each bypass has a test in
`backend/tests/test_bypasses.py`.
- Sender checks: Authentication-Results is read clause by clause (no
  more `dkim=pass` hidden in a comment or a quoted address), and a
  second From:, a From: with several addresses or domains, or ARC
  results alone no longer prove anything. The From: is read as written,
  not as Python's parser rebuilds it, encoded names are decoded wherever
  they stand, and an address inside a quoted display name no longer
  counts as a second sender (an encoded name stays a name, whatever it
  says, and keeps the quotes it stands in). Notifications from sharing
  services (Google Docs, DocuSign, Dropbox...) that show their user's
  own address are no longer taken for impersonation, nor are SharePoint
  Online, Amazon Pay and Colissimo. Gmail's "signed-by" is only read
  outside the email body.
- Brand impersonation catches look-alike domains (`paypal.tk`,
  `chronopost.us`), look-alike letters and padded or malformed names.
- Hidden text and links (inline styles, `<style>` rules, near-invisible
  colours, tiny links) go after the visible ones, on the server and in
  the extension, which share their test cases; words a style sheet
  writes with `::before` are read too.
- Links are read like a browser reads them (`HTTPS:evil.tk`,
  backslashes, encoded hosts, `www.` in plain text), and hidden or
  written-out links can no longer push the real ones out of the check.
  Forms and shared files on large sites (Microsoft Forms, OneDrive,
  SharePoint, Google Docs) and redirects to `www.` addresses no longer
  count as links to a known site, nor do redirect pages. A huge inline
  image, comment or flood of decoy links before the real link no longer
  hides it, and links inside SVG drawings are read in the browser too.
  Long comments are left out of the text (their links are still
  checked), style sheets written inside "<!-- -->" apply, and "/./" in a
  path no longer hides a redirect.
- A huge `<style>` sheet can no longer stall the server.
- Zero-width spaces, soft hyphens and control characters inside a word
  no longer cut it in pieces for the text model, and can no longer hide
  a file's real extension.
- Safe Browsing: a link it did not check is never cached as clean, a
  scan sends it at most 30 links, and its key stays out of the logs.
- Attachments: forms, frames and pages inside `data:` addresses are
  read in HTML files, with addresses built by scripts; names that
  Windows runs as programs ("invoice.exe ." or with a direction mark)
  are caught; a ZIP is read by what it holds, whatever its name, and an
  Office file stays an Office file whatever else its ZIP holds; Office
  parts are read whatever their name or case, Word fields as Word
  builds them, and templates, frames, "Run program" actions, Excel DDE
  and programs packed in embedded objects are flagged (OLE files read
  from their directory, in any case); .xlsb workbooks, drawings and
  document properties are read for links; an Office file holding other
  files lists them like an archive, though not the chart workbooks and
  SVG pictures Office adds itself; SVG, web archives and HTML smuggling
  are read; 7z files are unpacked in memory.
- Outlook: the sender's real address is used, and "internal" mail only
  gets the soft path.
- Personal mailboxes and platforms that relay their users' messages
  (Google, PayPal, DocuSign...) left the allowlist.
- Pickle model files are refused unless `AGENTS_ALLOW_PICKLE=1`.

### Added
- A Firefox build (Firefox 140+), attached to each release.
- A privacy notice in Gmail and Outlook before the first PhishLens Cloud
  scan.

### Changed
- Long display names no longer break a scan, and the automatic scan
  skips an email the server refuses instead of stopping.
- Server cleanup: one Spamhaus lookup, one sender-domain function,
  `feature_extraction.py` cut to what the models read (same outputs).
- Website: one headline figure, and who runs PhishLens and why.
- Shorter docs.

### Fixed
- Scans saved at the same moment no longer overwrite each other.
- The website's live counters no longer show an error code when the
  server is slow.

## [2.0.11] - 2026-10-28

### Added
- `HF_MODEL_REVISION` and `HF_AGENTS_REVISION` pin the exact commit of
  the models the server downloads; a warning is logged when they are
  not set, and `/health` reports the revision.
- The popup warns that a local server reads the text with the English
  model, and the connection test says so when it does.
- `scripts/export_benchmark.py` and `docs/benchmark/`: the public runs
  behind the website's figures, one line per email (id, label, verdict,
  scores), comparable with anyone's own run.
- Every `/analyse` answer says which sign forced the verdict
  (`forced_by`).
- The home page in each language describes PhishLens to search engines
  with a schema.org `SoftwareApplication` block (JSON-LD): a free,
  open-source security application for Chrome, its languages, licence,
  download page and source code.

### Changed
- The signs that force a verdict on each trust path are declared with
  the path (`TrustPath.forcing`) instead of in branches; verdicts are
  unchanged.
- The website and the README show the scan time of a typical email (190
  ms, 65 ms for a short one), the 6 languages checked on real phishing
  (of the 22 the text model reads), and the false alarms as 1 of 414.
- The changelog keeps one short entry per change; the measurements are
  in `docs/evaluation.md`.
- The website's results show the whole system as it runs, in the 8
  languages: 90.6% of 2,000 recent phishing emails nobody had looked at
  caught, and 1 of 414 legitimate emails flagged (0.2%), instead of the
  text model's offline score alone.
- Extension code reorganised, same behaviour: the popup is split into ES
  modules, one per view; every request to the server, from the popup as
  from the mail pages, goes through the service worker (`lib/api.js`),
  which also keeps the explanation cache; no HTML is built from strings
  any more: elements come from `h()` (`lib/dom.js`) and the translated
  texts with markup are rebuilt from an allowlist of tags; a test fails
  on `innerHTML`.
- A failed word-level explanation in Gmail and Outlook now says so,
  instead of "Computing the explanation…" forever.

### Fixed
- A large inline image (a `data:` URI) before an email's links pushed
  them past the part of the HTML the scan reads: a bank's welcome email
  with a 600 KB banner showed no link at all.
- In Gmail, an email too large to display shows its HTML source as text;
  that text was scored as the email's wording (99%, a false alarm on a
  DKIM-signed bank email).
- Transaction alerts sent through `email-messaging.com` click tracking
  were taken for links "elsewhere" and flagged by the link rule.
- A sender showing "E.Leclerc" or "Stanbic IBTC" from another domain is
  now flagged as impersonation (a fake Leclerc prize email was rated
  safe).

### Documentation
- The privacy policy and the terms, in the 8 languages, say who runs
  PhishLens (a personal, non-commercial project maintained by an
  individual), where PhishLens Cloud is hosted (Oracle Cloud
  Infrastructure, Frankfurt) and through whom the domain's DNS goes
  (Cloudflare), give a contact address, privacy@phishlens.dev, and
  explain how to ask what is kept and have it deleted.
- `docs/evaluation.md` and `docs/multilingual-model.md`: r7b, the bigger
  text model (mmBERT-base): 91.2% of the control phishing caught against
  r4's 90.4%, one more inbox false alarm and twice the scan time.
- `docs/evaluation.md` and `docs/multilingual-model.md`: r7h, a text
  model leaning more on the true labels, measured against the system
  with the link rule: 93.0% of the control phishing caught against r4's
  90.4%, the same false alarms, below the +3 points set before training.

## [2.0.10] - 2026-10-24

### Added
- `scripts/benchmark.py --domain-age` adds to each cached result the age
  of the sender's domain when the email was sent, looked up with RDAP
  from the machine running the benchmark (`scripts/domain_age.py`).
- `scripts/benchmark.py --link-profile` adds to each cached result where
  the email's links go compared with its sender's domain: to the
  sender's own domain, to large known sites, to public file hosts,
  through a mass-mailing platform's click tracking, or elsewhere.

### Changed
- Every `/analyse` answer reports where the links go compared with the
  sender's domain (`link_alignment`: counts only). **On the
  `crypto_verified` path, links that all lead away from the sender's
  domain** (click tracking and large known sites aside) **with a text
  score of 0.5 or more force the phishing verdict**: a DKIM signature
  proves the domain, not the sender's honesty.

### Fixed
- An email the parser rejects is scanned instead of refused.

### Documentation
- The link rule, measured on the running server: 90.6% of 2,000 fresh
  phishing emails caught (95% CI 89.2% to 91.8%).
- `docs/evaluation.md` and `docs/multilingual-model.md`: two changes
  measured and not shipped.

## [2.0.9] - 2026-10-23

### Added
- The popup says where emails go before the first scan.
- `scripts/benchmark.py --exclude`: leaves out the emails of earlier
  runs, so a change tuned on one sample is measured on a control sample
  nobody looked at (`docs/evaluation.md`).
- `scripts/benchmark.py --show-errors` prints, on the machine running it
  only, the sender domain and subject of each false alarm and missed
  phishing.

### Documentation
- The README and the project overview show the 2.0.9 figures: 85.5% of
  1,997 control phishing emails caught, 1 of 297 mailing-list emails and
  0 of 117 real inbox emails flagged.
- `docs/evaluation.md`: a control sample of 2,000 phishing emails nobody
  looked at (85.5% caught, 83.9% to 87.0%), 117 legitimate emails from
  real inboxes received after the model's training mail (1.7% flagged),
  and a change measured and rejected: letting a confident text score
  decide on the `crypto_verified` path would catch 7 points more
  phishing but doubles the false alarms on real inbox mail.

### Changed
- The `/analyse` handler is split into named steps (scores, sender
  trust, response blocks), and the email parser, the reputation cascade
  and the PDF, Office and archive parsers into smaller functions.

### Fixed
- Mail relayed through Microsoft 365 keeps its authenticated sender.
- Confidence intervals no longer print "-0.0%" as their lower bound.
- `/health` and `/` answer `HEAD` requests (200 instead of 405), so
  uptime monitors that probe with `HEAD`, such as UptimeRobot's free
  plan, no longer report the server as down.

## [2.0.8] - 2026-10-17

### Added
- `scripts/benchmark.py`: a public, reproducible benchmark of a
  PhishLens server on labelled `.eml` and `.mbox` files, with the
  confusion matrix per detected language and 95% confidence intervals.

### Fixed
- A link score alone no longer flags legitimate mailing-list mail.
- The text model reads the subject again.
- Legitimate emails scanned from a `.eml` file (popup, website, API) are
  no longer flagged because of their headers.

### Documentation
- The public benchmark runs, from 2.0.7 to 2.0.8, with their full
  figures and what each one showed (`docs/evaluation.md`).
- The figures of the multilingual model come with their counts and 95%
  confidence intervals (README, website, project overview, model notes):
  English 1/255 legitimate emails flagged and 1,805/1,952 phishing
  caught, French 1/63 and 202/231.
- `docs/evaluation.md`: what each figure measures, why every rate comes
  with its count and a confidence interval, the benchmark protocol and
  its public sources.

## [2.0.7] - 2026-10-16

### Added
- Brand impersonation: an email whose sender name is a known brand
  (Chronopost, La Poste, PayPal, DHL, Spotify, banks, administrations in
  France, Nigeria and elsewhere) while the address belongs to another
  domain loses every softer trust path, and its sender score is at least
  0.9, which makes it phishing.
- The release workflow can also be started by hand from the Actions tab:
  it tags `main` with the code's version and publishes the release.
- Links to public cloud hosts (Google Cloud Storage, Firebase, Azure
  Blob, R2, Pages, IPFS gateways...) raise the link score.

### Changed
- Links that only go to large known sites (Amazon, Coinbase, La
  Poste...) are no longer scored by the trained link model, which read
  their long tracking links as phishing (a real Amazon order link was at
  97%).
- Without any sender information (pasted text), the sender score shows
  "not checked" instead of a default value.
- The explanation no longer shows words such as "the", "votre" or "est".
- The website shows "Phishing risk: X%" instead of "Overall score".
- The allowlist of authenticated senders covers large European and
  international senders as well as Nigerian ones.

### Fixed
- Readable buttons on any Gmail or Outlook theme: in automatic mode the
  banner and button colours followed the system, so a light Gmail on a
  dark system showed a white label on a light orange hover.
- The social preview image (shown when the website link is shared) still
  gave the former address.

## [2.0.6] - 2026-10-16

### Added
- After a report is sent, its reference comes with a **Copy** button
  (extension and website), to keep it for a deletion request.

## [2.0.5] - 2026-10-16

### Changed
- New address: phishlens.dev.
- Privacy policy and terms: the new address (dated October 16, 2026).

### Documentation
- README rewritten shorter: what PhishLens checks, a **Privacy** section
  (what is sent where, what is kept), and the figures with how far they
  can be trusted, before installation.
- Website: the results show the share of phishing caught on real mail
  instead of an offline F1 score, with how it was measured.
- The project overview explains which numbers to trust and why; the
  credits say who trained the original models.

## [2.0.4] - 2026-10-15

### Added
- Release workflow: pushing a version tag publishes the GitHub release
  with `PhishLens-extension-<version>.zip` and the version's changelog
  section, after checking that the tag matches the code.

### Changed
- Installation (website, README, user guide) uses the extension zip of
  each release; the Chrome Web Store description mentions Outlook.
- The README lists every backend module and script, and the roadmap puts
  the Chrome Web Store after Outlook, Yahoo Mail and the research work.
- CI lints the website scripts as well as the extension.

### Documentation
- Latency measured again with the multilingual text model, result cache
  off: `/analyse` median 65 ms for text, 57 ms for a full `.eml`, p95
  120 ms, no failure over 472 requests (README, website, operations
  guide).

## [2.0.3] - 2026-10-15

### Added
- `FEEDBACK_NOTIFY_CLICK`: the address a report notification opens when
  tapped, with the report's reference after `#`.
- `scripts/translation_review.py`: exports a translation to a workbook a
  native speaker can correct, and copies the corrections back.

### Fixed
- PhishTank: without an application key the feed allows only a few
  downloads a day, and the backend downloaded it at every start and
  every hour, so it was refused.
- The README badge and the website's "Model" link point to the
  multilingual model's documentation.
- A report needs at least three words; the report panel now says so
  instead of leaving **Send** greyed out without a reason.
- Writing a report and deleting one (`scripts/delete_report.py`) share a
  lock on the report folder, so a report sent during a deletion is not
  lost.

## [2.0.2] - 2026-10-15

### Added
- `FEEDBACK_NOTIFY_URL`: a one-line message for each new report (kind,
  verdict, languages, origin and reference, never the text), for example
  to an ntfy topic followed on a phone.

### Fixed
- The website's scripts and stylesheet carry a hash of their content, so
  a browser loads the new version right after a deployment instead of a
  cached one (the language line and the report link did not show up).
- A test replaced only the first `*` of a URL pattern (CodeQL).
- Redaction: a word was treated alone only when separated by spaces, so
  a line break could join two lines into one "username" and mask a real
  word.

## [2.0.1] - 2026-10-15

### Added
- The website's "try it" result shows the detected language, with
  Correct / Not this language, and **Wrong verdict? Report it**, with
  the same redaction as the extension (`site/redact.js` is a copy of
  `extension/lib/redact.js`, written by `scripts/build_site.py`).
- Every popup result can be reported, files and attachments included:
  the person pastes the part of the email to send, and the text is
  redacted as it is pasted.

### Fixed
- Insights: the report panel of a scan marked Wrong closed as soon as it
  opened, and the report button only appeared for Gmail and Outlook
  scans whose text was kept.
- The documentation, the website and the user guide no longer say the
  text model reads only English.

## [2.0.0] - 2026-10-15

### Added
- Multilingual text model support: the backend reads how a text model
  expects its input and how to read its scores from
  `phishlens_text_agent.json` next to the model (text normalisation,
  temperature calibration, its own override threshold), so the
  multilingual model can replace the English DistilBERT by changing
  `HF_MODEL_REPO`.
- Multilingual OCR: Tesseract's script detection picks the language
  packs per image (Latin languages, Cyrillic, Arabic, Chinese, Japanese,
  Korean, Hindi); the Docker images install them.
- Gmail's "mailed-by" / "signed-by" rows are recognised in Spanish,
  Portuguese, German, Italian and Dutch too (fallback when the full
  headers are not available).
- Interface in 8 languages: English, French, Portuguese, Spanish,
  German, Italian, Dutch and Hausa, for the popup, the Gmail and Outlook
  banners, attachment results and notifications.
- About and credits in Settings: link to the source code and the
  threat-intelligence sources, models, libraries and datasets PhishLens
  builds on; the same list is in the README.
- `/health` names the running text model, and "Test connection" shows
  the server version and that name.
- Detected language
- Report a wrong verdict
- Website: the header comes back as soon as you scroll up, and a "Back
  to top" button appears on long pages.
- Website in 8 languages: the same languages as the extension, each at
  its own address (`/fr/`, `/pt/`, ...), with a language menu,
  `hreflang` links for search engines and, on an English page, a link to
  the visitor's own language.

### Security
- Allowlist only for authenticated senders: a domain in
  `TRUSTED_DOMAINS` gave the softest trust path on the From: text alone,
  so a forged `alerts@gtbank.com` was treated as the bank.
- No internal details in error responses: server errors return a short
  reference; the details stay in the logs.
- Request size limits: oversized fields are refused (422) and bodies
  above 45 MB are refused before parsing (413).
- Office XML from attachments is parsed with defusedxml; the URL
  reputation cache moves from `/tmp` to `~/.cache/phishlens`.

### Fixed
- Model inference no longer blocks the server: the text model, the
  agents and attachment extraction (PDF, OCR, archives) run in a worker
  thread, so one slow scan no longer stalls every other request.
- Chrome Web Store: the manifest description is under the 132 character
  limit.


### Changed
- PhishLens Cloud reads emails in 22 languages: its text model is now a
  multilingual mmBERT-small, distilled from a larger multilingual
  detector and calibrated.
- README and website illustrations redrawn in light and dark with the
  detected language and the report link.
- License: GNU AGPL-3.0
- The popup footer and the website no longer present PhishLens as a
  student project; the README explains where it started.
- Backend split by responsibility: the 1,688-line `extension_backend.py`
  now only holds the HTTP layer.
- Extension: one shared library (`lib/shared.js`) for the server URL,
  HTML escaping and error messages, which were copied in three files
  (the popup fell back to the local server where the rest used PhishLens
  Cloud).
- `/health` and `/` report the version; `/health` says when the text
  model is not loaded.
- PhishTank works again, without flagging shared hosts: the feed was
  requested over plain HTTP and never loaded; over HTTPS it does.
- Version history moved out of code comments into this changelog.

### Development
- Ruff lint (pycodestyle, pyflakes, bugbear, pyupgrade, simplify, isort,
  complexity) and format on `backend/` and `scripts/`, pinned in CI.

### Documentation
- `docs/languages.md`: how the interface, the website, the OCR and the
  text model handle languages, how translations are checked and how to
  add one.
- `docs/architecture.md`: every extension and backend module after the
  split, and the text-model settings file.
- README, project overview and contributing guide point to the user
  guide (wiki) and describe the translation workflow.

## [1.15.5] - 2026-10-13

Security fix from an external code review, and clearer reporting of which
checks ran.

### Security
- Sender alignment under shared public suffixes: the alignment built
  from Gmail's "signed-by" compared only the last two labels of each
  domain, so a message from `billing@paypal.co.uk` signed by
  `attacker.co.uk` was treated as DMARC-aligned and could get the softer
  trust path.

### Added
- Which checks ran: `/analyse` returns `agents.<name>.source` (`model`,
  `rules` or `none`), so a missing or bypassed trained model is visible
  in every result, and `auth_source` (`headers` when the real
  Authentication-Results header was read, `gmail_ui` when the result
  comes from the "signed-by" / "mailed-by" that Gmail shows, `none`).

### Fixed
- Website upload box: a long file name no longer spills out of the box;
  it wraps on two lines at most (full name on hover) and the size shows
  on its own line.

## [1.15.4] - 2026-10-05

Archives now say which file inside is the problem.

### Added
- Files named inside archives: `/analyse_attachment` returns
  `attachment.suspicious_files` for ZIP, RAR and 7z attachments, one row
  per member with the reasons in plain words: fake extension, program,
  script, shortcut, disk image, archive inside the archive, macros,
  remote template, login form, flagged link, or phishing wording (the
  text model scores each inner file on its own).

### Changed
- Popup drop zone lists every supported attachment type (ZIP, RAR, 7z
  and .ics included), also after a file is removed.

## [1.15.3] - 2026-10-05

RAR and 7z attachments are opened, like ZIP.

### Added
- RAR and 7z archives

### Changed
- ZIP, RAR and 7z share one listing and inner-file routine.
- Website and README list RAR and 7z among the supported attachments;
  the RAR / 7z item is removed from the roadmap.

## [1.15.2] - 2026-10-05

Small operations release: a result cache, an uptime alert, weekly
encrypted backups, and a warning before emails would leave in clear text.

### Added
- Result cache
- Weekly backups
- Uptime alert

### Changed
- Custom backend URL: the settings warn when an `http://` address points
  outside this computer or the home network, since emails would then
  cross the internet unencrypted.
- Privacy policy: lists the 24-hour result cache and the 30-day
  web-server logs.
- README: notes that the paper describes PhishLens as it was when
  written, with later changes in the CHANGELOG.

## [1.15.1] - 2026-10-02

Look and feel release: the website, the popup and the README pictures
now share one style, in light and dark.

### Changed
- Popup controls in the accent colour: checkboxes, radios and the
  keyboard focus ring use the PhishLens orange instead of the browser
  blue.
- Illustrations in light and dark
- Website rebuilt

### Added
- Popup restyled like the website
- Terms of use
- Privacy policy: a "This website" section (no cookies, visit counts
  from server logs kept 30 days).

### Security
- CodeQL alerts #12 and #13: the Outlook sender name no longer goes
  through a one-pass tag strip (incomplete sanitization), and the
  organisation domain is validated label by label instead of with a
  nested-quantifier regex.

## [1.15.0] - 2026-10-02

Real-mail release: Gmail full headers, automatic scanning, Outlook on
the web, live evaluation, and scoring fixes found by testing on a real
inbox (header and URL models on 2026 mail).

### Added
- Full headers in Gmail: with "Read full headers" on (default), a scan
  fetches the message behind Gmail's "Show original" (all headers and
  text parts, no attachment files) and sends it as a full email, so the
  metadata agent and the SPF/DKIM/DMARC checks see the real Received
  chain, Authentication-Results, Reply-To and so on.
- Automatic scanning (opt-in): with "Scan new emails automatically" on,
  unread emails in the inbox list are fetched through "Show original"
  and scanned one at a time (10 per pass, cached by thread), without
  opening them.
- Live evaluation: each scan in Insights can be marked "Right" or
  "Wrong".
- Outlook on the web
- Privacy policy
- Backend: `.eml` scans also collect the real link targets of the HTML
  part, and accept `client_context.link_urls`.

### Changed
- Outlook internal senders: Outlook hides the address of senders from
  the user's own organisation.
- PhishLens Cloud
- Removed the unused `http://130.61.146.213/*` host permission.

### Fixed
- Insights chart: daily buckets used the UTC date, so east of Greenwich
  today's scans fell outside the 30-day chart.
- HTML-only emails: `.eml` bodies (and the full-headers Gmail scans)
  were turned into text with a tag strip that kept `<style>` contents,
  so the text model read CSS ("25px", "roboto").
- URL agent and the single-agent override: on the default path the URL
  agent alone forces "phishing" only with a concrete sign (a
  threat-intelligence hit, or a rule: raw IP, plain http, `@`,
  suspicious TLD).
- Disconnected content scripts
- Open tabs after an update: Chrome does not inject content scripts into
  tabs that are already open, so the background worker now does it on
  install and update (new `scripting` permission, Outlook hosts added to
  `host_permissions`).
- Trained URL model and hidden links: on real 2026 links the URL Random
  Forest scores almost any URL with a path at ~0.95
  (`github.com/user/repo` 0.95, `wikipedia.org/wiki/...` 0.97).
- Text the text model reads: a scan with the full original sends the
  page text too, and the backend uses it for the text agent (a GitHub CI
  email scored 0.51 on the page text and 0.998 on its plain-text part,
  which spells every URL out).
- Extension updates without refreshing Gmail: after an update, the old
  copy of the content script stays in open tabs, cut off from the
  extension ("please refresh this tab").
- Insights chart: bars were sized in percent inside an auto-height
  column and collapsed to 2px; they are sized in pixels now.
- Full headers and the trained header model: on real 2026 Gmail headers
  (ARC, X-Gm-*, long Received chains) the trained metadata Random Forest
  scored legitimate mail at ~1.0 (it was trained on older corpora).
- Sent messages: a message without delivery headers (one you sent) is
  scanned from the page instead of "Show original".
- Attachment-only emails
- Outlook: the banner sits under the subject bar instead of inside the
  message; drafts in a conversation are ignored; the button frees up
  before the word-level explanation arrives.
- Banner meters
- Automatic scan: safe emails get a green "Safe" pill too.
- Automatic scan feedback: a status toast in Gmail shows the scan in
  progress and its result.

## [1.14.1] - 2026-10-01

Security fix for the v1.14 parsers, and a one-command redeploy.

### Added
- `scripts/redeploy.sh`: one-command redeploy on the VM (pull, build,
  restart, health check and smoke `/analyse`, landing page copy), with
  automatic rollback to the previous image when the new one is not
  healthy, and `--rollback` to undo by hand.

### Security
- CodeQL alerts #9 to #11 (polynomial regular expressions): the
  forwarded-sender lookup and the HTML stripping of calendar invites
  used regexes that could backtrack badly on crafted input.

## [1.14.0] - 2026-09-30

Real-inbox release: conversations, forwarded and image-only emails,
hidden and shared links, and attachments PhishLens could not read before.

### Added
- Conversations: in a Gmail thread, the scan reads the last expanded
  message only (body, sender, links, mailed-by / signed-by), so text and
  sender can no longer come from two different emails.
- Forwarded emails: a forward marker ("Forwarded message", "Begin
  forwarded message:", "Message transféré", ...) or a Fwd:/TR: subject
  switches off the sender-trust discounts, since the forwarder is not
  the author.
- Image-only emails: with fewer than 3 words the text agent is left out
  of the fusion (`text_agent_used: false`) and the verdict rests on the
  links and the sender.
- Shared-file links: links to Google Drive / Docs / Forms, OneDrive,
  SharePoint, Dropbox, WeTransfer and similar services are listed in
  `shared_links` and shown as a warning (no score change).
- Attachments: ZIP archives (entries listed, password protection,
  executables, scripts, shortcuts, disk images and double extensions
  flagged, supported files inside analysed one level deep, zip-bomb
  guard), RAR / 7z (recognised, reported as not inspectable), calendar
  invites (`.ics`: text, links, organizer), attached emails (`.eml`,
  full email pipeline), password-protected PDFs, and executables / disk
  images attached directly.

### Fixed
- Trained URL agent and hidden links: the Random Forest extracts its
  features from text, so link targets and QR-code URLs that were not in
  the visible text are now appended to it before scoring.
- Hidden links in Gmail: the Gmail scan sent only the visible text, so a
  link written as "Click here" was never checked.
- Attachment-only emails: scanning an email with no body text no longer
  ends in "could not read the email body".
- History: attachment scans run from Gmail are now saved in the scan
  history (source "Gmail attachment"), and attachments dropped in the
  popup are labelled "attachment" instead of ".eml file".

## [1.13.0] - 2026-09-30

Interface release: new landing page, Gmail UI and popup polish.

### Changed
- Landing page rewritten
- Gmail UI redesigned
- Popup
- README illustrations
- A safe verdict with a high agent score now explains why (trusted
  sender, DKIM or Gmail delivery lowered the weight), instead of showing
  red meters under "looks safe" without context.
- Single characters and bare numbers are no longer shown among the LIME
  words.
- Roadmap: Chrome Web Store release, Outlook Web, automatic scanning,
  live evaluation.

### Fixed
- LIME words showed a weight of "0.00" (the real weights are below
  0.01).
- Attachment chips were unreadable in Gmail's light theme (dark-theme
  colours were always applied).
- The scan history stored the text-agent score as the overall score; it
  now stores the fused score.

### Security
- Threat model: R4 (pickled models) and T1 marked closed, the production
  backend runs with `AGENTS_ALLOW_PICKLE=0`.

## [1.12.0] - 2026-09-30

Attachment analysis, phase 2, and the end of pickle.

### Added
- Scanned PDFs and images.
- QR codes ("quishing").
- Word, Excel and PowerPoint
- Random Forest agents in the skops format
- Extension, popup and landing page accept all the new attachment types.
- Tests: OCR / QR / scanned PDFs, Office parsing (macros, template
  injection, DDE, zip bombs, XXE, legacy and encrypted files), skops
  round trip and allowlist, extension libraries with `node:test`, popup
  UI with Playwright (new CI job, not required yet).

### Changed
- Docker images and CI on **Python 3.12** (unblocks numpy 2.5); the
  images install `tesseract-ocr` and copy every backend module.
- The CI job "Requirements resolve (Python 3.11)" is now "Requirements
  resolve (Docker Python)".
- ESLint: every rule now fails the build (`--max-warnings 0`); the
  remaining warnings were fixed (dead Gmail helpers from v1.6.2 removed,
  unused popup variables removed).
- GitHub Actions bumped to `checkout@v7` and `setup-python@v7` (the v4 /
  v5 ones ran on the deprecated Node 20).

### Fixed
- CSV formula injection in the history export.
- The popup file picker went back to accepting only `.eml` after the
  first file was chosen.
- `.dockerignore` had an inline comment that disabled its pattern.

## [1.11.0] - 2026-09-29

### Security
- A Google Safe Browsing hit now forces the phishing verdict on the
  `trusted_sender` path too.

### Added
- CI job for the Chrome extension: `node --check` on every script, then
  ESLint (`eslint.config.mjs`).
- Branch protection on `main`: the three CI jobs must pass before a pull
  request can merge.
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
- Manual install instructions (README, CONTRIBUTING) now install the CPU
  build of torch, which `requirements.txt` deliberately leaves out.

## [1.10.2] - 2026-09-29

### Added
- CI job that resolves `backend/requirements.txt` on Python 3.11 (the
  Docker base) with `pip install --dry-run`, so dependency bumps that
  cannot install in the image fail in CI instead of at deploy time.
- DistilBERT checkpoint and Random Forest joblibs persisted on host
  volumes (see `docs/operations.md`), so re-creating the container no
  longer re-downloads them.

### Changed
- Dependabot ignores major versions of transformers, huggingface-hub and
  scikit-learn; those are upgraded by hand after a real model test.
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
  0.5 s at about 4 requests per second.

## [1.10.1] - 2026-09-29

### Fixed
- Link-free emails could be flagged as phishing on the default path.

## [1.10.0] - 2026-09-29

Engineering-process release: tests, observability and documentation.
No change to detection behaviour or to the extension's features.

### Added
- Prometheus metrics on `GET /metrics`: request count, latency and
  in-flight requests per endpoint, plus `phishlens_verdicts_total` by
  endpoint, verdict and trust path.
- `trust_path` field in the `/analyse` response (`trusted_sender`,
  `crypto_verified`, `gmail_inbox_soft` or `default`).
- Tests for `feature_extraction`, `reputation` and the FastAPI endpoints
  (`/health`, `/analyse`, `/analyse_attachment`, `/metrics`), covering
  all four trust paths and the attachment trust inheritance.
- Coverage report in CI (`pytest-cov`).
- Locust load test (`scripts/locustfile.py`).
- Documentation: `docs/project-overview.md` (hub for both repositories,
  models and report), `docs/architecture.md` (diagrams and design
  decisions), `docs/threat-model.md` (STRIDE), `docs/operations.md`
  (deploy, logging, metrics, load testing), `CONTRIBUTING.md`, this
  changelog, and a pull request template.

### Fixed
- About 20 log calls printed the literal text `{e}` instead of the error
  (missing `f` prefix).
- The remaining `print()` calls in the runtime were moved to the logger,
  and the `phishlens.*` loggers now get a handler, so INFO lines (model
  loaded, agents loaded, PhishTank feed size) actually reach `docker
  logs`.

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
- `sender_auth` and `url_reputation` in the `/analyse` response, `GET
  /reputation/stats`, and matching UI chips.

## [1.5.0] - 2026-09-11

### Added
- Trained URL and metadata Random Forest agents loaded from Hugging
  Face.
- Scan history and analytics dashboard in the popup, CSV and JSON
  export.

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

[Unreleased]: https://github.com/AnzouK/PhishLens/compare/v2.0.11...HEAD
[2.0.11]: https://github.com/AnzouK/PhishLens/compare/v2.0.10...v2.0.11
[2.0.10]: https://github.com/AnzouK/PhishLens/compare/v2.0.9...v2.0.10
[2.0.9]: https://github.com/AnzouK/PhishLens/compare/v2.0.8...v2.0.9
[2.0.8]: https://github.com/AnzouK/PhishLens/compare/v2.0.7...v2.0.8
[2.0.7]: https://github.com/AnzouK/PhishLens/compare/v2.0.6...v2.0.7
[2.0.6]: https://github.com/AnzouK/PhishLens/compare/v2.0.5...v2.0.6
[2.0.5]: https://github.com/AnzouK/PhishLens/compare/v2.0.4...v2.0.5
[2.0.4]: https://github.com/AnzouK/PhishLens/compare/v2.0.3...v2.0.4
[2.0.3]: https://github.com/AnzouK/PhishLens/compare/v2.0.2...v2.0.3
[2.0.2]: https://github.com/AnzouK/PhishLens/compare/v2.0.1...v2.0.2
[2.0.1]: https://github.com/AnzouK/PhishLens/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/AnzouK/PhishLens/compare/v1.15.5...v2.0.0
[1.15.5]: https://github.com/AnzouK/PhishLens/compare/v1.15.4...v1.15.5
[1.15.4]: https://github.com/AnzouK/PhishLens/compare/v1.15.3...v1.15.4
[1.15.3]: https://github.com/AnzouK/PhishLens/compare/v1.15.2...v1.15.3
[1.15.2]: https://github.com/AnzouK/PhishLens/compare/v1.15.1...v1.15.2
[1.15.1]: https://github.com/AnzouK/PhishLens/compare/v1.15.0...v1.15.1
[1.15.0]: https://github.com/AnzouK/PhishLens/compare/v1.14.1...v1.15.0
[1.14.1]: https://github.com/AnzouK/PhishLens/compare/v1.14.0...v1.14.1
[1.14.0]: https://github.com/AnzouK/PhishLens/compare/v1.13.0...v1.14.0
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
