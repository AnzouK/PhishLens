# Changelog

All notable changes to PhishLens are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/). The extension and the
backend share one version number.

## [Unreleased]

### Fixed
- `/health` and `/` answer `HEAD` requests (200 instead of 405), so
  uptime monitors that probe with `HEAD`, such as UptimeRobot's free
  plan, no longer report the server as down.

## [2.0.8] - 2026-10-17

### Added
- `scripts/benchmark.py`: a public, reproducible benchmark of a PhishLens
  server on labelled `.eml` and `.mbox` files, with the confusion matrix
  per detected language and 95% confidence intervals; results are cached
  without the emails so a run resumes and can be published. It shows its
  progress, prints the report of what was scored when stopped with
  Ctrl+C, and `--sample N` scores at most N emails per label, always the
  same ones. It keeps each check's score and says which check the false
  alarms and the missed phishing come from, and on which trust path.

### Fixed
- **A link score alone no longer flags legitimate mailing-list mail.**
  The trained link model scores the written-out links of plain-text
  mail near 1.0, and a plain `http://` link was enough to let it force
  the verdict: it decided all 14 remaining false alarms of the public
  benchmark. It now needs a threat-intelligence hit or a strong sign (a
  raw IP address, "@" before the host, a suspicious TLD, a file on a
  public cloud host). Replayed on the benchmark's scores with the link
  score never deciding alone, false alarms go from 14 to 1 of 297, for
  2 of 500 phishing emails missed in addition.
- **The text model reads the subject again.** It was trained and
  measured on "subject + body", but the server gave it the body only, in
  Gmail, Outlook and `.eml` scans alike. On 120 phishing emails the
  public benchmark missed, its score went from 10% on average with the
  body alone to 94% with the subject. The "Why?" words come from the
  same text.
- Legitimate emails scanned from a `.eml` file (popup, website, API) are
  no longer flagged because of their headers. The trained metadata
  Random Forest scored modern and mailing-list headers near 1.0 and
  forced the verdict: the public benchmark found 43.8% of legitimate
  mailing-list emails flagged, 121 of the 130 by that check alone. It is
  now off by default (`METADATA_MODEL_ENABLED=1` turns it back on); the
  sender score comes from the rules and the real SPF, DKIM and DMARC
  results, as it already did for Gmail scans.

### Documentation
- The public benchmark runs, from 2.0.7 to 2.0.8, with their full
  figures and what each one showed (`docs/evaluation.md`). On 2.0.8:
  1 of 297 legitimate mailing-list emails flagged (95% CI 0.1% to
  1.9%) and 436 of 500 phishing emails caught (84.0% to 89.8%), against
  130 of 297 and 461 of 500 on 2.0.7. The README shows the 2.0.8
  figures next to the text model's.
- The figures of the multilingual model come with their counts and 95%
  confidence intervals (README, website, project overview, model notes):
  English 1/255 legitimate emails flagged and 1,805/1,952 phishing caught,
  French 1/63 and 202/231.
- `docs/evaluation.md`: what each figure measures, why every rate comes
  with its count and a confidence interval, the benchmark protocol and
  its public sources.

## [2.0.7] - 2026-10-16

### Added
- **Brand impersonation:** an email whose sender name is a known brand
  (Chronopost, La Poste, PayPal, DHL, Spotify, banks, administrations in
  France, Nigeria and elsewhere) while the address belongs to another
  domain loses every softer trust path, and its sender score is at least
  0.9, which makes it phishing. The banner, the popup and the website
  say "Uses the name X, sent from Y". The extension now sends the sender
  name it shows with the address.
- The release workflow can also be started by hand from the Actions
  tab: it tags `main` with the code's version and publishes the release.
- **Links to public cloud hosts** (Google Cloud Storage, Firebase,
  Azure Blob, R2, Pages, IPFS gateways...) raise the link score.

### Changed
- Links that only go to large known sites (Amazon, Coinbase, La Poste...)
  are no longer scored by the trained link model, which read their long
  tracking links as phishing (a real Amazon order link was at 97%).
- Without any sender information (pasted text), the sender score shows
  "not checked" instead of a default value.
- The explanation no longer shows words such as "the", "votre" or "est".
- The website shows "Phishing risk: X%" instead of "Overall score".
- The allowlist of authenticated senders covers large European and
  international senders as well as Nigerian ones.

### Fixed
- **Readable buttons on any Gmail or Outlook theme:** in automatic mode
  the banner and button colours followed the system, so a light Gmail on
  a dark system showed a white label on a light orange hover. They now
  follow the mail page itself, and change with it.
- The social preview image (shown when the website link is shared)
  still gave the former address; it now shows phishlens.dev and the
  same tagline as the website (shield icon, "8 languages"), and its URL
  carries a content hash so that apps load the new image.

## [2.0.6] - 2026-10-16

### Added
- After a report is sent, its reference comes with a **Copy** button
  (extension and website), to keep it for a deletion request.

## [2.0.5] - 2026-10-16

### Changed
- **New address: phishlens.dev.** The website and PhishLens Cloud move
  from `anzouk.duckdns.org`, a free dynamic-DNS name of the kind
  phishing campaigns also use, to `phishlens.dev`. The extension uses the
  new address; the former one keeps answering the API for older
  versions of the extension and redirects its pages.
- Privacy policy and terms: the new address (dated October 16, 2026).

### Documentation
- README rewritten shorter: what PhishLens checks, a **Privacy** section
  (what is sent where, what is kept), and the figures with how far they
  can be trusted, before installation. The configuration table moved to
  the operations guide and the project layout to the contributing guide.
- Website: the results show the share of phishing caught on real mail
  instead of an offline F1 score, with how it was measured; the privacy
  text says exactly what is and is not kept.
- The project overview explains which numbers to trust and why; the
  credits say who trained the original models.

## [2.0.4] - 2026-10-15

### Added
- **Release workflow:** pushing a version tag publishes the GitHub
  release with `PhishLens-extension-<version>.zip` and the version's
  changelog section, after checking that the tag matches the code.

### Changed
- Installation (website, README, user guide) uses the extension zip of
  each release; the Chrome Web Store description mentions Outlook.
- The README lists every backend module and script, and the roadmap
  puts the Chrome Web Store after Outlook, Yahoo Mail and the research
  work.
- CI lints the website scripts as well as the extension.

### Documentation
- Latency measured again with the multilingual text model, result cache
  off: `/analyse` median 65 ms for text, 57 ms for a full `.eml`, p95
  120 ms, no failure over 472 requests (README, website, operations
  guide). The load test now turns the result cache off and waits for the
  model instead of a fixed delay.

## [2.0.3] - 2026-10-15

### Added
- `FEEDBACK_NOTIFY_CLICK`: the address a report notification opens when
  tapped, with the report's reference after `#`.
- `scripts/translation_review.py`: exports a translation to a workbook a
  native speaker can correct, and copies the corrections back.

### Fixed
- **PhishTank:** without an application key the feed allows only a few
  downloads a day, and the backend downloaded it at every start and every
  hour, so it was refused. It now downloads every 6 hours (1 hour with
  `PHISHTANK_API_KEY`), the compressed file, keeps the last good copy
  next to the cache and loads it at start; `/reputation/stats` gives the
  reason of a refused download (`phishtank_last_error`).
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
- **Redaction:** a word was treated alone only when separated by
  spaces, so a line break could join two lines into one "username" and
  mask a real word; and the server's second pass masked the extension's
  own placeholders again (`<<NAME>>`). Words are now split on any
  whitespace and placeholders are left alone; a test checks that
  redacting twice changes nothing.

## [2.0.1] - 2026-10-15

### Added
- The website's "try it" result shows the detected language, with
  Correct / Not this language, and **Wrong verdict? Report it**, with the
  same redaction as the extension (`site/redact.js` is a copy of
  `extension/lib/redact.js`, written by `scripts/build_site.py`).
- Every popup result can be reported, files and attachments included:
  the person pastes the part of the email to send, and the text is
  redacted as it is pasted.

### Fixed
- **Insights:** the report panel of a scan marked Wrong closed as soon
  as it opened, and the report button only appeared for Gmail and
  Outlook scans whose text was kept; it now appears for every scan
  marked Wrong.
- The documentation, the website and the user guide no longer say the
  text model reads only English.

## [2.0.0] - 2026-10-15

### Added
- **Multilingual text model support:** the backend reads how a text
  model expects its input and how to read its scores from
  `phishlens_text_agent.json` next to the model (text normalisation,
  temperature calibration, its own override threshold), so the
  multilingual model can replace the English DistilBERT by changing
  `HF_MODEL_REPO`. Each model repository is stored in its own folder.
- **Multilingual OCR:** Tesseract's script detection picks the language
  packs per image (Latin languages, Cyrillic, Arabic, Chinese, Japanese,
  Korean, Hindi); the Docker images install them.
- Gmail's "mailed-by" / "signed-by" rows are recognised in Spanish,
  Portuguese, German, Italian and Dutch too (fallback when the full
  headers are not available).
- **Interface in 8 languages:** English, French, Portuguese, Spanish,
  German, Italian, Dutch and Hausa, for the popup, the Gmail and Outlook
  banners, attachment results and notifications. The language follows
  the browser by default and can be changed in Settings. The Hausa
  translation is a draft awaiting review by a native speaker.
- **About and credits in Settings:** link to the source code and the
  threat-intelligence sources, models, libraries and datasets PhishLens
  builds on; the same list is in the README.
- `/health` names the running text model, and "Test connection" shows
  the server version and that name.
- **Detected language** under each verdict (Gmail, Outlook, popup), with
  "Correct" / "Not this language"; the answer is kept in the history and
  the CSV / JSON exports. `/analyse` returns `language`.
- **Report a wrong verdict** from the banner, the popup or Insights: the
  email is redacted in the browser (names, the user's own name and
  address, email addresses, phone and long numbers, IBANs, handles, link
  paths), shown for editing and sent to PhishLens Cloud only after a
  confirmation; the server redacts it again and keeps it without any IP
  address (`POST /feedback`, `FEEDBACK_DIR`). Insights can also share the
  reviewed history as statistics, without subject, sender or text.
- Website: the header comes back as soon as you scroll up, and a "Back to
  top" button appears on long pages.
- **Website in 8 languages:** the same languages as the extension, each
  at its own address (`/fr/`, `/pt/`, ...), with a language menu,
  `hreflang` links for search engines and, on an English page, a link to
  the visitor's own language. The privacy policy and terms are
  translated too; the English version prevails. Built by
  `scripts/build_site.py` from `site-src/`.

### Security
- **Allowlist only for authenticated senders:** a domain in
  `TRUSTED_DOMAINS` gave the softest trust path on the From: text alone,
  so a forged `alerts@gtbank.com` was treated as the bank. The allowlist
  now applies only when DKIM is aligned with From: (real headers or
  Gmail's "signed-by") or for internal Outlook mail; otherwise the
  message stays on its normal path.
- **No internal details in error responses:** server errors return
  a short reference; the details stay in the logs.
- **Request size limits:** oversized fields are refused (422) and
  bodies above 45 MB are refused before parsing (413).
- Office XML from attachments is parsed with defusedxml; the URL
  reputation cache moves from `/tmp` to `~/.cache/phishlens`.

### Fixed
- **Model inference no longer blocks the server:** the text model,
  the agents and attachment extraction (PDF, OCR, archives) run in a
  worker thread, so one slow scan no longer stalls every other request.
- **Chrome Web Store:** the manifest description is under the 132
  character limit.


### Changed
- **PhishLens Cloud reads emails in 22 languages:** its text model is now
  a multilingual mmBERT-small, distilled from a larger multilingual
  detector and calibrated. On real mail it never saw, with a 0.7
  threshold: 0.4% false alarms and 92.5% of phishing caught in English,
  1.6% and 87.4% in French. Self-hosted backends keep the English
  DistilBERT unless `HF_MODEL_REPO` says otherwise.
- README and website illustrations redrawn in light and dark with the
  detected language and the report link.
- **License: GNU AGPL-3.0** instead of MIT. PhishLens stays free and open
  source; a modified version, including one run as an online service,
  must now be published under the same license. Versions up to 1.15.5
  remain available under MIT.
- The popup footer and the website no longer present PhishLens as a
  student project; the README explains where it started.
- **Backend split by responsibility:** the 1,688-line
  `extension_backend.py` now only holds the HTTP layer; `settings.py`
  (version, environment, every scoring constant), `email_parsing.py`,
  `sender_trust.py` with `trusted_domains.py`, `text_model.py`,
  `structured_agents.py`, `fusion.py` (verdict rules as pure functions)
  and `rf_agent.py` (inference-only Random Forest wrapper; the training
  code stays in PhishingDetector). Same API, same verdicts.
- **Extension:** one shared library (`lib/shared.js`) for the server
  URL, HTML escaping and error messages, which were copied in three
  files (the popup fell back to the local server where the rest used
  PhishLens Cloud). The service worker no longer pings the server every
  10 minutes, and the `alarms` permission is gone. API errors such as an
  oversized email are shown as readable text.
- `/health` and `/` report the version; `/health` says when the text
  model is not loaded. The PhishTank feed is downloaded over HTTPS.
- **PhishTank works again, without flagging shared hosts:** the feed
  was requested over plain HTTP and never loaded; over HTTPS it does.
  Its domain-level match no longer applies to hosts shared by unrelated
  owners (cloud storage buckets, link shorteners, file-sharing and form
  services, email click trackers, big platforms): there only the exact
  listed URL counts. Before, one phishing page on storage.googleapis.com
  or one bit.ly link flagged every link of that host.
- Version history moved out of code comments into this changelog.

### Development
- Ruff lint (pycodestyle, pyflakes, bugbear, pyupgrade, simplify,
  isort, complexity) and format on `backend/` and `scripts/`, pinned in
  CI; a version check between the backend and the extension; coverage
  minimum 80% (83.8%), with new tests for the fusion rules, the text
  model wrapper, agent loading and the reputation clients; optional
  pre-commit hooks.

### Documentation
- `docs/languages.md`: how the interface, the website, the OCR and the
  text model handle languages, how translations are checked and how to
  add one.
- `docs/architecture.md`: every extension and backend module after the
  split, and the text-model settings file. `docs/operations.md`:
  switching the text model, OCR language packs, building the website.
  `docs/threat-model.md`: request limits, model switching, PhishTank on
  shared hosts, escaped translations; reviewed for this version.
- README, project overview and contributing guide point to the user
  guide (wiki) and describe the translation workflow.

## [1.15.5] - 2026-10-13

Security fix from an external code review, and clearer reporting of which
checks ran.

### Security
- **Sender alignment under shared public suffixes:** the alignment built
  from Gmail's "signed-by" compared only the last two labels of each
  domain, so a message from `billing@paypal.co.uk` signed by
  `attacker.co.uk` was treated as DMARC-aligned and could get the softer
  trust path; the header parser had a short list of two-part suffixes
  with the same gap for others (`attacker.com.ng` vs `firstbank.com.ng`).
  Both now use one organisational-domain rule that keeps three labels
  under country-code registries (co, com, org, gov, edu, ac, ...) and on
  shared-hosting suffixes (github.io, web.app, duckdns.org, ...), with
  regression tests.

### Added
- **Which checks ran:** `/analyse` returns `agents.<name>.source`
  (`model`, `rules` or `none`), so a missing or bypassed trained model is
  visible in every result, and `auth_source` (`headers` when the real
  Authentication-Results header was read, `gmail_ui` when the result comes
  from the "signed-by" / "mailed-by" that Gmail shows, `none`). `/health`
  lists which agents run a trained model.

### Fixed
- **Website upload box:** a long file name no longer spills out of the
  box; it wraps on two lines at most (full name on hover) and the size
  shows on its own line.

## [1.15.4] - 2026-10-05

Archives now say which file inside is the problem.

### Added
- **Files named inside archives:** `/analyse_attachment` returns
  `attachment.suspicious_files` for ZIP, RAR and 7z attachments, one row
  per member with the reasons in plain words: fake extension, program,
  script, shortcut, disk image, archive inside the archive, macros,
  remote template, login form, flagged link, or phishing wording (the
  text model scores each inner file on its own). The Gmail attachment
  card and the popup show them under **Do not open** (phishing verdict)
  or **Check before opening** (safe verdict but something stands out),
  followed by the full list of files, folded. File names are inserted as
  text, never as HTML.

### Changed
- Popup drop zone lists every supported attachment type (ZIP, RAR, 7z
  and .ics included), also after a file is removed.

## [1.15.3] - 2026-10-05

RAR and 7z attachments are opened, like ZIP.

### Added
- **RAR and 7z archives** (`backend/archive_analysis.py`): listed with
  `rarfile` and `py7zr`, risky members flagged (executables, scripts,
  shortcuts, disk images, double extensions, nested archives), and the
  supported files inside (PDF, Office, HTML, images, text) analysed one
  level deep, with the same limits as ZIP (500 entries, 5 inner files,
  5 MB each, 15 MB in total, compression ratio 100). Password-protected
  archives, including those whose file list is encrypted (`rar -hp`,
  `7z -mhe`), are flagged `encrypted_archive`. 7z members are written to
  a private temporary folder, deleted at once, after the size checks;
  RAR members are decompressed by `bsdtar` (`libarchive-tools`, now in
  the Docker images). A RAR whose members cannot be decompressed is
  flagged `inner_files_not_extracted`; a damaged or multi-volume archive
  stays `uninspectable_archive`.

### Changed
- ZIP, RAR and 7z share one listing and inner-file routine.
- Website and README list RAR and 7z among the supported attachments;
  the RAR / 7z item is removed from the roadmap.

## [1.15.2] - 2026-10-05

Small operations release: a result cache, an uptime alert, weekly
encrypted backups, and a warning before emails would leave in clear text.

### Added
- **Result cache** (`backend/result_cache.py`): `/analyse` and `/explain`
  answers are kept in memory for 24 hours, keyed by a SHA-256 of the
  request (never the email itself). The same email scanned twice, or
  auto-scanned then opened, answers at once with `"cached": true`, and
  "Why this verdict?" gives the same words on every click. The
  `auto_scan` flag does not split entries; a result where a check failed
  is not cached. `RESULT_CACHE_TTL` (0 turns it off) and
  `RESULT_CACHE_MAX`; hit rate in `/reputation/stats`.
- **Weekly backups** (`scripts/backup.sh`): server configuration, backend
  data (consistent SQLite copies) and access logs, uploaded to any rclone
  remote (an encrypted crypt remote is recommended); archives older than
  60 days are removed. See `docs/operations.md`.
- **Uptime alert** note in `docs/operations.md` (any external monitor on
  `/health`).

### Changed
- **Custom backend URL:** the settings warn when an `http://` address
  points outside this computer or the home network, since emails would
  then cross the internet unencrypted.
- **Privacy policy:** lists the 24-hour result cache and the 30-day
  web-server logs.
- **README:** notes that the paper describes PhishLens as it was when
  written, with later changes in the CHANGELOG.

## [1.15.1] - 2026-10-02

Look and feel release: the website, the popup and the README pictures
now share one style, in light and dark.

### Changed
- **Popup controls in the accent colour:** checkboxes, radios and the
  keyboard focus ring use the PhishLens orange instead of the browser
  blue; the selected backend is a plain card with an orange border; the
  footer fits on one line.
- **Illustrations in light and dark** (`scripts/build_illustrations.py`):
  the README shows `docs/*-light.svg` or `docs/*-dark.svg` to match the
  reader's GitHub theme, and the website uses the dark ones. The dark
  Gmail pictures use the extension's real dark-mode colours, the canvas
  is transparent so it takes the page background, and the popup picture
  is redrawn from the real popup in both themes.
- **Website rebuilt** (`site/`): "Console" style (charcoal background,
  one orange accent, system fonts, line icons, aligned rows, borders
  instead of shadows, no gradients, glows, glass or hover animations;
  results and live server counters up front, features, a fuller install
  guide, a paste-from-clipboard button, fixed-size check panels, centred
  mobile layout),
  Gmail and Outlook covered, one call to action ("Install PhishLens"),
  the live check form with validation, a honeypot and a submit
  throttle, loading indicators, and the live server table. Stylesheet
  and script moved to `/style.css` and `/app.js` (no inline code, ready
  for a strict Content-Security-Policy).

### Added
- **Popup restyled like the website** (same charcoal palette, orange
  accent, small radii, no gradients or press animations; the light theme
  uses the site's paper tones) and the **extension version** in the
  popup footer.
- **Terms of use** (`TERMS.md`, `/terms.html`), a custom `/404.html`,
  `robots.txt`, `sitemap.xml`, a social preview image (`/img/og.png`),
  `favicon.ico` and `apple-touch-icon.png`, canonical and Open Graph
  tags on every page. `scripts/build_site_pages.py` rebuilds the privacy,
  terms and 404 pages from the Markdown sources.
- **Privacy policy:** a "This website" section (no cookies, visit counts
  from server logs kept 30 days).

### Security
- **CodeQL alerts #12 and #13:** the Outlook sender name no longer goes
  through a one-pass tag strip (incomplete sanitization), and the
  organisation domain is validated label by label instead of with a
  nested-quantifier regex.

## [1.15.0] - 2026-10-02

Real-mail release: Gmail full headers, automatic scanning, Outlook on
the web, live evaluation, and scoring fixes found by testing on a real
inbox (header and URL models on 2026 mail).

### Added
- **Full headers in Gmail:** with "Read full headers" on (default), a
  scan fetches the message behind Gmail's "Show original" (all headers
  and text parts, no attachment files) and sends it as a full email, so
  the metadata agent and the SPF/DKIM/DMARC checks see the real Received
  chain, Authentication-Results, Reply-To and so on. Falls back to the
  visible page when Gmail does not serve it. Banner chip "Full headers
  checked".
- **Automatic scanning (opt-in):** with "Scan new emails automatically"
  on, unread emails in the inbox list are fetched through "Show
  original" and scanned one at a time (10 per pass, cached by thread),
  without opening them. Phishing gets a red "Phishing?" pill on the row
  and a desktop notification (new `notifications` permission); results
  go to the history as "Gmail (automatic)".
- **Live evaluation:** each scan in Insights can be marked "Right" or
  "Wrong"; a "Live accuracy" block shows reviewed scans, accuracy, false
  alarms and missed phishing, and the CSV export has a `label` column.
  `scripts/live_eval.py` turns an exported JSON history into a report
  (confusion matrix, precision, recall, false-positive rate with 95%
  intervals, per source) without printing subjects or senders.
- **Outlook on the web** (`outlook.office.com`, `outlook.office365.com`,
  `outlook.live.com`): a "Scan with PhishLens" button under the subject
  and the same verdict banner, scores, chips and word-level explanation
  as in Gmail, on the last expanded message of a conversation. Manual
  scans only for now (no attachments, full headers or automatic scan
  yet); history source "Outlook".
- **Privacy policy** (`PRIVACY.md`), published at `/privacy.html` on the
  site and linked from the footer.
- **Backend:** `.eml` scans also collect the real link targets of the
  HTML part, and accept `client_context.link_urls`.

### Changed
- **Outlook internal senders:** Outlook hides the address of senders
  from the user's own organisation. Such mail (already authenticated by
  the organisation's server) now gets the soft path, as a new
  `outlook_internal` trust path (text weight x0.6, threshold 0.62, no
  single-agent override except Safe Browsing), and the organisation's
  domain, read from the folder pane, is used for the allowlist check. An
  "Internal sender" pill shows it.
- **PhishLens Cloud** (formerly "Cloud demo") is the hosted backend for
  normal use and the **default** for new installs; existing settings are
  kept. Renamed everywhere (settings, README, site, privacy policy,
  threat model).
- Removed the unused `http://130.61.146.213/*` host permission.

### Fixed
- **Insights chart:** daily buckets used the UTC date, so east of
  Greenwich today's scans fell outside the 30-day chart.
- **HTML-only emails:** `.eml` bodies (and the full-headers Gmail scans)
  were turned into text with a tag strip that kept `<style>` contents,
  so the text model read CSS ("25px", "roboto"). `html_to_text` now
  keeps only the visible text. CSS-like tokens are also left out of the
  "Top phishing tokens" stats.
- **URL agent and the single-agent override:** on the default path the
  URL agent alone forces "phishing" only with a concrete sign (a
  threat-intelligence hit, or a rule: raw IP, plain http, `@`,
  suspicious TLD). Its score still counts in the fusion. Same rule for
  attachments. Removes false alarms on legitimate unverified senders
  whose links merely have a path.
- **Disconnected content scripts** (after an extension update) stop
  their observers and no longer log "Extension context invalidated".
- **Open tabs after an update:** Chrome does not inject content scripts
  into tabs that are already open, so the background worker now does it
  on install and update (new `scripting` permission, Outlook hosts added
  to `host_permissions`); the new copy replaces the old buttons. No more
  "please refresh this tab" after an update.
- **Trained URL model and hidden links:** on real 2026 links the URL
  Random Forest scores almost any URL with a path at ~0.95
  (`github.com/user/repo` 0.95, `wikipedia.org/wiki/...` 0.97; a bare
  domain 0.05), so feeding it the hidden link targets flagged nearly
  every HTML email. It now only judges the URLs written in the text, as
  in training; hidden targets (Gmail hrefs, HTML parts, QR codes) get
  the rule-based score and the threat-intelligence lookups.
- **Text the text model reads:** a scan with the full original sends the
  page text too, and the backend uses it for the text agent (a GitHub CI
  email scored 0.51 on the page text and 0.998 on its plain-text part,
  which spells every URL out). `.eml` bodies now come from the rendered
  HTML part first, then the plain-text part.
- **Extension updates without refreshing Gmail:** after an update, the
  old copy of the content script stays in open tabs, cut off from the
  extension ("please refresh this tab"). Each copy now tags its buttons,
  a newer copy replaces the old ones, and a disconnected copy stops.
- **Insights chart:** bars were sized in percent inside an auto-height
  column and collapsed to 2px; they are sized in pixels now. Function
  words ("have", "good") are left out of "Top phishing tokens".
- **Full headers and the trained header model:** on real 2026 Gmail
  headers (ARC, X-Gm-*, long Received chains) the trained metadata
  Random Forest scored legitimate mail at ~1.0 (it was trained on older
  corpora). Scans that send Gmail's "Show original"
  (`client_context.headers_source = "gmail_show_original"`) now use the
  header heuristics plus the real SPF/DKIM/DMARC results instead, until
  the model is retrained on modern headers. Automatic-scan results from
  before the fix are discarded.
- **Sent messages:** a message without delivery headers (one you sent)
  is scanned from the page instead of "Show original".
- **Attachment-only emails** sent as full `.eml` no longer get a 400:
  headers and links are scored, the text agent is left out.
- **Outlook:** the banner sits under the subject bar instead of inside
  the message; drafts in a conversation are ignored; the button frees up
  before the word-level explanation arrives.
- **Banner meters** wrap on narrow reading panes instead of overlapping.
- **Automatic scan:** safe emails get a green "Safe" pill too.
- **Automatic scan feedback:** a status toast in Gmail shows the scan in
  progress and its result.

## [1.14.1] - 2026-10-01

Security fix for the v1.14 parsers, and a one-command redeploy.

### Added
- **`scripts/redeploy.sh`:** one-command redeploy on the VM (pull,
  build, restart, health check and smoke `/analyse`, landing page copy),
  with automatic rollback to the previous image when the new one is not
  healthy, and `--rollback` to undo by hand.

### Security
- **CodeQL alerts #9 to #11 (polynomial regular expressions):** the
  forwarded-sender lookup and the HTML stripping of calendar invites
  used regexes that could backtrack badly on crafted input. They are
  replaced by linear, bounded parsing (`email.utils.parseaddr` on the
  first "From:" line, and a split-based tag stripper); the forward
  markers only match spaces and tabs, not newlines.

## [1.14.0] - 2026-09-30

Real-inbox release: conversations, forwarded and image-only emails,
hidden and shared links, and attachments PhishLens could not read before.

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

[Unreleased]: https://github.com/AnzouK/PhishLens/compare/v2.0.8...HEAD
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
