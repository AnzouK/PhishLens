# Changelog

All notable changes to PhishLens are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/). The extension and the
backend share one version number.

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

[1.10.0]: https://github.com/AnzouK/PhishLens/compare/v1.9.0...v1.10.0
[1.9.0]: https://github.com/AnzouK/PhishLens/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/AnzouK/PhishLens/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/AnzouK/PhishLens/compare/v1.6.2...v1.7.0
[1.6.2]: https://github.com/AnzouK/PhishLens/compare/v1.6.1...v1.6.2
[1.6.1]: https://github.com/AnzouK/PhishLens/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/AnzouK/PhishLens/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/AnzouK/PhishLens/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/AnzouK/PhishLens/releases/tag/v1.4.0
