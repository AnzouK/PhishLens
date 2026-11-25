# Contributing to PhishLens

Thanks for taking the time. Bug reports, false-positive and
false-negative samples, and pull requests are all welcome.

## Before you start

Please don't report security issues in public. [SECURITY.md](SECURITY.md)
explains how to send them privately.

A wrong verdict is a normal issue. Include the verdict, the per-agent
scores and `trust_path` from the response, and a redacted copy of the
email with names, addresses and anything personal removed.

For anything bigger than a small fix, open an issue first so we can
agree on the approach.

## Setup

```bash
git clone https://github.com/AnzouK/PhishLens.git
cd PhishLens/backend
python3 -m venv .venv && source .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt pytest pytest-cov "ruff==0.16.10" reportlab
# OCR needs the tesseract binary: brew install tesseract / apt install tesseract-ocr
uvicorn extension_backend:app --host 127.0.0.1 --port 8000
```

Load the extension from `extension/` in `chrome://extensions` (Developer
mode, Load unpacked) and pick the local backend in the gear menu.
See [docs/architecture.md](docs/architecture.md) for how the pieces fit.

## Project layout

```
backend/                  FastAPI app (one module per concern)
  extension_backend.py      HTTP API: endpoints, limits, metrics
  settings.py               version, environment, scoring constants
  email_parsing.py          text, links and headers of an email
  sender_trust.py           sender domain, allowlist, Gmail auth hints
  text_model.py             text agent and LIME; text_normalize.py, language.py
  structured_agents.py      URL and metadata agents (rf_agent.py, agent_io.py)
  fusion.py                 scores to verdict (pure functions)
  auth_headers.py           SPF / DKIM / DMARC and Spamhaus DBL
  reputation.py             threat-intel cascade with SQLite cache
  attachment_analysis.py    attachments: PDF, HTML, images (ocr.py), Office
                            (office_analysis.py), archives (archive_analysis.py)
  feedback.py               reports users send, redacted again (redaction.py)
  tests/                    offline pytest suite
extension/                Chrome MV3 extension (plain JS, no build step)
  background.js             service worker: every request to the server
  lib/                      shared libraries, one globalThis name each
                            (api.js, dom.js, constants.js, gmail_page.js...)
  content_scripts/          Gmail and Outlook pages: core.js creates the
                            PhishLensPage namespace the other files add to
  popup/                    the popup, as ES modules (one per view)
site/                     website in 8 languages, generated from site-src/
functions/                Cloudflare Pages Function: the API proxy of phishlens.dev
tests/                    extension and Pages Function unit tests (node:test), popup and
                          website UI tests (Playwright)
docs/                     architecture, threat model, operations, languages, model
scripts/                  website and extension builds, benchmark, load test,
                          translation review, report deletion, version check
```

## Checks to run before a pull request

```bash
ruff check backend/ scripts/          # rules in ruff.toml
ruff format backend/ scripts/         # one code style
python scripts/check_version.py       # backend and extension versions agree
cd backend && pytest -q --cov=. --cov-config=.coveragerc   # 80% minimum
```

`pip install pre-commit && pre-commit install` runs the first three on
every commit.

For extension changes, lint the JavaScript too (from the repo root):

```bash
npm install --no-save --no-package-lock eslint@9 globals@15
npx eslint . --max-warnings 0
node --test tests/extension/*.test.js tests/functions/*.test.mjs
```

The popup and website UI tests need Playwright. Install it with
`npm install --no-save @playwright/test@1` and
`npx playwright install chromium`, then run
`npx playwright test --config tests/ui/playwright.config.js`.

## Texts and translations

Extension texts never go in the code. Add a key to
`extension/lib/locales/en.js` and to the seven other locale files, then
call `t("key")`. `node --test tests/extension/*.test.js` lists missing
keys, placeholders or tags, and fails on any HTML built from a string
(`innerHTML`). Build nodes with `h()` from `extension/lib/dom.js`. The
`*_html` translations go through `setMarkup`, which only keeps a short
list of tags.

Website texts live in `site-src/`. Edit them there, run
`python3 scripts/build_site.py` (it needs pandoc) and commit `site/`
with the change. Don't edit `site/` by hand.

A change to `PRIVACY.md` or `TERMS.md` needs the same change in
`site-src/legal/<lang>/`. [docs/languages.md](docs/languages.md) has
the details and explains how to add a language.

CI runs all of the above, plus CodeQL. A pull request needs a green CI.

## Guidelines

New backend logic needs a test in `backend/tests/`. Tests must stay
offline, with no model download and no network. Patch
`text_model.text_agent` and look at the fakes in `test_reputation.py`
and `test_text_model.py` for examples.

Scoring changes (weights, thresholds, trust paths) belong in
`backend/settings.py` and `backend/fusion.py`, with a test in
`test_fusion.py`. Update the tables in `docs/architecture.md` too, and
say in the pull request which false positive or false negative the
change fixes.

`feature_extraction.py` is shared with the trained Random Forests. If
you change feature names or their meaning, the forests have to be
retrained in [PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector).

In the extension, never build HTML from strings. Use `h()` from
`extension/lib/dom.js` so text from an email is never parsed as markup
(a test fails on `innerHTML`). Server requests go through `PhishLensApi`
in `lib/api.js`. Anything that depends on Gmail's page goes in
`lib/gmail_page.js`, with a sample page in `tests/fixtures/gmail/`. An
empty `catch` either explains in a comment why the error is ignored or
calls `PhishLensShared.debug()`.

Regular expressions that run on email or URL input must use bounded
quantifiers. CodeQL checks for ReDoS.

Keep secrets and personal data out of code, commits, fixtures and
screenshots.

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`). Add a line under
an "Unreleased" heading in [CHANGELOG.md](CHANGELOG.md).

## Releases

Maintainers bump the version in `extension/manifest.json` and
`backend/settings.py` (CI checks they agree), move the
"Unreleased" entries under the new version in `CHANGELOG.md` and push
the tag `vX.Y.Z` on `main`. The release workflow
(`.github/workflows/release.yml`) checks that the tag matches the code,
zips `extension/` and publishes the GitHub release with that zip and the
version's changelog section. The same workflow can be started by hand
from the Actions tab (**Release**, then **Run workflow** on `main`). In
that case it creates the tag from the code's version.
