# Contributing to PhishLens

Thanks for taking the time. Bug reports, false-positive and
false-negative samples, and pull requests are all welcome.

## Before you start

- **Security issues** do not go in public issues. Follow
  [SECURITY.md](SECURITY.md).
- **A wrong verdict** is a regular issue. Include the verdict, the
  per-agent scores and `trust_path` from the response, and a redacted
  copy of the email (remove names, addresses and anything personal).
- For anything bigger than a small fix, open an issue first so we can
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
site/                     website in 8 languages, generated from site-src/
tests/                    extension unit tests (node:test), popup and website UI tests (Playwright)
docs/                     architecture, threat model, operations, languages, model
scripts/                  website build, redeploy and backup, load test,
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
node --test tests/extension/*.test.js
```

The popup and website UI tests need Playwright: `npm install --no-save @playwright/test@1`,
`npx playwright install chromium`, then
`npx playwright test --config tests/ui/playwright.config.js`.

## Texts and translations

- **Extension texts** are never written in the code: add a key to
  `extension/lib/locales/en.js` and to the seven other locale files, and
  call `t("key")`. `node --test tests/extension/*.test.js` lists missing
  keys, placeholders or tags, and fails on a translated text built into
  HTML without `escapeHTML`.
- **Website texts** live in `site-src/`; edit them there, run
  `python3 scripts/build_site.py` (needs pandoc) and commit `site/` with
  the change. Do not edit `site/` by hand.
- **Privacy policy and terms:** a change to `PRIVACY.md` or `TERMS.md`
  comes with the same change in `site-src/legal/<lang>/`.
- Details, and how to add a language: [docs/languages.md](docs/languages.md).

CI runs all of the above, plus CodeQL. A pull request needs a green CI.

## Guidelines

- **Tests.** New backend logic comes with a test in `backend/tests/`.
  Tests must stay offline: no model download, no network. Patch
  `text_model.text_agent`, and use the fakes in `test_reputation.py` and
  `test_text_model.py` as examples.
- **Scoring changes** (weights, thresholds, trust paths) are made in
  `backend/settings.py` and `backend/fusion.py`, with a test in
  `test_fusion.py`; update the tables in `docs/architecture.md` and
  explain in the pull request which false positive or false negative
  they fix.
- **Feature engineering** in `feature_extraction.py` is shared with the
  trained Random Forests. Changing feature names or semantics requires
  retraining in [PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector).
- **Regular expressions** on email or URL input must use bounded
  quantifiers (CodeQL checks for ReDoS).
- **No secrets and no personal data** in code, commits, fixtures or
  screenshots.
- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`).
- **Changelog.** Add a line under an "Unreleased" heading in
  [CHANGELOG.md](CHANGELOG.md).

## Releases

Maintainers bump the version in `extension/manifest.json` and
`backend/settings.py` (CI checks they agree), move the
"Unreleased" entries under the new version in `CHANGELOG.md` and push
the tag `vX.Y.Z` on `main`. The release workflow
(`.github/workflows/release.yml`) checks that the tag matches the code,
zips `extension/` and publishes the GitHub release with that zip and the
version's changelog section.
