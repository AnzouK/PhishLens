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
pip install -r requirements.txt pytest pytest-cov ruff
uvicorn extension_backend:app --host 127.0.0.1 --port 8000
```

Load the extension from `extension/` in `chrome://extensions` (Developer
mode, Load unpacked) and pick the local backend in the gear menu.
See [docs/architecture.md](docs/architecture.md) for how the pieces fit.

## Checks to run before a pull request

```bash
cd backend
ruff check . --select E9,F63,F7,F82
pytest -q --cov=. --cov-config=.coveragerc
```

For extension changes, lint the JavaScript too (from the repo root):

```bash
npm install --no-save --no-package-lock eslint@9 globals@15
npx eslint extension/
```

CI runs all of the above, plus CodeQL. A pull request needs a green CI.

## Guidelines

- **Tests.** New backend logic comes with a test in `backend/tests/`.
  Tests must stay offline: no model download, no network. Patch
  `text_agent` and use the fakes in `test_reputation.py` as examples.
- **Scoring changes** (weights, thresholds, trust paths) must update the
  tables in the README and `docs/architecture.md`, and should explain in
  the pull request which false positive or false negative they fix.
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

Maintainers bump the version in `extension/manifest.json`, move the
"Unreleased" entries under the new version in `CHANGELOG.md`, tag
`vX.Y.Z` on `main` and publish the GitHub release.
