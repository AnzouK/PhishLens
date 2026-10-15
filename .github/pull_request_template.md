## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `ruff check backend/ scripts/`, `ruff format --check backend/ scripts/` and `pytest` pass locally
- [ ] Extension or website changes: `npx eslint .` reports no errors
- [ ] New or changed backend logic has a test (offline, no model, no network)
- [ ] Scoring changes are made in `settings.py` / `fusion.py`, tested in `test_fusion.py` and reflected in `docs/architecture.md`
- [ ] Entry added to `CHANGELOG.md` under "Unreleased"
- [ ] No secrets or personal data in the diff, fixtures or screenshots
