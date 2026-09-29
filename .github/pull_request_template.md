## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `ruff check backend --select E9,F63,F7,F82` and `pytest` pass locally
- [ ] Extension changes: `npx eslint extension/` reports no errors
- [ ] New or changed backend logic has a test (offline, no model, no network)
- [ ] Scoring changes are reflected in the README and `docs/architecture.md`
- [ ] Entry added to `CHANGELOG.md` under "Unreleased"
- [ ] No secrets or personal data in the diff, fixtures or screenshots
