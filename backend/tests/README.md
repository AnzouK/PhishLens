# PhishLens backend tests

Pure-function pytest suite for the modules that don't touch the model
(loading DistilBERT is ~3 s and blows the CI budget). Currently covers:

- `test_auth_headers.py` — RFC 7489 SPF/DKIM/DMARC parsing, org-domain
  alignment, and the spoof rejection that used to slip past the old
  static allowlist.
- `test_attachment_analysis.py` — MIME sniffing, size cap enforcement,
  HTML feature-flag extraction, plain-text and unsupported-type paths.

Run locally:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q
```

Or via the CI workflow (`.github/workflows/ci.yml`) on every push.
