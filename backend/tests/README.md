# PhishLens backend tests

This is an offline pytest suite. Nothing here loads a model or touches
the network. `conftest.py` stubs torch, transformers and lime when they
are not installed, the endpoint tests patch the text agent with a fixed
score, and the reputation tests replace every threat-intel tier with an
in-process fake. Tests that need an optional dependency (Tesseract,
OpenCV, scikit-learn, skops) skip themselves when it is missing.

What each file covers:

- `test_auth_headers.py` checks RFC 7489 SPF, DKIM and DMARC parsing,
  organisational-domain alignment and spoof rejection.
- `test_attachment_analysis.py` covers MIME sniffing, the size cap, HTML
  feature flags and unsupported types.
- `test_ocr.py` covers OCR of images and scanned PDFs, QR decoding and
  image size limits.
- `test_office_analysis.py` covers Word, Excel and PowerPoint text and
  links, macros, remote templates, DDE, zip bombs, and legacy and
  encrypted files.
- `test_feature_extraction.py` pins the URL and metadata features the
  Random Forest agents consume.
- `test_reputation.py` covers the SQLite cache and its TTL, the Safe
  Browsing daily quota, cascade scoring and cache reuse.
- `test_agent_io.py` checks the skops round trip of the agents and the
  type allowlist.
- `test_reputation_clients.py` runs the Safe Browsing, PhishTank and
  URLhaus clients against fake HTTP servers.
- `test_fusion.py` tests every verdict rule, from trust-path precedence
  and weights to overrides, the attachment bonus and droppers.
- `test_text_model.py` tests the text agent wrapper and LIME selection
  with stand-ins for torch, transformers and LIME.
- `test_structured_agents.py` covers loading the trained URL and
  metadata agents, pickle refusal and the rule fallback.
- `test_rf_agent.py` covers inference of the Random Forest agents
  (feature padding, joblib fallback).
- `test_bypass_*.py` holds every way we found to make a phishing email
  look safer, grouped by topic. `sender` covers forged results and
  impersonation, `html` hidden text and links, `text` invisible
  characters and source shown as text, `urls` URL tricks and known
  sites, `attachments` pages, scripts, archives and file names, and
  `office` Office and OLE2 documents. The JSON files in
  `tests/fixtures/` are shared with the extension's tests through
  `conftest.shared_cases`.
- `test_extension_backend.py` covers the endpoints, request limits and
  errors, the trust paths (allowlist only for authenticated senders),
  attachment trust inheritance and `/metrics`.

To run them locally:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install pytest pytest-cov fastapi httpx prometheus-fastapi-instrumentator \
            numpy pandas beautifulsoup4 pdfplumber pypdfium2 pillow pytesseract \
            opencv-python-headless reportlab scikit-learn joblib skops rarfile py7zr defusedxml \
            slowapi
pytest -q --cov=. --cov-config=.coveragerc
```

The extension has its own tests at the repository root.
`node --test tests/extension/*.test.js` covers the library code with no
dependencies, and `npx playwright test --config tests/ui/playwright.config.js`
covers the popup.
