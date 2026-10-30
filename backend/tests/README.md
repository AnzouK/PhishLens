# PhishLens backend tests

Offline pytest suite. Nothing here loads DistilBERT or touches the
network: `conftest.py` stubs torch / transformers / lime when they are
not installed, the endpoint tests patch the text agent with a fixed
score, and the reputation tests replace every threat-intel tier with an
in-process fake. Tests that need an optional dependency (Tesseract,
OpenCV, scikit-learn, skops) skip themselves when it is missing.

| File | What it pins |
| --- | --- |
| `test_auth_headers.py` | RFC 7489 SPF/DKIM/DMARC parsing, org-domain alignment, spoof rejection |
| `test_attachment_analysis.py` | MIME sniffing, size cap, HTML feature flags, unsupported types |
| `test_ocr.py` | OCR of images and scanned PDFs, QR decoding, image size limits |
| `test_office_analysis.py` | Word / Excel / PowerPoint text and links, macros, remote templates, DDE, zip bombs, legacy and encrypted files |
| `test_feature_extraction.py` | URL and metadata features consumed by the Random Forest agents |
| `test_reputation.py` | SQLite cache and TTL, GSB daily quota, cascade scoring, cache reuse |
| `test_agent_io.py` | skops round trip of the agents and the type allowlist |
| `test_reputation_clients.py` | Safe Browsing, PhishTank and URLhaus clients against fake HTTP servers |
| `test_fusion.py` | every verdict rule: trust-path precedence, weights, overrides, attachment bonus and droppers |
| `test_text_model.py` | text agent wrapper and LIME selection with stand-ins for torch / transformers / LIME |
| `test_structured_agents.py` | loading the trained URL / metadata agents, pickle refusal, rule fallback |
| `test_rf_agent.py` | inference of the Random Forest agents (feature padding, joblib fallback) |
| `test_bypasses.py` | each way found to make a phishing email look safer (audits): forged results, impersonation variants, hidden text and links, URL tricks, attachment links; `tests/fixtures/hidden_cases.json` is shared with the extension's tests |
| `test_extension_backend.py` | endpoints, request limits and errors, the trust paths (allowlist only for authenticated senders), attachment trust inheritance, `/metrics` |

Run locally:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install pytest pytest-cov fastapi httpx prometheus-fastapi-instrumentator \
            numpy pandas beautifulsoup4 pdfplumber pypdfium2 pillow pytesseract \
            opencv-python-headless reportlab scikit-learn joblib skops rarfile py7zr defusedxml
pytest -q --cov=. --cov-config=.coveragerc
```

The extension has its own tests at the repository root:
`node --test tests/extension/*.test.js` (library code, no dependencies)
and `npx playwright test --config tests/ui/playwright.config.js` (popup).
