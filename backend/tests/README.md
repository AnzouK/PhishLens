# PhishLens backend tests

Offline pytest suite. Nothing here loads DistilBERT or touches the
network: `conftest.py` stubs torch / transformers / lime when they are
not installed, the endpoint tests patch the text agent with a fixed
score, and the reputation tests replace every threat-intel tier with an
in-process fake.

| File | What it pins |
| --- | --- |
| `test_auth_headers.py` | RFC 7489 SPF/DKIM/DMARC parsing, org-domain alignment, spoof rejection |
| `test_attachment_analysis.py` | MIME sniffing, size cap, HTML feature flags, unsupported types |
| `test_feature_extraction.py` | URL and metadata features consumed by the Random Forest agents (names and semantics) |
| `test_reputation.py` | SQLite cache and TTL, GSB daily quota, cascade scoring, cache reuse |
| `test_extension_backend.py` | `/health`, `/analyse`, `/analyse_attachment`, `/metrics`, the four trust paths, heuristic agents |

Run locally:

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install pytest pytest-cov beautifulsoup4 numpy fastapi httpx prometheus-fastapi-instrumentator
pytest -q --cov=. --cov-config=.coveragerc
```

CI (`.github/workflows/ci.yml`) runs the same command on every push and
pull request and prints the coverage table in the job log.
