# PhishLens project overview

This page is the entry point to everything that makes up the project.
PhishLens is spread over two repositories, two Hugging Face model repos,
a live deployment, a user guide and a written report; each piece is
linked below with what it is for.

## The artefacts

| Artefact | What lives there |
| --- | --- |
| [AnzouK/PhishLens](https://github.com/AnzouK/PhishLens) (this repo) | The runtime system: Chrome MV3 extension, FastAPI backend, landing page, CI, security policy. What you clone to install and run PhishLens. |
| [dodi-ctrl/PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector) | The research side: the three Colab training notebooks, dataset loaders, augmentation cell, per-agent metrics and known model limitations. What you clone to retrain or reproduce the models. |
| AnzouKiona/phishlens-text-v2 (private) | The multilingual text agent PhishLens Cloud runs (mmBERT-small, distilled and calibrated). Private because part of its training mail is; how it was built: [multilingual-model.md](multilingual-model.md). |
| [AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert) | The fine-tuned English DistilBERT text agent (model card, weights, tokenizer). The default of a self-hosted backend. |
| [AnzouKiona/phishlens-agents](https://huggingface.co/AnzouKiona/phishlens-agents) | The trained URL and metadata Random Forest agents (joblib). Pulled by the backend at startup. |
| [anzouk.duckdns.org](https://anzouk.duckdns.org) | Website in 8 languages: landing page, try-it widget, privacy policy and terms, and the PhishLens Cloud backend used by the extension's "PhishLens Cloud" setting. |
| [Wiki](https://github.com/AnzouK/PhishLens/wiki) | The user guide: installing, using PhishLens in Gmail and Outlook, reading a verdict, settings, troubleshooting. |
| Project report | B.Sc. final-year report (Department of Cybersecurity, Nile University of Nigeria, 2025/2026): literature review, methodology, evaluation. Not published here; available on request through the university. |

## Documentation map

| Question | Where to look |
| --- | --- |
| How do I install and use it? | [README](../README.md), Quickstart section |
| How do I use it day to day? | The [wiki](https://github.com/AnzouK/PhishLens/wiki) |
| How is the system built, and why that way? | [architecture.md](architecture.md) |
| Which languages are supported, and how are translations made and checked? | [languages.md](languages.md) |
| How was the multilingual text model built, and how good is it? | [multilingual-model.md](multilingual-model.md) |
| Which text model is running, and how is it switched? | [architecture.md, text model](architecture.md#text-model) and [operations.md](operations.md#switch-the-text-model) |
| What can go wrong security-wise, and what stops it? | [threat-model.md](threat-model.md) |
| How do I run, monitor and load-test a deployment? | [operations.md](operations.md) |
| How were the models trained and how good are they? | [PhishingDetector README](https://github.com/dodi-ctrl/PhishingDetector#at-a-glance) and the Hugging Face model cards |
| What are the known limitations? | [threat-model.md, residual risks](threat-model.md#residual-risks-and-known-limitations) and [PhishingDetector, Limitations](https://github.com/dodi-ctrl/PhishingDetector#limitations) |
| What changed between versions? | [CHANGELOG.md](../CHANGELOG.md) and [GitHub Releases](https://github.com/AnzouK/PhishLens/releases) |
| How do I report a vulnerability? | [SECURITY.md](../SECURITY.md) |
| How do I contribute? | [CONTRIBUTING.md](../CONTRIBUTING.md) |

## Development lifecycle at a glance

| Phase | How it is covered |
| --- | --- |
| Requirements and scope | Project report (problem statement, objectives); README "What it does" |
| Design | [architecture.md](architecture.md), including the design decisions and their rationale |
| Implementation | Conventional commits, semantic version tags, one tag per release; Ruff and ESLint in CI |
| Security (SSDLC) | [threat-model.md](threat-model.md), CodeQL on every push, Dependabot alerts and weekly version updates, [SECURITY.md](../SECURITY.md), per-IP rate limiting, least-privilege CI token |
| Testing | Offline pytest suite in `backend/tests/` (80% coverage minimum in CI); extension unit tests (node:test), including the translation checks; popup and website UI tests (Playwright); model evaluation in the PhishingDetector notebooks |
| Deployment | Docker images (`Dockerfile.local`, `Dockerfile.cloud`), Caddy with Let's Encrypt on an Oracle Cloud VM |
| Operations | Structured logging, Prometheus `/metrics`, `/health` and `/reputation/stats`, Locust load test ([operations.md](operations.md)) |
| Maintenance | [CHANGELOG.md](../CHANGELOG.md), Dependabot, GitHub Releases, roadmap in the README |

## Headline numbers

| Agent | Model | Accuracy | F1 |
| --- | --- | --- | --- |
| Text (self-hosted default) | DistilBERT (fine-tuned) | 97.34% | 0.9665 |
| URL | Random Forest, 23 features | 99.34% | 0.9911 |
| Metadata | Random Forest, 37 features | 99.92% | 0.9994 |

PhishLens Cloud's multilingual text model, on real mail it never saw
(0.7 threshold): 0.4% false alarms and 92.5% of phishing caught in
English, 1.6% and 87.4% in French
([multilingual-model.md](multilingual-model.md)).

The table is measured on held-out splits; see PhishingDetector for the datasets and the
evaluation protocol. These are offline numbers, not live-traffic numbers
(see the residual risks in the threat model).
