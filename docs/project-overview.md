# PhishLens project overview

Where each part of PhishLens lives, and where to find answers.

## The artefacts

| Artefact | What lives there |
| --- | --- |
| [AnzouK/PhishLens](https://github.com/AnzouK/PhishLens) (this repo) | The runtime system: Chrome MV3 extension, FastAPI backend, landing page, CI, security policy. What you clone to install and run PhishLens. |
| [dodi-ctrl/PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector) | The research side: the three Colab training notebooks, dataset loaders, augmentation cell, per-agent metrics and known model limitations. What you clone to retrain or reproduce the models. |
| AnzouKiona/phishlens-text-v2 (private) | The multilingual text agent PhishLens Cloud runs (mmBERT-small, distilled and calibrated). Private because part of its training mail is; how it was built: [multilingual-model.md](multilingual-model.md). |
| [AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert) | The fine-tuned English DistilBERT text agent (model card, weights, tokenizer). The default of a self-hosted backend. |
| [AnzouKiona/phishlens-agents](https://huggingface.co/AnzouKiona/phishlens-agents) | The trained URL and metadata Random Forest agents (skops files, with the original joblib ones). Pulled by the backend at startup. |
| [phishlens.dev](https://phishlens.dev) | Website in 8 languages: landing page, try-it widget, privacy policy and terms, and the PhishLens Cloud backend used by the extension's "PhishLens Cloud" setting. |
| [Wiki](https://github.com/AnzouK/PhishLens/wiki) | The user guide: installing, using PhishLens in Gmail and Outlook, reading a verdict, settings, troubleshooting. |
| Project report | B.Sc. final-year report (Department of Cybersecurity, Nile University of Nigeria, 2025/2026): literature review, methodology, evaluation. Not published here; available on request through the university. |

## Documentation map

| Question | Where to look |
| --- | --- |
| How do I install it? | [README](../README.md#install) |
| How do I use it day to day? | The [wiki](https://github.com/AnzouK/PhishLens/wiki) |
| How is the system built, and why that way? | [architecture.md](architecture.md) |
| Which languages are supported, and how are translations made and checked? | [languages.md](languages.md) |
| How was the multilingual text model built, and how good is it? | [multilingual-model.md](multilingual-model.md) |
| Which text model is running, and how is it switched? | [architecture.md, text model](architecture.md#text-model) and [operations.md](operations.md#switch-the-text-model) |
| What can go wrong security-wise, and what stops it? | [threat-model.md](threat-model.md) |
| How do I run, monitor and load-test a deployment? | [operations.md](operations.md) |
| How were the models trained and how good are they? | [PhishingDetector README](https://github.com/dodi-ctrl/PhishingDetector#results) and the Hugging Face model cards |
| What are the known limitations? | [threat-model.md, residual risks](threat-model.md#residual-risks-and-known-limitations) and [PhishingDetector, Limitations](https://github.com/dodi-ctrl/PhishingDetector#limitations) |
| What changed between versions? | [CHANGELOG.md](../CHANGELOG.md) and [GitHub Releases](https://github.com/AnzouK/PhishLens/releases) |
| How do I report a vulnerability? | [SECURITY.md](../SECURITY.md) |
| How do I contribute? | [CONTRIBUTING.md](../CONTRIBUTING.md) |

## Numbers, and how much to trust them

| Measure | Figure | Read it as |
| --- | --- | --- |
| Multilingual text model, real mail it never saw, threshold 0.7 | English: 0.4% false alarms, 92.5% caught; French: 1.6%, 87.4% | The closest to real use, but about 330 legitimate emails from one mailbox ([details](multilingual-model.md#evaluation)) |
| English DistilBERT, held-out split | Accuracy 97.34%, F1 0.967 | Offline, on public corpora |
| URL and metadata Random Forests, held-out splits | F1 0.991 and 0.999 | Upper bounds: phishing and legitimate samples come from different corpora and years, which makes them easy to tell apart |

Every figure should come with its count and a confidence interval, and
the public benchmark lets anyone measure the running system
([evaluation.md](evaluation.md)). None of these is a live-traffic measurement. The reports users send
will give one; until then, see the
[known limitations](threat-model.md#residual-risks-and-known-limitations).
