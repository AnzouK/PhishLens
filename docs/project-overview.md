# Project overview

## Where things live

| Artefact | What |
| --- | --- |
| [AnzouK/PhishLens](https://github.com/AnzouK/PhishLens) | This repository: extension, server, website, tests |
| [dodi-ctrl/PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector) | Training notebooks of the original three models |
| AnzouKiona/phishlens-text-v2 (private) | The multilingual text model PhishLens Cloud runs; private because part of its training mail is ([how it was built](multilingual-model.md)) |
| [AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert) | The English v1 text model, default of a self-hosted server |
| [AnzouKiona/phishlens-agents](https://huggingface.co/AnzouKiona/phishlens-agents) | The URL and header Random Forests (skops) |
| [phishlens.dev](https://phishlens.dev) | Website in 8 languages and PhishLens Cloud |
| [Wiki](https://github.com/AnzouK/PhishLens/wiki) | User guide |

A report on the first version was written at Nile University of
Nigeria (2025/2026); it is not published here.

## Where to look

| Question | Page |
| --- | --- |
| Install | [README](../README.md#install) |
| Use it day to day | [wiki](https://github.com/AnzouK/PhishLens/wiki) |
| How it decides, and why | [architecture.md](architecture.md) |
| How good it is, and how it was measured | [evaluation.md](evaluation.md) |
| How the text model was built | [multilingual-model.md](multilingual-model.md) |
| Languages and translations | [languages.md](languages.md) |
| What can go wrong | [threat-model.md](threat-model.md) |
| Running a server | [operations.md](operations.md) |
| Reporting a vulnerability, contributing | [SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md) |

## Which figures to trust

| Figure | Read it as |
| --- | --- |
| Whole system, public benchmark: 1,812 of 2,000 recent phishing caught (89.2% to 91.8%), 1 of 414 legitimate flagged (0.0% to 1.4%) | Real 2026 mail through the running server; the legitimate side is small ([evaluation](evaluation.md#results)) |
| Text model alone, unseen real mail at 0.7: English 92.5% caught, 1 of 255 flagged; French 87.4%, 1 of 63 | One mailbox as the legitimate reference ([details](multilingual-model.md#confidence-intervals)) |
| Original Random Forests, F1 0.991 and 0.999 | Upper bounds: phishing and legitimate samples came from different corpora and years. The header one flagged most modern legitimate mail and is off |

None of these is live traffic. User reports will give that.
