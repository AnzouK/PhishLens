# Project overview

This page lists where each part of PhishLens lives, which document
answers which question, and how far each published figure can be
trusted.

## Where things live

- [AnzouK/PhishLens](https://github.com/AnzouK/PhishLens): this
  repository, with the extension, the server, the website and the tests.
- [dodi-ctrl/PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector):
  the training notebooks of the original three models.
- AnzouKiona/phishlens-text-v2 (private): the multilingual text model
  PhishLens Cloud runs. It is private because part of its training mail
  is ([how it was built](multilingual-model.md)).
- [AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert):
  the English v1 text model, the default of a self-hosted server.
- [AnzouKiona/phishlens-agents](https://huggingface.co/AnzouKiona/phishlens-agents):
  the URL and header Random Forests (skops).
- [phishlens.dev](https://phishlens.dev): the website, in 8 languages,
  and PhishLens Cloud.
- [Wiki](https://github.com/AnzouK/PhishLens/wiki): the user guide.

A report on the first version was written at Nile University of
Nigeria (2025/2026). It is not published here.

## Where to look

- Install: [README](../README.md#install)
- Use it day to day: [wiki](https://github.com/AnzouK/PhishLens/wiki)
- How it decides, and why: [architecture.md](architecture.md)
- How good it is, and how it was measured: [evaluation.md](evaluation.md)
- How the text model was built: [multilingual-model.md](multilingual-model.md)
- Languages and translations: [languages.md](languages.md)
- What can go wrong: [threat-model.md](threat-model.md)
- Running a server: [operations.md](operations.md)
- Reporting a vulnerability, contributing: [SECURITY.md](../SECURITY.md),
  [CONTRIBUTING.md](../CONTRIBUTING.md)

## Which figures to trust

The whole system on the public benchmark caught 1,804 of 2,000 recent
phishing emails (88.8% to 91.4%), and flagged 0 of 117 real inbox
emails (at most 3.2%) and 1 of 297 Apache mailing list emails (used for
tuning). This is real 2026 mail through the running server, but the
legitimate side is small and only the inbox emails are unseen
([evaluation](evaluation.md#results)).

The text model alone, on unseen real mail at 0.7, caught 92.5% in
English with 1 of 255 flagged, and 87.4% in French with 1 of 63. One
mailbox is the legitimate reference
([details](multilingual-model.md#confidence-intervals)).

The original Random Forests reached F1 0.991 and 0.999. Read these as
upper bounds: phishing and legitimate samples came from different
corpora and years. The header one flagged most modern legitimate mail
and is off.

None of these is live traffic. User reports will give that.
