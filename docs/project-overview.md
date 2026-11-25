# Project overview

## Where things live

The code for the extension, the server, the website and the tests is in
this repository, [AnzouK/PhishLens](https://github.com/AnzouK/PhishLens).
The training notebooks of the original three models are in
[dodi-ctrl/PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector).

PhishLens Cloud runs the multilingual text model
AnzouKiona/phishlens-text-v2. It is private because part of its
training mail is ([how it was built](multilingual-model.md)). A
self-hosted server uses the English v1 model,
[AnzouKiona/phishlens-distilbert](https://huggingface.co/AnzouKiona/phishlens-distilbert),
by default. The URL and header Random Forests are stored as skops files
in [AnzouKiona/phishlens-agents](https://huggingface.co/AnzouKiona/phishlens-agents).

[phishlens.dev](https://phishlens.dev) hosts the website in 8 languages
and PhishLens Cloud. The user guide is in the
[wiki](https://github.com/AnzouK/PhishLens/wiki).

A report on the first version was written at Nile University of
Nigeria (2025/2026). It is not published here.

## Where to look

The [README](../README.md#install) covers installation and the
[wiki](https://github.com/AnzouK/PhishLens/wiki) covers daily use.
[architecture.md](architecture.md) explains how PhishLens decides and
why. [evaluation.md](evaluation.md) says how good it is and how that
was measured, and [multilingual-model.md](multilingual-model.md) how
the text model was built. Languages and translations are in
[languages.md](languages.md), what can go wrong is in
[threat-model.md](threat-model.md), and running a server is in
[operations.md](operations.md). To report a vulnerability or contribute,
see [SECURITY.md](../SECURITY.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md).

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
upper bounds, because the phishing and legitimate samples came from
different corpora and years. The header one flagged most modern legitimate mail
and is off.

None of these is live traffic. User reports will give that.
