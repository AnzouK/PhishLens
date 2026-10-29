<div align="center">

<img src="extension/icons/128.png" alt="PhishLens" width="96" height="96">

# PhishLens

**Detect and explain phishing emails in real time, inside Gmail and Outlook.**

[![CI](https://github.com/AnzouK/PhishLens/actions/workflows/ci.yml/badge.svg)](https://github.com/AnzouK/PhishLens/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AnzouK/PhishLens?color=blueviolet)](https://github.com/AnzouK/PhishLens/releases/latest)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)
[![Website](https://img.shields.io/badge/Website-phishlens.dev-F80000)](https://phishlens.dev)
[![Text model](https://img.shields.io/badge/checked%20on%20real%20phishing-6%20languages-yellow)](docs/multilingual-model.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/gmail-verdicts-dark.svg">
  <img src="docs/gmail-verdicts-light.svg" alt="PhishLens verdict banners in Gmail: a phishing verdict with per-agent scores, threat-intelligence chips and the words behind the decision, and a safe verdict from a trusted sender" width="860">
</picture>

</div>

PhishLens is a Chrome extension that checks an email in Gmail or Outlook
and tells you whether it looks like phishing, and why: which words, which
links, whether the sender is who it claims to be, what the attachments
contain. It is free, open source and available in English, French,
Portuguese, Spanish, German, Italian, Dutch and Hausa.

It is an assistant, not a filter: it gives a verdict and its reasons so
you can decide, and it can be wrong.

## What it checks

| Check | How |
| --- | --- |
| Wording | A multilingual text model scores the email; LIME shows the words that weighed most |
| Links | Every real link target, including the one behind "Click here", against Google Safe Browsing, PhishTank, URLhaus and Spamhaus, plus a link model |
| Sender | SPF, DKIM and DMARC, read from Gmail's original headers; whether the name shown ("Chronopost", "PayPal") matches the address |
| Attachments | PDFs (scanned ones through OCR), images, QR codes, Office files and their macros, archives, calendar invites |

The text score alone would flag real bank and university emails, because
they use the same words as phishing. PhishLens lowers it only when the
sender is proven (DKIM aligned with the From: domain), and a link known
to be malicious makes the verdict "phishing" whoever sent it. Details:
[architecture](docs/architecture.md).

## Privacy

To check an email, PhishLens sends its text, links and headers (and the
attachment, if you scan one) to a server. By default that server is
**PhishLens Cloud**, run by the author on Oracle Cloud:

- the email is analysed in memory and **not stored**; only the result is
  kept, for 24 hours, keyed by a hash of the email, so that a second scan
  answers at once;
- threat-intelligence services receive the **link addresses only**;
- your scan history stays **in your browser**;
- nothing else leaves your browser unless you choose to **report a wrong
  verdict**: you then see and can edit the redacted text before it is
  sent.

If you would rather no email leave your computer, run the backend
yourself (below) and pick **Local** in the settings. Everything is in
the [privacy policy](PRIVACY.md).

## How good is it?

On real mail that no model saw during training, PhishLens Cloud's text
model, at its 0.7 threshold:

| Language | Legitimate emails flagged | Phishing caught |
| --- | --- | --- |
| English | 1 of 255: 0.4% (95% CI 0.1% to 2.2%) | 1,805 of 1,952: 92.5% (91.2% to 93.6%) |
| French | 1 of 63: 1.6% (0.3% to 8.5%) | 202 of 231: 87.4% (82.6% to 91.1%) |

The intervals say how much these counts pin down: with one false alarm
in 63 French emails, the true rate could be anywhere from 0.3% to 8.5%.
The legitimate emails all come from one mailbox and the phishing from
recent public collections (Nazario 2025, phishing_pot 2026): another
inbox may see more false alarms. The model was trained on 22
languages but tested on real phishing only in English, French, German,
Dutch, Portuguese and Spanish; in other languages its score is less
proven. The link, sender and threat-intelligence checks do not depend on
the language. Measure it yourself with the public benchmark
([evaluation.md](docs/evaluation.md)). How the model was built and measured:
[multilingual-model.md](docs/multilingual-model.md); what can go wrong:
[known limitations](docs/threat-model.md#residual-risks-and-known-limitations).

The whole system (PhishLens Cloud, October 24, 2026), measured with the
public benchmark on real mail sent in 2026:

| Mail | Result |
| --- | --- |
| Phishing nobody looked at while tuning (phishing_pot, Nazario) | 1,812 of 2,000 caught: 90.6% (95% CI 89.2% to 91.8%) |
| Legitimate, public Apache mailing lists | 1 of 297 flagged: 0.3% (0.1% to 1.9%) |
| Legitimate, real personal inboxes (bank, university and service notifications), received after the model's training mail | 0 of 117 flagged: 0.0% (0.0% to 3.2%) |

English (81.6%) and French (87.2%) are the weakest languages, and some
phishing sent from the attacker's own DKIM-signed domain still gets
through; the runs, their causes and what was rejected are in
[evaluation.md](docs/evaluation.md#results).

A scan of a typical email (about 250 tokens) takes about 190 ms on the
server (median, CPU only), a short one about 65 ms, plus the
threat-intelligence lookups.

## Install

PhishLens is not on the Chrome Web Store yet.

1. Download `PhishLens-extension-<version>.zip` from the
   [latest release](https://github.com/AnzouK/PhishLens/releases/latest)
   and unzip it.
2. Open `chrome://extensions`, turn on **Developer mode** and click
   **Load unpacked** on the unzipped folder.
3. Open an email in Gmail or Outlook on the web and click **Scan with
   PhishLens** next to the subject. You can also drop a `.eml` file or an
   attachment, or paste text, in the popup.

The [user guide](https://github.com/AnzouK/PhishLens/wiki) covers
everything step by step.

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/popup-dark.svg">
    <img src="docs/popup-light.svg" alt="The PhishLens popup after scanning an email: phishing verdict, a score per check, threat-intelligence badges and the words behind the decision" width="400">
  </picture>
</div>

### Run your own server

```bash
mkdir -p backend/model
# the public English text model; PhishLens Cloud runs the multilingual one
huggingface-cli download AnzouKiona/phishlens-distilbert --local-dir backend/model
cd backend && docker compose up --build
```

Then pick **Local** in the extension settings. A self-hosted server uses
the English text model by default; the multilingual model is private
because part of its training mail is. Configuration, deployment and
monitoring: [operations guide](docs/operations.md).

### Source and tests

The release zip holds only what Chrome loads. The extension is plain
JavaScript with no build step, so `extension/` in this repository is the
same code, with its tests and lint configuration next to it:

```bash
node --test tests/extension/*.test.js                      # unit tests, no dependency
npx eslint . --max-warnings 0                              # eslint.config.mjs
npx playwright test --config tests/ui/playwright.config.js # popup and website
```

CI runs all three on every pull request. Setup and project layout:
[contributing guide](CONTRIBUTING.md).

## Documentation

| Document | Contents |
| --- | --- |
| [User guide (wiki)](https://github.com/AnzouK/PhishLens/wiki) | Install, Gmail and Outlook, reading a verdict, settings, troubleshooting |
| [Architecture](docs/architecture.md) | Components, scoring, trust paths, design decisions |
| [Multilingual model](docs/multilingual-model.md) | How the text model was trained and measured |
| [Evaluation](docs/evaluation.md) | What is measured, confidence intervals, and a public benchmark you can run |
| [Languages](docs/languages.md) | Translations, OCR languages, adding a language |
| [Threat model](docs/threat-model.md) | Risks, mitigations, known limitations |
| [Operations](docs/operations.md) | Deployment, configuration, logs, metrics, load testing |
| [Contributing](CONTRIBUTING.md) | Setup, project layout, checks |
| [Changelog](CHANGELOG.md), [Security](SECURITY.md), [Privacy](PRIVACY.md), [Terms](TERMS.md) | |

## Roadmap

- **Outlook:** attachments, full headers and automatic scanning, through
  Microsoft's mail API.
- **Yahoo Mail.**
- **Measurement and research:** more reviewed real emails, the reports
  users send, SHAP next to LIME, retraining on OCR text and QR-code
  phishing.
- **A multilingual model trained only on public data**, so that it can be
  published; a native review of the Hausa translation is under way.
- **Chrome Web Store release.**

## Who makes it

PhishLens is built and run by one person, [AnzouK](https://github.com/AnzouK).
It began as our group's final-year project at
[Nile University of Nigeria](https://nileuniversity.edu.ng/): of the
topics we considered, we chose a phishing detector that explains its
verdict instead of only flagging an email. The team trained the first
three models in [PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector)
(maintained by [dodi-ctrl](https://github.com/dodi-ctrl)). When the
course ended I kept it going on my own: it is now an independent
project, with no link to the university.

I write it with the help of an AI coding assistant. I review and test
every change, and no claim about detection ships before it is measured
on the public benchmark. The worst run so far, 130 of 297 legitimate
emails flagged in mid-October, and what fixed it are in
[evaluation.md](docs/evaluation.md#results).

## Credits

It builds on [Google Safe Browsing](https://safebrowsing.google.com/)
(its warnings are advisories provided by Google),
[PhishTank](https://phishtank.org/), [URLhaus](https://urlhaus.abuse.ch/)
by abuse.ch, the [Spamhaus](https://www.spamhaus.org/) Domain Block List,
[Hugging Face Transformers](https://github.com/huggingface/transformers),
[mmBERT](https://huggingface.co/jhu-clsp/mmBERT-small) and the
[phishing-scam-detector](https://huggingface.co/Horizon-Labs/phishing-scam-detector-base)
it was distilled from, DistilBERT, [scikit-learn](https://scikit-learn.org/),
[LIME](https://github.com/marcotcr/lime),
[Tesseract](https://github.com/tesseract-ocr/tesseract),
[FastAPI](https://fastapi.tiangolo.com/), and the public email datasets
listed in PhishingDetector and in the [model documentation](docs/multilingual-model.md#sources).

## License

[GNU AGPL-3.0](LICENSE): anyone may use, study, modify and share
PhishLens, and a modified version, including one offered as an online
service, must be published under the same license. Versions up to 1.15.5
were released under the MIT license. The text model weights are licensed
separately (CC BY-NC 4.0), because some of their training data is
non-commercial.
