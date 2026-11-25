<div align="center">

<img src="extension/icons/128.png" alt="PhishLens" width="96" height="96">

# PhishLens

[![CI](https://github.com/AnzouK/PhishLens/actions/workflows/ci.yml/badge.svg)](https://github.com/AnzouK/PhishLens/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/AnzouK/PhishLens?color=blueviolet)](https://github.com/AnzouK/PhishLens/releases/latest)
[![License](https://img.shields.io/badge/License-AGPL--3.0-green.svg)](LICENSE)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/gmail-verdicts-dark.svg">
  <img src="docs/gmail-verdicts-light.svg" alt="PhishLens verdict banners in Gmail: a phishing verdict with per-agent scores, threat-intelligence chips and the words behind the decision, and a safe verdict from a trusted sender" width="860">
</picture>

</div>

PhishLens is a Chrome extension for people who want a second opinion on
an email before they click. Open a message in Gmail or Outlook on the
web, press the scan button, and it tells you whether the email looks
like phishing and why. It points at the words, the links, whether the
sender is who it claims to be, and what the attachments contain.

It is free and open source, and the interface comes in English, French,
Portuguese, Spanish, German, Italian, Dutch and Hausa. Your mail stays
where it is: you get a verdict and the reasons for it, which can be
wrong, and decide for yourself. The website is
[phishlens.dev](https://phishlens.dev).

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

On Firefox 140 or later, take `PhishLens-firefox-<version>.zip` from the
same release and load it under `about:debugging`, This Firefox, Load
Temporary Add-on.

The [user guide](https://github.com/AnzouK/PhishLens/wiki) goes through
each step in more detail.

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/popup-dark.svg">
    <img src="docs/popup-light.svg" alt="The PhishLens popup after scanning an email: phishing verdict, a score per check, threat-intelligence badges and the words behind the decision" width="400">
  </picture>
</div>

### Running your own server

By default the extension talks to PhishLens Cloud, the server I run. If
you'd rather keep everything on your machine:

```bash
mkdir -p backend/model
# the public English text model; PhishLens Cloud runs the multilingual one
huggingface-cli download AnzouKiona/phishlens-distilbert --local-dir backend/model
cd backend && docker compose up --build
```

Then pick **Local** in the extension settings. A self-hosted server uses
the English text model by default. The multilingual model is private
because part of its training mail is. The
[operations guide](docs/operations.md) covers configuration, deployment
and monitoring.

## How it works

The extension reads what the mail page shows and sends it to a FastAPI
server, which does all the scoring. Three checks run side by side.

A multilingual text model scores the wording, and LIME shows the words
that weighed most. Every real link target, including the one behind
"Click here", is looked up in Google Safe Browsing, PhishTank, URLhaus
and Spamhaus and scored by a link model. For the sender, PhishLens reads
SPF, DKIM and DMARC from Gmail's original headers and checks whether the
name shown ("Chronopost", "PayPal") matches the address. Outlook only
gives the page the visible text, so SPF, DKIM and DMARC are read in
Gmail only. Attachments are opened too, including PDFs (scanned ones
through OCR), images, QR codes, Office files and their macros, archives
and calendar invites.

The text score alone would flag real bank and university emails, because
they use the same words as phishing. So the wording only counts for less
when the sender is proven (DKIM aligned with the From: domain), and a
link known to be malicious makes the verdict "phishing" whoever sent it.
The [architecture notes](docs/architecture.md) explain how the checks
are combined.

## Results

These figures come from real mail that no model saw during training,
scored by PhishLens Cloud's text model at its 0.7 threshold.

| Language | Legitimate emails flagged | Phishing caught |
| --- | --- | --- |
| English | 1 of 255, 0.4% (95% CI 0.1% to 2.2%) | 1,805 of 1,952, 92.5% (91.2% to 93.6%) |
| French | 1 of 63, 1.6% (0.3% to 8.5%) | 202 of 231, 87.4% (82.6% to 91.1%) |

The intervals show how little these counts can pin down. With one false
alarm in 63 French emails, the true rate could be anywhere from 0.3% to
8.5%. The legitimate emails all come from one mailbox and the phishing
from recent public collections (Nazario 2025, phishing_pot 2026), so
another inbox may see more false alarms. The model was trained on 22
languages but tested on real phishing only in English, French, German,
Dutch, Portuguese and Spanish, so its score is less proven in the
others. The link, sender and threat-intelligence checks work the same
in every language.

The same benchmark measured the whole system (PhishLens Cloud, November
1, 2026) on real mail sent in 2026:

| Mail | Result |
| --- | --- |
| Phishing nobody looked at while tuning (phishing_pot, Nazario) | 1,804 of 2,000 caught, 90.2% (95% CI 88.8% to 91.4%) |
| Legitimate, public Apache mailing lists (used while tuning) | 1 of 297 flagged, 0.3% (0.1% to 1.9%) |
| Legitimate, real personal inboxes (bank, university and service notifications), received after the model's training mail | 0 of 117 flagged, 0.0% (0.0% to 3.2%) |

A typical email (about 250 tokens) takes about 190 ms on the server
(median, CPU only) and a short one about 65 ms, plus the
threat-intelligence lookups.

[multilingual-model.md](docs/multilingual-model.md) explains how the
model was built and measured. [evaluation.md](docs/evaluation.md#results)
lists every run, what caused each change and what was rejected, and you
can rerun the public benchmark yourself with the instructions in
[evaluation.md](docs/evaluation.md).

## Privacy

To check an email, PhishLens sends its text, links and headers (and the
attachment, if you scan one) to a server. By default that is PhishLens
Cloud, which I run on Google Cloud Run in Belgium, reached through
`phishlens.dev` on Cloudflare.

The email is analysed in memory and not stored. Only the result is
kept, for 24 hours, keyed by a hash of the email, so a second scan
answers at once. Threat-intelligence services only receive the link
addresses. Your scan history stays in your browser. Nothing else leaves
it unless you choose to report a wrong verdict, and then you see the
redacted text, and can edit it, before it is sent.

If you'd rather no email leave your computer, run the backend yourself
(see above) and pick **Local** in the settings. The
[privacy policy](PRIVACY.md) has the full details.

## Limitations

English (81.6%) and French (87.2%) are the weakest languages on the
public benchmark, and some phishing sent from the attacker's own
DKIM-signed domain still gets through. The false-alarm figures rest on
a few hundred legitimate emails. The
[known limitations](docs/threat-model.md#residual-risks-and-known-limitations)
in the threat model list the rest.

Outlook support is thinner than Gmail's for now. Attachments, full
headers and automatic scanning there will need Microsoft's mail API.
After that I'd like to add Yahoo Mail, more reviewed real emails and
user reports for measurement, SHAP next to LIME, and retraining on OCR
text and QR-code phishing. I also want a multilingual model trained only
on public data so it can be published, and a Chrome Web Store release.
A native review of the Hausa translation is under way.

## Contributing

The release zips only hold what Chrome and Firefox load. The extension is plain
JavaScript with no build step, so `extension/` in this repository is the
same code, with its tests and lint configuration next to it.

```bash
node --test tests/extension/*.test.js tests/functions/*.test.mjs  # unit tests, no dependency
npx eslint . --max-warnings 0                              # eslint.config.mjs
npx playwright test --config tests/ui/playwright.config.js # popup and website
```

CI runs all three on every pull request. The
[contributing guide](CONTRIBUTING.md) covers setup, the project layout
and the checks for the backend.

Other documents:

- [architecture notes](docs/architecture.md) (components, scoring, trust paths, design decisions)
- [languages](docs/languages.md) (translations and OCR)
- [threat model](docs/threat-model.md)
- [operations guide](docs/operations.md) (deployment, logs, metrics, load testing)
- [changelog](CHANGELOG.md), [security policy](SECURITY.md) and [terms](TERMS.md)

## Background

I build and run PhishLens on my own as [AnzouK](https://github.com/AnzouK).
It began as our group's final-year project at
[Nile University of Nigeria](https://nileuniversity.edu.ng/). Of the
topics we considered, we chose a phishing detector that explains its
verdict instead of only flagging an email. The team trained the first
three models in [PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector)
(maintained by [dodi-ctrl](https://github.com/dodi-ctrl)). When the
course ended I kept it going, and it is now an independent project with
no link to the university.

An AI coding assistant helps me write PhishLens. I review and test what
it changes, and a detection figure is only published once the public
benchmark has measured it; [evaluation.md](docs/evaluation.md#results)
includes the worst run so far (130 of 297 legitimate emails flagged in
mid-October) and what fixed it.

### Credits

PhishLens builds on [Google Safe Browsing](https://safebrowsing.google.com/)
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

PhishLens is released under the [GNU AGPL-3.0](LICENSE). You may use,
study, modify and share it, and a modified version, including one
offered as an online service, must be published under the same license.
Versions up to 1.15.5 were released under the MIT license. The text
model weights are licensed separately (CC BY-NC 4.0), because some of
their training data is non-commercial.
