# The multilingual text model (research notes)

How the text agent of PhishLens 2.0 was built and measured: what was
tried, what worked, what did not, and what is still open. The training
code lives outside this repository; this page describes the method and
the results so they can be checked and questioned.

## Why a new text model

PhishLens 1.x read the text of an email with a DistilBERT fine-tuned on
English corpora, most of them older than 2010. On real 2026 mail it no
longer separated legitimate mail from phishing: in a review of 129 real
scans it scored 101 above 0.95, including 52 of the 76 legitimate ones,
and almost every French email. The verdicts were still mostly right
because the sender checks, the link checks and the trust paths decided,
not the text.

| Baseline (real mail) | False alarms (en / fr) | AUC (en / fr) | CPU per email |
| --- | --- | --- | --- |
| v1 DistilBERT, English | 87% / 99% | 0.62 / 0.65 | 237 ms |
| Horizon-Labs/phishing-scam-detector-base, unchanged | low | 0.97 / 0.97 | 900 ms |

The Horizon-Labs model (Apache-2.0, mmBERT-base, about 300M parameters,
70+ languages) separates real mail well but is close to four times too
slow for a CPU-only server, where LIME needs about a hundred forward
passes per explanation. Hence distillation: a small model trained to
imitate it.

## Goals and constraints

- French and Portuguese first, then Spanish, German, Italian, Dutch and
  Nigerian languages, without losing English: 22 languages in the end
  (`en fr pt es de it nl pl ru uk tr ar hi id vi zh ja ko ha yo ig sw`).
- About 250 ms per email on a CPU-only ARM server.
- Measured on real recent mail, not only on old or synthetic test sets.
- Personal mail is used for testing; a published model is never trained
  on it.
- Some data is non-commercial (phishing_pot, NLLB-200 translations), so
  published weights would be CC BY-NC 4.0.
- Only the text agent changes; the backend reads the model's settings
  from `phishlens_text_agent.json` ([architecture.md](architecture.md#text-model)).

## Method

| Part | Choice |
| --- | --- |
| Teacher | `Horizon-Labs/phishing-scam-detector-base` |
| Student | `jhu-clsp/mmBERT-small`, two classes |
| Teacher score | P(fraud) + 0.5 x P(spam), capped at 1 (with 1 x P(spam), newsletters looked like phishing) |
| Loss | 0.7 x class-weighted cross-entropy on the gold label + 0.3 x binary cross-entropy towards the teacher score |
| Training | 2 epochs, learning rate 3e-5, batch 32, 256 tokens |
| Rare languages | rows repeated: fr and pt x2, es x1.5, ha, yo, ig, sw x2 |
| Calibration | temperature fitted on validation data (about 0.45) |
| Input | the same normalisation everywhere: links, addresses and phone numbers become `<URL>`, `<EMAIL>`, `<PHONE>` (`backend/text_normalize.py`) |

The first plan kept DistilBERT for English and routed other languages to
a multilingual model. From round 2 the multilingual student also beat v1
in English (AUC 0.986 against 0.62 on real mail), so one model replaced
the routing: simpler to run, explain and audit.

## Data

| Source | Languages | Licence | Use |
| --- | --- | --- | --- |
| zefang-liu/phishing-email-dataset | en | LGPL-3.0 | train and test (seen by v1) |
| cybersectony/PhishingEmailDetectionv2.0 | en | not stated | train and test (seen by v1) |
| MeAJOR corpus (Zenodo) | mostly en | CC BY 4.0 | legitimate and fraudulent mail, capped |
| MOZ-Smishing | pt | OpenRAIL-M | test only (real SMS) |
| french-spam-text-dataset | fr | CC BY 4.0 | synthetic, reported apart |
| SMS Spam multilingual | fr, pt | GPL | machine-translated, training only |
| Nazario phishing corpus | several | CC BY 4.0 | 2023-2024 train, 2025 test |
| phishing_pot | several | CC BY-NC 4.0 | before 2026 train, 2026 test |
| untroubled.org spam traps | several | free use | kept as phishing only when the teacher says fraud (P >= 0.7) |
| nyuuzyou/phishing-snapshots | fr, pt, es, ... | CC0 | text of real phishing pages with a form |
| SpaPhish (Mendeley) | es | CC BY 4.0 | real Spanish mail; 2025 is test |
| FineWeb, FineWeb-2 | 22 languages | ODC-By | ordinary web text as legitimate; 300 pages per language held out |
| OPUS-MT and NLLB-200 translations | 21 languages | CC BY 4.0 / CC BY-NC 4.0 | phishing and legitimate translated in equal numbers |
| Synthetic notifications (round 5) | 22 languages | made for PhishLens | legitimate notifications and phishing on the same topics |
| A maintainer's mailbox (private) | en, fr | private | legitimate test mail; mass mail used to train the private models only |

Rules: nothing dated 2026 trains a model (2026 phishing stays a test of
the future); any text found in a test set is removed from training; test
sets are real messages, synthetic and translated ones are reported
apart; both classes are translated in equal numbers so translation style
does not reveal the label; commercial spam is not labelled phishing.

## Evaluation

- **realmix_\<lang\>**: recent real phishing (Nazario 2025, phishing_pot
  2026) mixed with the private legitimate mail. The closest test to what
  PhishLens meets.
- For every model: AUC, false alarms and phishing caught at thresholds
  0.3 to 0.95, share of legitimate mail above 0.95, CPU time per email.
- Per language: recent real phishing caught where it exists, and the
  share of ordinary web text flagged (300 pages per language).
- A diagnostic lists the missed phishing and the flagged legitimate mail,
  so errors are read, not only averaged.

Limits of these numbers: the legitimate side of realmix comes from one
mailbox (257 emails in English, 69 in French, almost none in
Portuguese); in French 2.9% is 2 emails. Hausa, Yoruba, Igbo and Swahili
have no real phishing to test on: only the false-alarm rate on web text
is measured for them.

## Rounds

Real mail, threshold 0.7 unless stated (false alarms / phishing caught).

| Round | What changed | Result | Lesson |
| --- | --- | --- | --- |
| r1 | mmBERT-small, teacher P(fraud) + P(spam), alpha 0.5 | AUC 0.935 en / 0.892 fr; at 0.85: 5.1% / 78% (en) | the teacher's "spam" counted as phishing: newsletters looked like phishing |
| r2 | spam weighted 0.5, alpha 0.7, commercial web pages and personal mass mail as legitimate | AUC 0.986 en / 0.961 fr; en 2.7% / 93% at 0.5; fr only 60% caught | scores rarely above 0.9: calibration needed; too little French |
| r3 | French, Portuguese and Spanish sources, language boost, calibration | en 2.3% / 90%; fr 2.9% / 84%; AUC 0.982 / 0.974; 229 ms | targets met; Spanish legitimate mail and languages seen mostly as phishing still weak |
| r4 | 22 languages: FineWeb-2 web text, NLLB-200 translations, per-language tests | en 2.7% / 92.5%; fr 2.9% / 87.4%; AUC 0.975 / 0.976; SpaPhish false alarms 15.9%; web text flagged at most 1.7% in the 19 new languages; recent phishing caught de 95.6%, nl 92.9%, pt 98.7%, es 90.9%; 232 ms | best model; trained partly on private mail, so private |
| r4p | r4 without any personal mail | en 59.5% / 96.1%; fr 58.0% / 96.1%; AUC 0.826 / 0.826 | learned "account email = phishing": no public legitimate notifications |
| r5p | r4p + 3,000 legitimate and 1,500 phishing synthetic notifications, translated | en 58.0% / 96.7%; fr 53.6% / 91.3%; AUC 0.902 / 0.847; SpaPhish 26% | templates are short and clean, real notifications long and noisy: the model learns "synthetic or real" |
| r5 | r4 + stronger anonymisation + synthetic notifications + training mail close to a test email removed | on mail no model saw: en 0.4% / 91.9% (r4: 0.4% / 92.5%); fr 0% / 80.1% (r4: 1.6% / 87.4%); AUC 0.981 / 0.986; SpaPhish 13.6%; 236 ms | slightly fewer false alarms but 7 points less French phishing caught, real scams included: r4 is kept |

The r4 figures in the r5 row are measured on the test sets after the
second anonymisation and split into mail seen or never seen in training,
like r5's, which is why they differ from the r4 row (2.7% becomes 0.4% in
English). Compare figures within a row.

How optimistic is r4? Only 7 of the 334 legitimate test emails have a
close copy in its training mail (same template, or TF-IDF cosine >= 0.5),
so its false-alarm rate is mostly measured on kinds of email it never
saw. It does know that mailbox's world (banks, services, languages):
users elsewhere may see more false alarms. User reports will measure it.

## Privacy

- Personal mail is exported, converted and anonymised; raw mailboxes are
  deleted after conversion.
- The first anonymisation (links, addresses, phone numbers, given names)
  missed handles, names written in capitals and double-encoded HTML
  entities. A second pass (round 5) masks handles and usernames, names
  after a greeting or a title, people sharing a file, payment
  counterparts and a list of personal words stored only as SHA-256
  hashes; it also runs on cached translations and test sets.
- Models trained with personal mail stay private. Public candidates
  ("p" rounds) refuse any row from it, checked before the data is
  written.
- Reports sent from the extension since 2.0 are redacted twice and kept
  private ([PRIVACY.md](../PRIVACY.md)).

## Decisions and status

- PhishLens 2.0 ships r4, from a private Hugging Face repository. The rule
  set before round 5 was to take r5 only if it was at least as good on
  unseen mail at 0.7; it matched r4 on false alarms but caught 7 points
  less French phishing.
- Open: r4's recipe on the cleaned data, without the synthetic
  notifications (r6). It does not block 2.0.
- No public model yet: r4p and r5p are research results, not models to
  use. A public model waits for real public legitimate mail, such as
  reviewed user reports.
- The text agent alone forces a phishing verdict from 0.7 (calibrated
  model) instead of 0.85; the rest of the fusion is unchanged.

## Known limits and next steps

- One mailbox as the real legitimate reference; little French, almost no
  Portuguese.
- No real phishing tests in Hausa, Yoruba, Igbo or Swahili; the Hausa
  interface awaits a native speaker's review.
- Callback scams without a link and lead-generation spam remain hard.
- Next: reviewed user reports as real legitimate data, the Tri-Class
  Multilingual dataset (embargoed until 2 December 2026), real French and
  Nigerian-language phishing, then SHAP and retraining on OCR text and QR
  phishing.
