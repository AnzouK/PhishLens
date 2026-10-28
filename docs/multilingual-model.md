# The multilingual text model

How the text model of PhishLens 2 was built and measured, what was
tried and rejected, and what is still open. The training code is not in
this repository; this page gives the method and the results so they can
be checked.

## Why

PhishLens 1 read the text with a DistilBERT fine-tuned on English
corpora mostly older than 2010. On real 2026 mail it no longer told
legitimate mail from phishing: in 129 real scans it scored 52 of the 76
legitimate ones above 0.95, and almost every French email. Verdicts were
still mostly right only because the sender and link checks decided.

| Baseline, real mail | False alarms (en / fr) | AUC (en / fr) | CPU per email |
| --- | --- | --- | --- |
| v1 DistilBERT, English | 87% / 99% | 0.62 / 0.65 | 237 ms |
| Horizon-Labs/phishing-scam-detector-base | low | 0.97 / 0.97 | 900 ms |

The Horizon-Labs model (mmBERT-base, 70+ languages) separates real mail
well but is four times too slow for a CPU-only server where LIME runs
the model a hundred times per explanation. Hence distillation: a small
model trained to imitate it.

Goals, fixed at the start: French and Portuguese first, then 20 more
languages (`en fr pt es de it nl pl ru uk tr ar hi id vi zh ja ko ha yo
ig sw`), about 250 ms per email on a CPU, measured on real recent mail,
and no published model trained on personal mail.

## Method

| Part | Choice |
| --- | --- |
| Teacher | [Horizon-Labs/phishing-scam-detector-base](https://huggingface.co/Horizon-Labs/phishing-scam-detector-base) |
| Student | [jhu-clsp/mmBERT-small](https://huggingface.co/jhu-clsp/mmBERT-small), two classes |
| Teacher score | P(fraud) + 0.5 x P(spam): with the full spam weight, newsletters looked like phishing |
| Loss | 0.7 x cross-entropy on the true label + 0.3 x towards the teacher |
| Training | 2 epochs, learning rate 3e-5, batch 32, 256 tokens; rare languages repeated |
| Calibration | temperature fitted on validation data |
| Input | links, addresses and phone numbers masked the same way everywhere (`backend/text_normalize.py`) |

One model for every language replaced the first plan (DistilBERT for
English, a multilingual model for the rest) once the student beat v1 in
English too: AUC 0.986 against 0.62.

## Sources

| Source | Languages | Licence | Use |
| --- | --- | --- | --- |
| [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) | en | LGPL-3.0 | train and test |
| [cybersectony/PhishingEmailDetectionv2.0](https://huggingface.co/datasets/cybersectony/PhishingEmailDetectionv2.0) | en | not stated | train and test |
| [MeAJOR corpus](https://zenodo.org/records/18471483) | mostly en | CC BY 4.0 | train, capped |
| [MOZ-Smishing](https://huggingface.co/datasets/MOZNLP/MOZ-Smishing) | pt | OpenRAIL-M | test only |
| [french-spam-text-dataset](https://github.com/Djochrist/french-spam-text-dataset-v1.0) | fr | CC BY 4.0 | synthetic, reported apart |
| [SMS Spam multilingual](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) | fr, pt | GPL | train only |
| [Nazario](https://monkey.org/~jose/phishing/) | several | CC BY 4.0 | 2023-2024 train, 2025 test |
| [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | several | CC BY-NC 4.0 | before 2026 train, 2026 test |
| [untroubled.org spam traps](https://untroubled.org/spam/) | several | free use | phishing only when the teacher says fraud |
| [nyuuzyou/phishing-snapshots](https://huggingface.co/datasets/nyuuzyou/phishing-snapshots) | fr, pt, es... | CC0 | text of real phishing pages |
| [SpaPhish](https://data.mendeley.com/datasets/hz2d6gz7pc) | es | CC BY 4.0 | 2025 is test |
| [FineWeb](https://huggingface.co/datasets/HuggingFaceFW/fineweb), [FineWeb-2](https://huggingface.co/datasets/HuggingFaceFW/fineweb-2) | 22 | ODC-By | ordinary web text as legitimate |
| [OPUS-MT](https://huggingface.co/Helsinki-NLP/opus-mt-tc-big-en-fr), [NLLB-200](https://huggingface.co/facebook/nllb-200-distilled-600M) translations | 21 | CC BY 4.0 / CC BY-NC 4.0 | both classes translated in equal numbers |
| The maintainer's mailboxes | en, fr | private | legitimate test mail; private models only |

Rules: nothing dated 2026 trains a model; a text found in a test set is
removed from training; test sets are real messages (synthetic and
translated ones are reported apart); both classes are translated alike
so translation style does not reveal the label; commercial spam is not
phishing.

## Rounds

Real mail, threshold 0.7 (false alarms / phishing caught), unless stated.

| Round | What changed | Result | Kept? |
| --- | --- | --- | --- |
| r1 | first student | en 5.1% / 78% at 0.85 | no: the teacher's "spam" made newsletters look like phishing |
| r2 | spam weighted 0.5 | AUC 0.986 en, but fr only 60% caught | no: too little French, uncalibrated |
| r3 | French, Portuguese, Spanish sources; calibration | en 2.3% / 90%, fr 2.9% / 84% | no: Spanish legitimate mail flagged |
| **r4** | 22 languages, web text, translations | en 2.7% / 92.5%, fr 2.9% / 87.4%; de 95.6%, nl 92.9%, pt 98.7%, es 90.9% caught; 232 ms | **yes, in production** (private: trained partly on personal mail) |
| r4p | r4 without personal mail | en 59.5% false alarms | no: without real notifications it learns "account email = phishing" |
| r5p | r4p + synthetic notifications | en 58.0% false alarms | no: it learns "synthetic or real", not "phishing or not" |
| r5 | stronger anonymisation, synthetic notifications | French phishing caught 7 points lower | no |
| r6 | recent real phishing in training | +1.2 points on the benchmark | no: below +3 fixed in advance |
| r7h | more weight on true labels | +2.6 points | no: below +3; more offline false alarms |
| r7b | mmBERT-base | +0.8 points, 395 ms | no: slower, one more inbox false alarm |

The benchmark comparisons of r6, r7h and r7b are in
[evaluation.md](evaluation.md#measured-and-rejected).

### Confidence intervals

r4 on mail no model saw (95% Wilson intervals): the legitimate side is
mailbox mail with no close copy in training, the phishing Nazario 2025
and phishing_pot 2026.

| Set | Threshold | Legitimate flagged | Phishing caught |
| --- | --- | --- | --- |
| English | 0.7 | 1/255 = 0.4% (0.1% to 2.2%) | 1,805/1,952 = 92.5% (91.2% to 93.6%) |
| French | 0.7 | 1/63 = 1.6% (0.3% to 8.5%) | 202/231 = 87.4% (82.6% to 91.1%) |

The phishing side gives tight intervals; the legitimate side does not,
especially in French. Only 7 of the 334 legitimate test emails have a
close copy in training, but the model knows that mailbox's world (its
banks, its services): other users may see more false alarms.

## Privacy

Personal mail is anonymised twice (links, addresses, numbers, names,
handles, and a list of personal words stored only as hashes) and raw
mailboxes are deleted after conversion. Models trained with it stay
private; public candidates refuse any row from it, checked before the
data is written.

## Open

- A public model: it waits for real public legitimate mail, such as
  reviewed user reports. Until then a self-hosted server uses v1.
- One person's mailboxes as the legitimate reference; little French,
  almost no Portuguese.
- No real phishing to test Hausa, Yoruba, Igbo or Swahili; the Hausa
  interface awaits a native speaker.
- Scams without a link (call this number) remain hard.
