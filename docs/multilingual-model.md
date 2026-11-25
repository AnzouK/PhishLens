# The multilingual text model

This page describes how the text model of PhishLens 2 was built and
measured, what was tried and rejected, and what is still open. The
training code is not in this repository, so the method and the results
are given here to be checked.

## Why

PhishLens 1 read the text with a DistilBERT fine-tuned on English
corpora mostly older than 2010. On real 2026 mail it no longer told
legitimate mail from phishing. In 129 real scans it scored 52 of the 76
legitimate ones above 0.95, and almost every French email. Verdicts were
still mostly right only because the sender and link checks decided.

| Baseline, real mail | False alarms (en / fr) | AUC (en / fr) | CPU per email |
| --- | --- | --- | --- |
| v1 DistilBERT, English | 87% / 99% | 0.62 / 0.65 | 237 ms |
| Horizon-Labs/phishing-scam-detector-base | low | 0.97 / 0.97 | 900 ms |

The Horizon-Labs model (mmBERT-base, 70+ languages) separates real mail
well but is four times too slow for a CPU-only server where LIME runs
the model a hundred times per explanation. Hence distillation, a small
model trained to imitate it.

The goals were fixed at the start: French and Portuguese first, then 20 more
languages (`en fr pt es de it nl pl ru uk tr ar hi id vi zh ja ko ha yo
ig sw`), about 250 ms per email on a CPU, measured on real recent mail,
and no published model trained on personal mail.

## Method

The teacher is
[Horizon-Labs/phishing-scam-detector-base](https://huggingface.co/Horizon-Labs/phishing-scam-detector-base)
and the student is
[jhu-clsp/mmBERT-small](https://huggingface.co/jhu-clsp/mmBERT-small)
with two classes. The teacher's score is P(fraud) + 0.5 x P(spam),
because with the full spam weight newsletters looked like phishing. The
loss is 0.7 x cross-entropy on the true label plus 0.3 x the distance to
the teacher.

Training ran for 2 epochs at learning rate 3e-5, batch 32 and 256
tokens, with rare languages repeated. A temperature fitted on
validation data calibrates the output. Links, addresses and phone
numbers are masked the same way in training and in production
(`backend/text_normalize.py`).

One model for every language replaced the first plan (DistilBERT for
English, a multilingual model for the rest) once the student beat v1 in
English too, with an AUC of 0.986 against 0.62.

## Sources

English email corpora:

- [zefang-liu/phishing-email-dataset](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset)
  (LGPL-3.0), used for training and testing.
- [cybersectony/PhishingEmailDetectionv2.0](https://huggingface.co/datasets/cybersectony/PhishingEmailDetectionv2.0)
  (licence not stated), used for training and testing.
- The [MeAJOR corpus](https://zenodo.org/records/18471483) (mostly
  English, CC BY 4.0), used for training with a cap.

Other languages:

- [MOZ-Smishing](https://huggingface.co/datasets/MOZNLP/MOZ-Smishing)
  (Portuguese, OpenRAIL-M), used for testing only.
- [french-spam-text-dataset](https://github.com/Djochrist/french-spam-text-dataset-v1.0)
  (French, CC BY 4.0). It is synthetic, so its results are reported
  apart.
- [SMS Spam multilingual](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset)
  (French and Portuguese, GPL), used for training only.
- [SpaPhish](https://data.mendeley.com/datasets/hz2d6gz7pc) (Spanish,
  CC BY 4.0). Its 2025 part is test data.

Real phishing in several languages:

- [Nazario](https://monkey.org/~jose/phishing/) (CC BY 4.0). 2023 and
  2024 train the model and 2025 tests it.
- [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
  (CC BY-NC 4.0). Mail before 2026 trains the model and 2026 tests it.
- [untroubled.org spam traps](https://untroubled.org/spam/) (free use).
  A message counts as phishing only when the teacher says fraud.
- [nyuuzyou/phishing-snapshots](https://huggingface.co/datasets/nyuuzyou/phishing-snapshots)
  (French, Portuguese, Spanish and more, CC0), the text of real phishing
  pages.

Legitimate text and translations:

- [FineWeb](https://huggingface.co/datasets/HuggingFaceFW/fineweb) and
  [FineWeb-2](https://huggingface.co/datasets/HuggingFaceFW/fineweb-2)
  (22 languages, ODC-By), ordinary web text used as legitimate.
- Translations with
  [OPUS-MT](https://huggingface.co/Helsinki-NLP/opus-mt-tc-big-en-fr)
  (CC BY 4.0) and
  [NLLB-200](https://huggingface.co/facebook/nllb-200-distilled-600M)
  (CC BY-NC 4.0) into 21 languages, with both classes translated in
  equal numbers.
- The maintainer's own mailboxes (English and French, private), used as
  legitimate test mail and only in private models.

A few rules apply throughout. Nothing dated 2026 trains a model, and a
text found in a test set is removed from training. Test sets are real
messages (synthetic and translated ones are reported apart). Both
classes are translated alike so translation style does not reveal the
label, and commercial spam is not phishing.

## Rounds

Results are on real mail at threshold 0.7 (false alarms / phishing
caught) unless stated otherwise.

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

These are r4's results on mail no model saw, with 95% Wilson intervals.
The legitimate side is mailbox mail with no close copy in training, and
the phishing comes from Nazario 2025 and phishing_pot 2026.

| Set | Threshold | Legitimate flagged | Phishing caught |
| --- | --- | --- | --- |
| English | 0.7 | 1/255 = 0.4% (0.1% to 2.2%) | 1,805/1,952 = 92.5% (91.2% to 93.6%) |
| French | 0.7 | 1/63 = 1.6% (0.3% to 8.5%) | 202/231 = 87.4% (82.6% to 91.1%) |

The phishing side gives tight intervals and the legitimate side does
not, especially in French. Only 7 of the 334 legitimate test emails have
a close copy in training, but the model knows that mailbox's world (its
banks, its services), so other users may see more false alarms.

## Privacy

Personal mail is anonymised twice (links, addresses, numbers, names,
handles, and a list of personal words stored only as hashes) and raw
mailboxes are deleted after conversion. Models trained with it stay
private. Public candidates refuse any row from it, which is checked
before the data is written.

## Open

- A public model waits for real public legitimate mail, such as
  reviewed user reports. Until then a self-hosted server uses v1.
- The legitimate reference is one person's mailboxes, with little
  French and almost no Portuguese.
- There is no real phishing to test Hausa, Yoruba, Igbo or Swahili, and
  the Hausa interface awaits a native speaker.
- Scams without a link (call this number) remain hard.
