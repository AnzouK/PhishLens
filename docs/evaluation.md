# Evaluation

This page explains how PhishLens is measured, how far each figure can be
trusted, and how to measure it yourself.

| Measure | What it covers | Where |
| --- | --- | --- |
| Public benchmark | The whole system as users see it, on emails anyone can download | this page, `scripts/benchmark.py` |
| Model evaluation | The text model alone, on held-out mail | [multilingual-model.md](multilingual-model.md) |
| Live evaluation | Scans a user marked right or wrong in their own history | `scripts/live_eval.py` |

Every rate comes with its count and a 95% Wilson confidence interval.
"1 of 297 (0.1% to 1.9%)" shows how little one error in a few hundred
emails pins down. A rate without its count is not reported.

## Public benchmark

```bash
python3 scripts/benchmark.py \
    --phishing phishing_pot/email nazario/phishing-2025.mbox \
    --legit legit/*.mbox \
    --since 2026-01-01 --sample 500 \
    --server http://127.0.0.1:8000 --markdown
```

The script sends each full message to a server, as the extension does,
and prints per language and overall the share of phishing caught and of
legitimate mail flagged. Results are cached by email hash (never the
email), so a run resumes and can be published. `--sample N` always picks
the same N emails per label, `--exclude` leaves out the emails of
earlier runs, and `--show-errors` lists the misses on your machine only.
Run it against your own server, because PhishLens Cloud is rate-limited
and its Safe Browsing quota is shared.

| Side | Source |
| --- | --- |
| Phishing | [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (real `.eml`, mostly English and Portuguese), [Nazario](https://monkey.org/~jose/phishing/) |
| Legitimate | Apache mailing-list archives, real and recent but technical, with no bank or delivery mail |
| Legitimate | Personal inboxes, the most realistic (counts only, never the emails) |

There is no public, recent collection of everyday legitimate mail (bank
notices, deliveries, newsletters) in several languages. That is the
main limit of this benchmark, and why the false-alarm rate rests on 414
emails.

### Rules

- Only mail newer than the model's training data is used (`--since`).
  Mail the model trained on measures memory, not detection.
- Sources and dates are decided before looking at results, and every
  readable email is kept.
- Every tuned change is measured again on a control sample drawn with
  `--exclude`, and that second figure is the one published.
- Decision rules are fixed before training or tuning. A new text model
  replaces the current one only with at least 3 points more phishing
  caught and no more false alarms.

## Published runs

The runs behind the website's figures are in [`docs/benchmark/`](benchmark/),
one line per email (id, label, verdict, scores), nothing of the email.
The id is the first 16 hex digits of the SHA-256 of the raw message, so
anyone with the same dataset finds the same emails and can compare:

```bash
python3 scripts/export_benchmark.py --compare docs/benchmark/fresh-phishing.jsonl my-run.jsonl
```

The 117 inbox emails are personal mail and are not published.

## Results

Phishing from phishing_pot and Nazario 2025, legitimate mail from
Apache mailing lists and 117 inbox emails, all sent from 2026-01-01.

| Date | Server | Legitimate flagged | Phishing caught |
| --- | --- | --- | --- |
| 10-16 | 2.0.7 | 130 of 297, 43.8% (38.2% to 49.5%) | 461 of 500, 92.2% |
| 10-16 | header model off | 14 of 297, 4.7% | 225 of 500, 45.0% |
| 10-16 | + subject read by the text model | 14 of 297, 4.7% | 436 of 500, 87.2% |
| 10-16 | 2.0.8 (link model needs a confirming sign) | 1 of 297, 0.3% (0.1% to 1.9%) | 436 of 500, 87.2% |
| 10-23 | 2.0.9 | 1 of 297; inbox 0 of 117 | control sample, 1,707 of 1,997, 85.5% (83.9% to 87.0%) |
| 10-24 | 2.0.10 (link rule) | 1 of 297; inbox 0 of 117 | fresh sample, 1,812 of 2,000, 90.6% (89.2% to 91.8%) |
| 11-01 | 2.0.12 (whole bodies read, text read as shown and as written) | 1 of 297; inbox 0 of 117 | same fresh sample, 1,804 of 2,000, 90.2% (88.8% to 91.4%) |

Each step taught something.

- Reading the whole email cost some "phishing". 2.0.10 read only the
  subject of 74 HTML emails whose body it could not reach, and 2.0.11
  and 2.0.12 read them whole. Most were casino and insurance ads that
  phishing_pot files as phishing. On the full text the model calls 45 of
  them safe, and it finds 29 others it had missed.
- Removing invisible characters also removed a sign. The model learned
  runs of zero-width and byte-order-mark characters as a mark of dubious
  mail (0.98 with them, 0.05 without on the same email). The text is now
  read both as shown and as written and the higher score is kept, which
  gives 1,804 caught instead of 1,797 with no new false alarm.
- The 92.2% was mostly an artefact. In 2.0.7, 121 of the 130 false
  alarms were decided by the trained header model alone, which scored
  modern mailing-list headers near 1.0. With it switched off, false
  alarms fell to 4.7% and detection to 45%, so that model had been
  flagging almost everything.
- The text model was fed the wrong text. It was trained on subject plus
  body but given the body only. On 120 missed emails the score went from
  10% to 94% on average once the subject was added.
- The link model alone is not evidence. All 14 remaining false alarms
  were decided by it, on written-out links in plain-text mail. Requiring
  a threat-intel hit or a strong sign removed 13 and lost no phishing.
- The tuned figure held on unseen mail, with 85.5% on 2,000 control
  emails nobody had looked at against 87.2% on the studied 500.
- The inbox mail revealed one real-world bug. 2 of 117 inbox emails were
  flagged because a Microsoft 365 relay added a lower
  `Authentication-Results` header that the parser read first. The
  topmost one is now used (0 of 117).
- DKIM-signed attackers were the largest group of misses (190 of 290),
  because attackers sign mail from their own domains. Flagging signed
  senders whose links all lead elsewhere, with phishing-like wording,
  took fresh-sample detection from 85.4% to 90.6% with no new false
  alarm, exactly as the replay on cached scores had predicted.

## Measured and rejected

| Candidate | Result | Why not shipped |
| --- | --- | --- |
| Text score of 0.95 forcing the verdict on signed senders | 92.6% caught | 2 more inbox false alarms (3.4%) |
| Young sender domain (RDAP) | +0.45 points | not worth sending every sender domain to a third party; this phishing mostly comes from domains years old |
| r6 text model (recent phishing in training) | +1.2 points | below the +3 fixed before training |
| r7h (more weight on true labels) | +2.6 points (93.0%) | below +3; offline it flags 5 of 255 unseen legitimate English emails against 1 |
| r7b (mmBERT-base, 2.2 times bigger) | +0.8 points | one more inbox false alarm, 395 ms per email against 190 ms |

The link rule leans on the text score (0.5), so every new text model is
measured with it. r7b's single inbox false alarm was a crypto exchange's
signed notice scored 0.56, where the current model stays below 0.5.

## Known gaps

- The 414 legitimate emails come from one person's inboxes plus
  technical mailing lists, so another inbox may see more false alarms.
- English (81.6%) and French (87.2%) are the weakest languages.
- Only 6 languages are measured on real phishing, while the text model
  reads 22.
- The 297 Apache emails were used while tuning (the 2.0.8 change was
  made on them), so they are not an unseen set. The 117 inbox emails
  are unseen, and 0 of 117 were flagged (at most 3.2% at 95%). That is
  the figure to expect on everyday mail, not the 0.2% of the two
  together.
- The 2,000 phishing emails of the 2.0.12 run are the sample of the
  2.0.10 run, measured again after looking at the emails whose verdict
  changed (and one change, the text read as shown and as written, came
  from that look). The next figure is measured on a fresh sample drawn
  with `--exclude`, before any change is made on it.
- The phishing labels come from phishing_pot and Nazario as published,
  and some are ads, not phishing. They are kept, as decided before the runs,
  and the rate is read with that in mind.
- Only one channel is measured, the raw message with its headers as
  Gmail gives it with "Read full headers" on. Gmail without the headers
  (visible text, links and Gmail's own signals) and Outlook are not
  measured yet. Outlook gives only the visible text and links, with no
  SPF, DKIM or DMARC, so the softer path for authenticated senders never
  applies there. A false alarm
  rate per channel needs the same legitimate mail scanned both ways.
- The misses are counted by trust path in each run (122 by default, 74
  on `crypto_verified` in 2.0.12) but not yet published as rates.
- The multilingual text model's weights are not public. Anyone can
  rerun the benchmark against PhishLens Cloud and compare email by email
  with the published runs (`docs/benchmark/`), but not rebuild the
  model. A self-hosted server uses the public English model, which
  flags more legitimate mail ([languages](languages.md#text-model)).
- The text model reads the first 256 tokens, so a long benign preamble
  can push the lure out of its window (threat model, R10). The links and the
  sender are checked whatever the length.
