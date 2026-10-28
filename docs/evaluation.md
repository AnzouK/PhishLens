# Evaluation

How PhishLens is measured, how far each figure can be trusted, and how
to measure it yourself.

| Measure | What it covers | Where |
| --- | --- | --- |
| Public benchmark | The whole system as users see it, on emails anyone can download | this page, `scripts/benchmark.py` |
| Model evaluation | The text model alone, on held-out mail | [multilingual-model.md](multilingual-model.md) |
| Live evaluation | Scans a user marked right or wrong in their own history | `scripts/live_eval.py` |

Every rate comes with its count and a 95% Wilson confidence interval:
"1 of 297 (0.1% to 1.9%)" says how little one error in a few hundred
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
Run it against your own server: PhishLens Cloud is rate-limited and its
Safe Browsing quota is shared.

| Side | Source |
| --- | --- |
| Phishing | [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (real `.eml`, mostly English and Portuguese), [Nazario](https://monkey.org/~jose/phishing/) |
| Legitimate | Apache mailing-list archives: real and recent, but technical, no bank or delivery mail |
| Legitimate | Personal inboxes: the most realistic; counts only, never the emails |

There is no public, recent collection of everyday legitimate mail (bank
notices, deliveries, newsletters) in several languages. That is the
main limit of this benchmark, and why the false-alarm rate rests on 414
emails.

### Rules

- **Only mail newer than the model's training data** (`--since`): mail
  the model trained on measures memory, not detection.
- **Sources and dates decided before looking at results**, and every
  readable email kept.
- **Every tuned change is measured again on a control sample** drawn
  with `--exclude`, and that second figure is the one published.
- **Decision rules fixed before training or tuning:** a new text model
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

The 117 inbox emails are not published: they are personal mail.

## Results

Phishing from phishing_pot and Nazario 2025, legitimate mail from
Apache mailing lists and 117 inbox emails, all sent from 2026-01-01.

| Date | Server | Legitimate flagged | Phishing caught |
| --- | --- | --- | --- |
| 10-16 | 2.0.7 | 130 of 297: 43.8% (38.2% to 49.5%) | 461 of 500: 92.2% |
| 10-16 | header model off | 14 of 297: 4.7% | 225 of 500: 45.0% |
| 10-16 | + subject read by the text model | 14 of 297: 4.7% | 436 of 500: 87.2% |
| 10-16 | 2.0.8 (link model needs a confirming sign) | 1 of 297: 0.3% (0.1% to 1.9%) | 436 of 500: 87.2% |
| 10-23 | 2.0.9 | 1 of 297; inbox 0 of 117 | control sample: 1,707 of 1,997: 85.5% (83.9% to 87.0%) |
| 10-24 | 2.0.10 (link rule) | 1 of 297; inbox 0 of 117 | fresh sample: 1,812 of 2,000: 90.6% (89.2% to 91.8%) |

What each step taught:

- **The 92.2% was mostly an artefact.** In 2.0.7, 121 of the 130 false
  alarms were decided by the trained header model alone, which scored
  modern mailing-list headers near 1.0. Switched off, false alarms fell
  to 4.7% and detection to 45%: that model had been flagging almost
  everything.
- **The text model was fed the wrong text.** It was trained on subject
  plus body and given the body only: on 120 missed emails the score went
  from 10% to 94% on average once the subject was added.
- **The link model alone is not evidence.** All 14 remaining false
  alarms were decided by it, on written-out links in plain-text mail.
  Requiring a threat-intel hit or a strong sign removed 13 and lost no
  phishing.
- **The tuned figure held on unseen mail.** 85.5% on 2,000 control
  emails nobody had looked at, against 87.2% on the studied 500.
- **One real-world bug in the inbox mail.** 2 of 117 inbox emails were
  flagged because a Microsoft 365 relay added a lower
  `Authentication-Results` header that the parser read first; the
  topmost one is now used (0 of 117).
- **DKIM-signed attackers were the largest group of misses** (190 of
  290): attackers sign mail from their own domains. Flagging signed
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
measured with it: r7b's single inbox false alarm was a crypto exchange's
signed notice scored 0.56 where the current model stays below 0.5.

## Known gaps

- 414 legitimate emails, one person's inboxes plus technical mailing
  lists: another inbox may see more false alarms. The upper bound of
  the interval, 1.4%, is the honest figure.
- English (81.6%) and French (87.2%) are the weakest languages.
- Only 6 languages are measured on real phishing; the text model reads
  22.
