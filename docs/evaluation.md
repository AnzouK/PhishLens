# Evaluation

How PhishLens is measured, how much each figure can be trusted, and how
to measure it yourself.

## What is measured

| Measure | What it covers | Where |
| --- | --- | --- |
| Public benchmark | The whole system as users see it (text model, links, sender checks, threat intelligence), on emails anyone can download | `scripts/benchmark.py`, this page |
| Model evaluation | The multilingual text model alone, on held-out mail including private mail | [multilingual-model.md](multilingual-model.md) |
| Live evaluation | Scans a user reviewed as right or wrong in their own history | `scripts/live_eval.py` |
| Original agents | The English DistilBERT and the two Random Forests, offline, on public corpora | [PhishingDetector](https://github.com/dodi-ctrl/PhishingDetector#results) |

Every rate is given with its count and a 95% Wilson confidence
interval: "1/255 = 0.4% (95% CI 0.1% to 2.2%)" says how little a single
error out of a few hundred emails pins down. A rate without its count is
not reported.

## Public benchmark

```bash
python3 scripts/benchmark.py \
    --phishing phishing_pot/email nazario/phishing-2025.mbox \
    --legit legit/*.mbox \
    --since 2026-01-01 --sample 500 \
    --server http://127.0.0.1:8000 --markdown
```

The script sends each email to a PhishLens server as the extension does
(the full message, headers included), then prints, per language the
server detects and overall, the confusion matrix, the share of
legitimate emails flagged and the share of phishing caught, each with its
confidence interval. Answers are kept in `benchmark-results.jsonl` (a
hash of each email, its label and the result, never the email), so a run
resumes where it stopped and the per-email results can be published.
`--sample N` scores at most N emails per label, always the same ones (the
N smallest hashes), so another person picks the same emails from the
same sources. The script shows its progress and, on Ctrl+C, prints the
report of what was scored so far.

Run it against your own server: PhishLens Cloud answers 30 requests a
minute (`--per-minute 25`) and its Safe Browsing quota is shared by every
user.

### Sources

| Side | Source | Notes |
| --- | --- | --- |
| Phishing | [phishing_pot](https://github.com/rf-peixoto/phishing_pot) | Real phishing `.eml` files with full headers, mostly English and Portuguese |
| Phishing | [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | One mbox per year |
| Legitimate | Public mailing-list archives (mbox downloads) | Real and recent, but technical: no bank or delivery mail |
| Legitimate | Your own mailbox | The most realistic; publish the counts and the per-email results only, never the emails |

There is no public, recent collection of everyday legitimate mail (bank
notices, deliveries, newsletters) in several languages; that is the main
limit of any public benchmark of phishing detection, this one included.
Report the legitimate side source by source.

### Rules

- **Date filter.** Keep only emails sent after the newest training data
  of the model under test (`--since`): an email the model trained on
  measures memory, not detection. The multilingual model's phishing test
  sets, kept out of its training, were Nazario 2025 and phishing_pot 2026:
  for it, use phishing from those years or later.
- **No selection after the fact.** Decide the sources and the date
  before looking at the results, and keep every email the server could
  read.
- **Report everything:** the server version (`/health`), the date of the
  run, the sources with their dates, the table, and the emails that could
  not be scored.

## Results

Sources of every run below: phishing from phishing_pot and Nazario 2025,
legitimate mail from public Apache mailing-list archives, all sent from
2026-01-01, `--sample 500`.

| Date | Server | Legitimate emails flagged | Phishing caught |
| --- | --- | --- | --- |
| 2026-10-16 | PhishLens Cloud 2.0.7, text model r4 | 130 of 297: 43.8% (95% CI 38.2% to 49.5%) | 461 of 500: 92.2% (89.5% to 94.2%) |
| 2026-10-16 | main after the metadata fix, not released | 14 of 297: 4.7% (2.8% to 7.8%) | 225 of 500: 45.0% (40.7% to 49.4%) |
| 2026-10-16 | main after the subject fix, not released | 14 of 297: 4.7% (2.8% to 7.8%) | 436 of 500: 87.2% (84.0% to 89.8%) |
| 2026-10-16 | 2.0.8 code (link fix), text model r4 | 1 of 297: 0.3% (0.1% to 1.9%) | 436 of 500: 87.2% (84.0% to 89.8%) |

**What the 2.0.7 run showed.** On the 130 false alarms, the mean scores
were 1% for the wording, 56% for the links and 92% for the sender, and
121 were decided by one check alone. The sender score came from the
trained metadata Random Forest, which read the raw `.eml` and scored the
headers of modern mailing-list mail near 1.0, enough to force the
verdict. Emails scanned in Gmail did not go through it: their headers
already went to the rules. From 2.0.8 the trained metadata model is off
by default for every request (`METADATA_MODEL_ENABLED`), and the sender
score comes from the rules and the real SPF, DKIM and DMARC results.

**What the second run showed.** Without that model, false alarms fell
to 4.7%, and so did detection, to 45.0%: the 92.2% had come in large
part from a check that flagged almost everything. On the 275 missed
phishing emails the text score averaged 13%, far from the 92.5%
measured offline. The server gave the text model the body only, while
the model was trained and measured on the subject followed by the body:
on 120 of the missed emails, the score went from 10% on average to 94%
with the subject (112 of 120 above 0.85). From 2.0.8 the model reads
the subject. The 14 remaining false alarms were all decided by the link
score alone, on plain-text mailing-list mail whose written-out links
(build servers, personal sites) go to the link model.


**What the third run showed.** With the subject, detection rose to
87.2% (Dutch from 11% to 90%, Portuguese from 29% to 95%) and false
alarms did not move. The 14 false alarms were all on the default path,
decided by the link score alone: a plain `http://` link was enough to
confirm the trained link model. Replayed on the cached scores with the
link score never deciding alone, false alarms fall to 1 of 297, for 2
more missed phishing emails. 2.0.8 still lets strong link signs (raw IP
address, "@" before the host, suspicious TLD, file on a public cloud
host) confirm it; the next run measures the result.

Of the 64 missed phishing emails, 38 were on the `crypto_verified`
path: DKIM aligned with the sender's domain, which an attacker gets for
their own domain. On that path the text weighs half and only Safe
Browsing forces the verdict. Replayed on the same scores, sending
unlisted DKIM-aligned senders to the default path together with the
link change catches 465 of 500 (93.0%) for 2 of 297 false alarms. That
discount exists for legitimate bank, delivery and university mail from
unlisted domains, which these mailing lists do not contain: the change
waits for a measurement on such mail.

**The 2.0.8 run.** The link change removed 13 of the 14 false alarms
and no phishing email was lost. The remaining false alarm was decided by
the sender score alone. By language, among the phishing emails: German
50 of 52 caught, Dutch 145 of 161, Portuguese 113 of 119, French 21 of
25, English 88 of 122; English is the weakest, and the 38 phishing
emails on the `crypto_verified` path are the largest group of misses.
