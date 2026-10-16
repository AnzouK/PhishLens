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

**What the 2.0.7 run showed.** On the 130 false alarms, the mean scores
were 1% for the wording, 56% for the links and 92% for the sender, and
121 were decided by one check alone. The sender score came from the
trained metadata Random Forest, which read the raw `.eml` and scored the
headers of modern mailing-list mail near 1.0, enough to force the
verdict. Emails scanned in Gmail did not go through it: their headers
already went to the rules. From 2.0.8 the trained metadata model is off
by default for every request (`METADATA_MODEL_ENABLED`), and the sender
score comes from the rules and the real SPF, DKIM and DMARC results.
The same run on 2.0.8 will be added here.
