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
same sources. `--exclude` leaves out the emails of earlier runs (their
caches): a change tuned while looking at one sample is then measured on
emails nobody looked at. `--domain-age` adds the age of each
sender's domain at sending time (RDAP, looked up from your machine, not
by the server); the lookups go to `<cache>.domains-private.json`, which
lists sender domains: publish the cache, not that file. The script shows
its progress and, on Ctrl+C, prints the report of what was scored so
far.

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
- **A control sample for every tuned change.** A threshold or rule
  chosen while looking at a run's errors is measured again on a sample
  drawn with `--exclude` from that run, and that second figure is the
  one published.
- **Check the errors, not the rest.** `--show-errors` lists the false
  alarms and missed phishing (sender domain and subject, on your machine
  only). A phishing found in an inbox export is listed in a file passed
  with `--drop`; report how many were dropped and why.
- **Report everything:** the server version (`/health`), the date of the
  run, the sources with their dates, the table, and the emails that could
  not be scored.

## Published runs

The runs behind the figures on public data are in [`docs/benchmark/`](benchmark/):
one line per email with its id, label, verdict and scores, nothing of
the email itself. The id is the first 16 hex digits of the SHA-256 of
the raw message, so anyone with the same public dataset finds the same
emails, runs the benchmark against their own server and compares:

```bash
python3 scripts/export_benchmark.py --compare docs/benchmark/fresh-phishing.jsonl my-run.jsonl
```

The 117 inbox emails are not published: they are personal mail.

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
| 2026-10-23 | 2.0.9 code, text model r4 | 1 of 297: 0.3% (0.1% to 1.9%) | control sample: 1,707 of 1,997: 85.5% (83.9% to 87.0%) |
| 2026-10-24 | 2.0.9 code + link rule, text model r4 | 1 of 297: 0.3% (0.1% to 1.9%); inbox 0 of 117 | fresh sample: 1,812 of 2,000: 90.6% (89.2% to 91.8%) |

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

**Control sample (2026-10-23).** 2,000 phishing emails drawn with
`--exclude` from every earlier run, from the same sources and dates,
against the same server: 1,708 of 1,998 caught, 85.5% (83.9% to 87.0%);
2 files could not be parsed. The 87.2% of the 500 emails studied holds
on emails nobody looked at. 190 of the 290 misses were on the
`crypto_verified` path.

**Real inbox mail (2026-10-23).** 117 legitimate emails received in
five personal Gmail inboxes after the text model's training mail was
exported (from 2026-10-15), with bank, university and service
notifications: 2 flagged, 1.7% (0.5% to 6.0%). Both came from a
university on the allowlist, DKIM-signed and passing DMARC, yet were
scored on the default path: the message also carried an
`Authentication-Results` header from an internal Microsoft 365 relay
("dkim=none"), lower in the headers, and the parser kept that one. From
2.0.9 the topmost one, written by the receiving provider, is used. The
same 117 emails against the fixed server: 0 flagged, 0.0% (0.0% to
3.2%).

**A change measured and rejected.** On the `crypto_verified` path,
letting a text score of 0.95 or more force the verdict caught 92.6%
(91.4% to 93.7%) of the control phishing instead of 85.5%, but flagged 2
more of the 117 inbox emails (3.4%, 1.3% to 8.5%): legitimate
DKIM-signed notifications from domains outside the allowlist score as
high as 0.98 and 1.00. It is not shipped; those misses wait for a
better text model or another signal.

**Domain age, measured and rejected (2026-10-24).** On the same path, a
young sender domain was the next candidate signal (`--domain-age`,
RDAP looked up from the benchmark machine). Of the 191 control phishing
emails on `crypto_verified`, RDAP gave an age for 67: only 9 were under
90 days old, and the median was about 5.8 years. Flagging those 9 would
catch 0.45 points more phishing with no inbox false alarm; not worth
sending every user's sender domains to a third party, so it is not
shipped. This phishing comes mostly from old, established domains, not
freshly registered ones.

**A new text model, measured and not shipped (2026-10-24).** r6 is r4's
recipe on the cleaned training data, with recent real phishing
(phishing_pot 2026, Nazario 2025) added to training except the control
sample, which stayed the test set. The rule, fixed before training: r6
replaces r4 only with at least 3 points more control phishing caught and
no more false alarms than r4 on the inbox mail and at most 2 on the
mailing lists. Measured the same day, against the same mail:

| | r4 | r6 |
| --- | --- | --- |
| Control phishing caught | 1,709 of 2,000: 85.5% (83.8% to 86.9%) | 1,734 of 2,000: 86.7% (85.1% to 88.1%) |
| English phishing caught | 357 of 493: 72.4% | 356 of 493: 72.2% |
| Mailing lists flagged | 1 of 297 | 2 of 297 |
| Inbox flagged | 0 of 117 | 0 of 117 |

+1.2 points: r4 stays. On the text alone, offline, r6 catches 95.9% of
the same English phishing (r4: 93.0%); through the whole system, 72.2%.
The missed phishing now has a mean wording score of 71%: the model sees
it, and the `crypto_verified` path (text weighed by half, only Safe
Browsing forces the verdict) holds it back. A better text model alone
will not lift those misses; the trust path is the bottleneck.

**Where the links go: shipped (2026-10-24).** On the `crypto_verified`
path, 64% of the control phishing (123 of 191) had no link to its
sender's own domain and at least one elsewhere, against 22% of the
legitimate signed mail (10 of 46). The rule was chosen on the control
sample, before any fresh mail was drawn, by its own criterion: no more
false alarms on the 414 legitimate emails, then the most phishing
caught. Links through a mass-mailing platform's click tracking
(SendGrid, Mailchimp...) are not counted as "elsewhere" (a real payment
service's notification linked only through SendGrid), and style sheets
and web fonts are not links. The rule: on that path, no link to the
sender's own domain, at least one to an unknown site or a public file
host, and a text score of 0.5 or more make the email phishing
(`CRYPTO_LINK_RULE`, `backend/link_alignment.py`).

It was frozen, then checked on 2,000 phishing emails drawn with
`--exclude` from every earlier run (the threshold, fixed in advance: at
least 3 points more, no more false alarms), first on the cached scores
and then on the running server with the rule on:

| | Without the rule | With the rule (server, 2026-10-24) |
| --- | --- | --- |
| Fresh phishing caught | 1,708 of 2,000: 85.4% (83.8% to 86.9%) | 1,812 of 2,000: 90.6% (89.2% to 91.8%) |
| English | 72.4% (control) | 395 of 484: 81.6% (77.9% to 84.8%) |
| French | 75.7% (control) | 116 of 133: 87.2% (80.5% to 91.9%) |
| Mailing lists flagged | 1 of 297 | 1 of 297 |
| Inbox flagged | 0 of 117 | 0 of 117 |

The server gave exactly the figure the replay predicted (1,812). The
misses on `crypto_verified` fell from 191 to 81; the remaining ones send
no link, link to their own domain, or go through click tracking.

**A text model leaning on the true labels, measured and not shipped
(2026-10-25).** r7h is r6's training data with more weight on the true
labels than on the teacher model (alpha 0.9 instead of 0.7). The rule,
fixed before training, is the one r6 had, now against the system with
the link rule: at least 3 points more control phishing caught, no more
false alarms on the inbox mail, at most 2 on the mailing lists.

| Same day, same mail | r4 | r7h |
| --- | --- | --- |
| Control phishing caught | 1,808 of 2,000: 90.4% (89.0% to 91.6%) | 1,859 of 2,000: 93.0% (91.7% to 94.0%) |
| English | 81.5% | 84.4% |
| French | 82.4% | 91.9% |
| Mailing lists flagged | 1 of 297 | 1 of 297 |
| Inbox flagged | 0 of 117 | 0 of 117 |

+2.6 points: below the 3 set in advance, so r4 stays, although the two
intervals do not overlap. Offline, on the legitimate English mail of the
inbox that no model saw, r7h flags 5 of 255 (r4: 1), a sign that more
inbox mail could show more false alarms than these 117 do.

**A bigger text model, measured and not shipped (2026-10-25).** r7b is
mmBERT-base (about 2.2 times the weights of mmBERT-small) on the same
data, with the same rule plus a speed limit fixed before training: a
median scan under 250 ms on the server.

| Same day, same mail | r4 | r7b |
| --- | --- | --- |
| Control phishing caught | 1,808 of 2,000: 90.4% (89.0% to 91.6%) | 1,825 of 2,000: 91.2% (89.9% to 92.4%) |
| Mailing lists flagged | 1 of 297 | 0 of 297 |
| Inbox flagged | 0 of 117 | 1 of 117 |
| Median scan, a 250-token email | 190 ms | 395 ms |

+0.8 points, one more inbox false alarm and twice the time: r4 stays.
The inbox false alarm is a real exchange's notice about crypto deposits,
DKIM-signed, with its links on other domains: r7b scored its wording
0.56, just above the link rule's 0.5, where r4 stays below. The link
rule leans on the text score, so a new text model must be measured with
it, as here.
