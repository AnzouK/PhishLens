# Operations guide

How to deploy, observe and load-test a PhishLens backend. The examples
match the reference deployment (Oracle Cloud ARM VM, Docker, Caddy in
front); adapt names and paths for your own host.

## Deploy or update

On the reference VM, one command does everything below: pull
`origin/main`, build, restart, wait for `/health`, run a smoke
`/analyse`, copy the landing page, and roll back to the previous image
if the new one is not healthy.

```bash
bash ~/PhishLens/scripts/redeploy.sh              # update and redeploy
bash ~/PhishLens/scripts/redeploy.sh --no-pull    # rebuild the current checkout
bash ~/PhishLens/scripts/redeploy.sh --rollback   # back to the previous image
```

The manual steps, for another host or for debugging:

```bash
cd ~/PhishLens
git fetch origin && git reset --hard origin/main
cd backend
docker build -f Dockerfile.cloud -t phishlens .
docker rm -f phishlens            # "docker restart" would keep the old image
docker run -d --restart=always \
  --network web \
  --env-file ~/.phishlens.env \
  -v ~/phishlens_data:/data \
  -v ~/phishlens_model:/home/user/app/model \
  -v ~/phishlens_agents:/home/user/app/agents \
  --name phishlens phishlens
docker logs -f phishlens          # wait for "Text model loaded from ..."
```

The two extra volumes keep the text model and the Random Forest agents
across container re-creations, so only the first boot downloads them
from Hugging Face. Create them once with
`mkdir -p ~/phishlens_model ~/phishlens_agents` (the container runs as
uid 1000, the same uid as the `opc` user). To pick up a new model
version published on Hugging Face, empty the folder
(`rm -rf ~/phishlens_model/*`) and re-create the container.

`~/.phishlens.env` holds the secrets and tuning knobs (`GSB_API_KEY`,
`REPUTATION_CACHE_DB=/data/reputation.db`, rate limits). It is never
committed. The website is static and deployed separately; Caddy serves
`/fr/`, `/pt/` and the other language folders as they are, and its
`handle_errors` block serves `404.html` for unknown paths in every
language. Its texts
live in `site-src/` (one file per language, legal pages translated from
`PRIVACY.md` and `TERMS.md`); rebuild it after any change, then copy it:
`python3 scripts/build_site.py` (needs pandoc), then
`rsync -avz --delete site/ <vm>:~/phishlens-site/`. When `PRIVACY.md` or
`TERMS.md` changes, update the translations in `site-src/legal/` too.

### Random Forest agents without pickle (one-time, v1.12)

The backend prefers `url_agent.skops` / `metadata_agent.skops` and only
falls back to the old joblib files, with a warning in the logs. Convert
and publish them once, from inside the running container so the same
scikit-learn version reads the originals:

```bash
docker exec -it phishlens python convert_agents_to_skops.py            # convert and verify
docker exec -it phishlens python convert_agents_to_skops.py --upload   # then publish
```

The script checks that the skops copy gives exactly the same
probabilities as the original on 200 random inputs before writing
anything. `--upload` asks for a Hugging Face write token (not echoed).
Afterwards add `AGENTS_ALLOW_PICKLE=0` to `~/.phishlens.env`, re-create
the container, and check that the logs say `Loaded trained url_agent
from agents/url_agent.skops`.

### Switch the text model

The text model is chosen with `HF_MODEL_REPO` in `~/.phishlens.env`
(default `AnzouKiona/phishlens-distilbert`). Each repository is
downloaded into its own subfolder of the model volume
(`~/phishlens_model/<owner>--<name>`), so switching back and forth costs
one download per model and never mixes files. A private repository also
needs `HF_TOKEN` (a read-only token). How the model is fed and how its
scores are read comes from `phishlens_text_agent.json` in the repository
([architecture.md, text model](architecture.md#text-model)).

```bash
# in ~/.phishlens.env
HF_MODEL_REPO=<owner>/<model>
HF_MODEL_REVISION=<commit sha>      # pin the exact model (see below)
HF_AGENTS_REVISION=<commit sha>     # pin the URL and metadata agents
HF_TOKEN=hf_...                     # private repositories only
```

Pin both revisions: without them the server downloads whatever the
repository holds at that moment, and the log says so at start-up. The
full sha of the latest commit (run where `HF_TOKEN` is set for a private
repository):

```bash
python3 -c "from huggingface_hub import HfApi; print(HfApi().model_info('<owner>/<model>').sha)"
```

Re-create the container, then check what answers:

```bash
curl -s https://phishlens.dev/health | python3 -m json.tool
```

`text_model` shows the repository, the display name, `normalize`,
`temperature` and `override_threshold`. To go back, restore the previous
`HF_MODEL_REPO` and re-create the container: the old model is still in
its folder. A new revision is a new `HF_MODEL_REVISION`: each pinned
revision gets its own folder (`<owner>--<name>@<sha>`).

### OCR languages

The Docker images install the Tesseract packs for English, French,
Spanish, Portuguese, German, Italian, Dutch, Russian, Ukrainian, Arabic,
simplified Chinese, Japanese, Korean and Hindi, and `OCR_LANG=auto`
picks them per image ([languages.md](languages.md#ocr)). On a host
without Docker, install the `tesseract-ocr-<lang>` packages you need;
missing packs are skipped.

### Collect reports from users

Reports (`POST /feedback`) are stored only when `FEEDBACK_DIR` is set:

```bash
# in ~/.phishlens.env
FEEDBACK_DIR=/data/feedback        # inside the data volume, so it survives re-creation
```

Caddy must also forward the path: add `/feedback` to the `@api` matcher of
the main domain (`@api path /analyse* /explain* /health /reputation* /feedback`)
and reload Caddy.

To be told about each new report, set `FEEDBACK_NOTIFY_URL` to an
`https://` address that accepts a plain-text POST, for example an
[ntfy](https://ntfy.sh) topic (`https://ntfy.sh/<long random name>`,
followed in the ntfy app). The message gives the kind of report, the
verdict, the languages, where it came from and its reference, never the
text. `FEEDBACK_NOTIFY_CLICK` (an `https://` address) is opened when the
message is tapped, with `#<reference>` added. Read the reports on the VM with
`cat ~/phishlens_data/feedback/feedback-*.jsonl | python3 -m json.tool --json-lines`.
To delete one on request: `python3 scripts/delete_report.py --dir
~/phishlens_data/feedback <reference>` (from the repository checkout on
the server). Files stay private: the backup
script archives the data folder encrypted; never commit or publish them.

### PhishTank feed

Without an application key PhishTank allows only a few downloads a day
(and new keys cannot be requested while its registration is closed), so
the backend downloads the feed every 6 hours, keeps the last good copy
next to the reputation cache (`/data/phishtank.json.gz` with
`REPUTATION_CACHE_DB=/data/reputation.db`) and loads it at start: a
restart costs no download. When a download is refused,
`/reputation/stats` shows why in `phishtank_last_error` (for example
`HTTP 429`), and the previous list stays in use.

## Domains

`phishlens.dev` serves the website and, on the API paths, PhishLens
Cloud; `www.phishlens.dev` redirects to it. The former address,
`anzouk.duckdns.org`, keeps answering the API paths so that extensions
older than 2.0.5 go on working, and redirects every other page to
`phishlens.dev`. In the Caddyfile:

```caddy
www.phishlens.dev {
        redir https://phishlens.dev{uri} permanent
}

anzouk.duckdns.org {
        import security_headers
        @api path /analyse* /explain* /health /reputation* /feedback
        handle @api {
                reverse_proxy phishlens:7860
        }
        handle {
                redir https://phishlens.dev{uri} permanent
        }
}
```

The `phishlens.dev` block is the former main domain block, renamed.

## Configuration

The backend reads environment variables (`~/.phishlens.env` on the VM).
The most useful:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GSB_API_KEY` | empty | Google Safe Browsing key; that tier is off without it |
| `REPUTATION_ENABLE_GSB` / `_PHISHTANK` / `_URLHAUS` / `_DBL` | `1` | Turn each threat-intel source on or off |
| `PHISHTANK_API_KEY` / `PHISHTANK_REFRESH_S` | empty / 6 h (1 h with a key) | PhishTank application key, and how often its feed is downloaded; the last good feed is kept next to the cache (`PHISHTANK_FEED_PATH`) |
| `REPUTATION_CACHE_DB` | `~/.cache/phishlens/reputation.db` | SQLite cache for URL verdicts (24 h TTL) |
| `CRYPTO_LINK_RULE` | `1` | `0` lets a DKIM-signed sender keep its softer path even when every link leads away from its domain and the wording looks like phishing ([evaluation](evaluation.md#results)) |
| `METADATA_MODEL_ENABLED` | `0` | `1` scores raw emails with the trained metadata Random Forest; off because it flags most modern legitimate headers ([evaluation](evaluation.md#results)) |
| `RATE_LIMIT_ANALYSE` | `30/minute` | Per-IP limit (also `RATE_LIMIT_ATTACHMENT`, `RATE_LIMIT_EXPLAIN`) |
| `LIME_NUM_SAMPLES` | `100` | Forward passes per explanation: higher is sharper and slower |
| `OCR_MAX_PAGES` / `OCR_TIMEOUT_S` | `3` / `10` | Pages of a scanned PDF sent to OCR, and the time limit per page |
| `AGENTS_ALLOW_PICKLE` | `1` | `0` refuses pickle files and loads only the `.skops` agents (PhishLens Cloud runs with `0`) |
| `MODEL_DIR` / `HF_MODEL_REPO` | `./model` / `AnzouKiona/phishlens-distilbert` | Where the text model is stored, and which Hugging Face repository it comes from ([switching models](docs/operations.md#switch-the-text-model)) |
| `HF_MODEL_REVISION` / `HF_AGENTS_REVISION` | empty | Commit of the model / agents repository to download; empty takes the latest (a warning is logged) |
| `HF_TOKEN` | empty | Read-only token, only for a private model repository |
| `OCR_LANG` | `auto` | Tesseract languages; `auto` picks them from the script of each image |
| `FEEDBACK_DIR` / `RATE_LIMIT_FEEDBACK` | empty / `20/hour` | Where reports sent from the extension are stored (empty: not collected) |
| `FEEDBACK_NOTIFY_URL` | empty | `https://` address that receives a one-line message for each new report, for example an [ntfy](https://ntfy.sh) topic; never the report's text; `FEEDBACK_NOTIFY_CLICK` is the address it opens when tapped (the reference is added after `#`) |
| `METRICS_ENABLED` | `1` | Prometheus metrics on `/metrics` (keep it private) |
| `LOG_LEVEL` | `INFO` | Log level for the `phishlens.*` loggers |

`RESULT_CACHE_TTL` / `RESULT_CACHE_MAX`, `FEEDBACK_MAX_MB`, `OCR_LANG`
and the others are described in their sections below and in
`backend/settings.py`.

## Health and status endpoints

| Endpoint | Use |
| --- | --- |
| `GET /health` | Liveness, server version, which agents run a trained model (`model`) or rules, and which text model is loaded (`text_model`). |
| `GET /reputation/stats` | Cache hit rate, GSB quota consumed and remaining, PhishTank feed size. |
| `GET /metrics` | Prometheus metrics (see below). Internal only. |

## Logging

All runtime modules log through `logging.getLogger("phishlens.<module>")`
to stdout, so `docker logs phishlens` shows everything. Format:
`2026-09-29 10:00:00,000 WARNING phishlens.reputation: GSB request failed: ...`.
Set `LOG_LEVEL=DEBUG` (or `WARNING` to quieten it) in the env file.
Email content is never logged.

## Metrics

Enabled by default when `prometheus-fastapi-instrumentator` is installed
(it is in `requirements.txt`). Disable with `METRICS_ENABLED=0`.

| Metric | Meaning |
| --- | --- |
| `http_requests_total{handler, method, status}` | Request count per endpoint and status code (429s show rate limiting at work) |
| `http_request_duration_seconds{handler}` | Latency histogram per endpoint |
| `http_requests_inprogress` | Requests currently being served |
| `phishlens_verdicts_total{endpoint, verdict, trust_path}` | Final verdicts, split by `/analyse` or `/analyse_attachment` and by scoring path |

The ratio `phishing / (phishing + safe)` over time is the number to watch:
a sudden jump means an attack wave or a model regression, a drop to zero
means something upstream (Gmail DOM change, extension bug) broke.

Read them on the VM without exposing anything:

```bash
docker exec phishlens python3 -c \
  "import urllib.request as u; print(u.urlopen('http://127.0.0.1:7860/metrics').read().decode())" \
  | grep -E '^(phishlens_|http_requests_total)'
```

### Keep `/metrics` private

On the main domain Caddy only forwards the API paths (`/analyse*`,
`/explain*`, `/health`, `/reputation*`), so `/metrics` is already not
reachable there. The raw-IP compatibility block forwards everything,
so add a rule to it:

```caddy
http://130.61.146.213 {
        @metrics path /metrics
        respond @metrics 404
        reverse_proxy phishlens:7860
}
```

Then `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`.
If you run a Prometheus server, scrape `phishlens:7860/metrics` from
inside the `web` Docker network.

## Load testing

`scripts/locustfile.py` replays the extension's traffic mix: text scans
(most of it), full `.eml` scans, HTML attachment scans and health pings.
`/explain` is excluded because it measures LIME, not the service.

Rules: never aim it at the public demo (it would burn the shared Google
Safe Browsing quota), and raise the per-IP rate limits for the test
container, otherwise you are only measuring the limiter.

```bash
# 1. Throwaway container on the VM, localhost only, limits lifted,
#    external intel off so the test measures PhishLens itself
# (--env-file: the same text model as production, HF_MODEL_REPO and HF_TOKEN)
docker run -d --rm --name phishlens-load -p 127.0.0.1:8001:7860 \
  --env-file ~/.phishlens.env -e FEEDBACK_DIR= -e FEEDBACK_NOTIFY_URL= \
  -e RESULT_CACHE_TTL=0 \
  -v ~/phishlens_model:/home/user/app/model:ro \
  -v ~/phishlens_agents:/home/user/app/agents:ro \
  -e RATE_LIMIT_ANALYSE=100000/minute \
  -e RATE_LIMIT_ATTACHMENT=100000/minute \
  -e REPUTATION_ENABLE_GSB=0 -e REPUTATION_ENABLE_DBL=0 \
  -e REPUTATION_ENABLE_URLHAUS=0 -e REPUTATION_ENABLE_PHISHTANK=0 \
  phishlens
until curl -sf http://127.0.0.1:8001/health | grep -q '"name"'; do sleep 5; done   # model load

# 2. Run the test from the repo root, with Locust in a container
cd ~/PhishLens
docker run --rm --network host -v "$PWD":/mnt/locust locustio/locust \
  -f /mnt/locust/scripts/locustfile.py --host http://127.0.0.1:8001 \
  --headless -u 10 -r 2 -t 2m --csv /mnt/locust/loadtest --only-summary

# 3. Clean up
docker stop phishlens-load
```

`loadtest_stats.csv` has the median, p95 and p99 latency and the
throughput per endpoint. The test container shares the VM's CPU with
the live backend, so the demo is slower for those two minutes. Record the numbers in the table below with the
date and hardware so regressions are visible.

| Date | Host | Users | Endpoint | Median | p95 | Req/s | Failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-09-29 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse [text]` | 77 ms | 280 ms | 2.4 | 0 / 283 |
| 2026-09-29 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse [eml]` | 150 ms | 360 ms | 0.7 | 0 / 85 |
| 2026-09-29 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse_attachment` | 4 ms | 210 ms | 0.3 | 0 / 35 |
| 2026-09-29 | Oracle A1, 4 OCPU, 24 GB | 10 | all endpoints | 84 ms | 300 ms | 3.8 | 0 / 454 |
| 2026-10-15 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse [text]` | 65 ms | 120 ms | 2.6 | 0 / 309 |
| 2026-10-15 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse [eml]` | 57 ms | 110 ms | 0.8 | 0 / 95 |
| 2026-10-15 | Oracle A1, 4 OCPU, 24 GB | 10 | `/analyse_attachment` | 4 ms | 9 ms | 0.2 | 0 / 26 |
| 2026-10-15 | Oracle A1, 4 OCPU, 24 GB | 10 | all endpoints | 62 ms | 110 ms | 4.0 | 0 / 472 |

Reading the 2026-09-29 run: 2 minutes, CPU inference in FP32, threat
intel switched off, live backend running on the same VM. Ten users with
a 1 to 4 second think time offer about 4 requests per second, and the
server kept up with zero failures and a p99 under 0.5 s, so this
measures latency under realistic load, not the saturation point. The
attachment median is low because the test page has no visible text, so
the text agent is skipped. In production, a cache miss on the URL
reputation cascade adds the network round-trip of the intel APIs on top
of these numbers; `/explain` (LIME) is excluded and is much slower.

The 2026-09-29 run used the English DistilBERT; the 2026-10-15 run the
multilingual model (mmBERT-small, inputs up to 256 tokens), with the
result cache turned off (`RESULT_CACHE_TTL=0`): the test sends the same
few emails again and again, so with the cache on most answers come from
memory and the median says nothing about the model (4 ms in a first
run). Keep the cache off when measuring.

To find the saturation point, raise the offered load, for example
`-u 50 -r 5` and a shorter `wait_time`, and watch for p95 growth and
failures.

## Uptime alert

Point any external uptime monitor (UptimeRobot, Better Stack, Healthchecks...)
at `GET /health` every few minutes. It answers `{"status":"ok",...}` only
once the model is loaded, so a keyword check on `"status":"ok"` also
catches a server that is up but not ready.

## Result cache

Since v1.15.2 the backend keeps the result of `/analyse` and `/explain`
in memory for 24 hours, keyed by a SHA-256 of the request (the email
itself is not kept). A second scan of the same email, or "Why this
verdict?" clicked twice, answers at once with `"cached": true`. Results
where a check failed (DNS or reputation lookup) are not cached.

| Variable | Default | Meaning |
| --- | --- | --- |
| `RESULT_CACHE_TTL` | `86400` | Seconds an entry is kept; `0` turns the cache off |
| `RESULT_CACHE_MAX` | `2000` | Entries kept at most (oldest go first) |

Hit rate and size: `"result_cache"` in `/reputation/stats`. A redeploy
empties the cache.

## Backups

`scripts/backup.sh` (run on the server, weekly with cron) archives what
cannot be rebuilt from the repository or Hugging Face: the env file, the
Caddyfile, the data folder (SQLite files copied with SQLite's backup API)
and the web-server access logs. It uploads the archive to any
[rclone](https://rclone.org) remote (`PHISHLENS_BACKUP_REMOTE`, default
`phishlens-backup:`) and removes archives older than
`PHISHLENS_BACKUP_KEEP_DAYS` (default 60). Use an rclone **crypt** remote
so the archive, which contains the env file, is encrypted before it
leaves the server.

```bash
bash scripts/backup.sh          # back up now
bash scripts/backup.sh --list   # list the archives on the remote
```

Scan reviews (Right / Wrong) are stored in the browser, not on the
server: export them from the popup (Insights, JSON).
