# Operations

Running your own PhishLens server: deploy, configure, observe. The
examples use Docker behind a reverse proxy; adapt names and paths.

## Deploy or update

`scripts/redeploy.sh` does it in one command on a Docker host: pull
`origin/main`, build, restart, wait for `/health`, run a test scan, and
go back to the previous image if the new one is not healthy.

```bash
bash ~/PhishLens/scripts/redeploy.sh              # update and redeploy
bash ~/PhishLens/scripts/redeploy.sh --no-pull    # rebuild the current checkout
bash ~/PhishLens/scripts/redeploy.sh --rollback   # back to the previous image
```

By hand:

```bash
cd ~/PhishLens/backend
docker build -f Dockerfile.cloud -t phishlens .
docker rm -f phishlens            # "docker restart" would keep the old image
docker run -d --restart=always --env-file ~/.phishlens.env \
  -v ~/phishlens_data:/data \
  -v ~/phishlens_model:/home/user/app/model \
  -v ~/phishlens_agents:/home/user/app/agents \
  --name phishlens phishlens
docker logs -f phishlens          # wait for "Text model loaded from ..."
```

The model and agents volumes survive re-creating the container, so only
the first start downloads from Hugging Face (the container runs as uid
1000). `~/.phishlens.env` holds the keys and settings; never commit it.
Enable Docker at boot (`systemctl enable docker`) or the server stays
down after a reboot.

The website is static: `python3 scripts/build_site.py` (needs pandoc)
writes `site/` from `site-src/`; copy it to the web server.

## Switch the text model

```bash
# in ~/.phishlens.env
HF_MODEL_REPO=<owner>/<model>
HF_MODEL_REVISION=<commit sha>
HF_AGENTS_REVISION=<commit sha>
HF_TOKEN=hf_...                     # private repositories only
```

Pin both revisions: unset, the server takes whatever the repository
holds when it starts (and logs a warning), so anyone who can push to it
changes your model. The sha of the latest commit:

```bash
python3 -c "from huggingface_hub import HfApi; print(HfApi().model_info('<owner>/<model>').sha)"
```

Each repository and revision gets its own folder, so going back is
restoring the previous values. `curl -s <server>/health` shows the
repository, revision and settings in use. How the server reads a model:
[architecture.md](architecture.md#text-model).

A self-hosted server uses the English model by default
(`AnzouKiona/phishlens-distilbert`); it flags far more legitimate mail
than the multilingual one, which is private because part of its
training mail is. The extension warns about it.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GSB_API_KEY` | empty | Google Safe Browsing; that source is off without it |
| `REPUTATION_ENABLE_GSB` / `_PHISHTANK` / `_URLHAUS` / `_DBL` | `1` | Each threat-intel source |
| `GSB_MAX_PER_SCAN` | `30` | Links of one scan sent to Safe Browsing, one per host first; the daily quota is shared by every user |
| `PHISHTANK_API_KEY` / `PHISHTANK_REFRESH_S` | empty / 6 h | Without a key PhishTank allows few downloads a day; the last good feed is kept on disk and reused at start |
| `REPUTATION_CACHE_DB` | `~/.cache/phishlens/reputation.db` | URL verdicts, kept 24 h; put it in the data volume |
| `CRYPTO_LINK_RULE` | `1` | Flag a DKIM-signed sender whose links all lead elsewhere and whose wording looks like phishing |
| `METADATA_MODEL_ENABLED` | `0` | The trained header model; off because it flags most modern legitimate headers |
| `AGENTS_ALLOW_PICKLE` | `0` | `1` also loads pickle (joblib) agents, which run code when loaded; only for an old local copy never converted to skops |
| `RATE_LIMIT_ANALYSE` | `30/minute` | Per IP; also `RATE_LIMIT_ATTACHMENT`, `RATE_LIMIT_EXPLAIN`, `RATE_LIMIT_FEEDBACK` |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Read by uvicorn: the reverse proxy's address, whose `X-Forwarded-For` gives the client's. If the access log (`docker logs phishlens`) shows one private address for every request (Caddy's), set it to that address's Docker network (`172.18.0.0/16`: the container's address can change at restart), or the rate limits apply to all users together |
| `RESULT_CACHE_TTL` / `RESULT_CACHE_MAX` | `86400` / `2000` | Results kept in memory by request hash; `0` turns it off |
| `LIME_NUM_SAMPLES` | `100` | Model runs per explanation |
| `OCR_LANG` / `OCR_MAX_PAGES` / `OCR_TIMEOUT_S` | `auto` / `3` / `10` | [OCR](languages.md#ocr) |
| `FEEDBACK_DIR` | empty | Where user reports are kept; empty refuses them |
| `FEEDBACK_NOTIFY_URL` | empty | `https://` address told about each new report (an [ntfy](https://ntfy.sh) topic works); never the report's text |
| `METRICS_ENABLED` / `LOG_LEVEL` | `1` / `INFO` | Prometheus metrics on `/metrics`; log level |

The rest is in `backend/settings.py`.

## Observe

| Endpoint | Use |
| --- | --- |
| `GET /health` | Version, which agents run a model or rules, the text model and its revision; answers `"status":"ok"` only once the model is loaded, so an uptime monitor checking that keyword catches a server that is up but not ready |
| `GET /reputation/stats` | Cache hit rate, Safe Browsing quota left, PhishTank feed size (refreshed every 30 s) |
| `GET /metrics` | Prometheus: requests, latency, and `phishlens_verdicts_total{endpoint, verdict, trust_path}` |

Keep `/metrics` private: forward only the API paths from the proxy
(`/analyse*`, `/explain*`, `/health`, `/reputation*`, `/feedback`). The
number to watch is the share of phishing verdicts over time: a jump is
an attack wave or a regression, a drop to zero means something upstream
broke (a Gmail change, an extension bug).

Logs go to stdout (`docker logs phishlens`); email content is never
logged.

## Reports from users

With `FEEDBACK_DIR=/data/feedback`, reports are appended to
`feedback-YYYY-MM.jsonl`. They are private: back them up encrypted,
never commit them. To delete one on request:
`python3 scripts/delete_report.py --dir <folder> <reference>`.

## Load test

`scripts/locustfile.py` replays the extension's traffic (text scans
mostly, `.eml` and attachment scans). Run it against a throwaway
container with the rate limits lifted, threat intel off and the result
cache off (`RESULT_CACHE_TTL=0`): otherwise it measures the limiter, the
intel APIs or the cache. Never aim it at someone else's server.

```bash
docker run --rm --network host -v "$PWD":/mnt/locust locustio/locust \
  -f /mnt/locust/scripts/locustfile.py --host http://127.0.0.1:8001 \
  --headless -u 10 -r 2 -t 2m --csv /mnt/locust/loadtest --only-summary
```

PhishLens Cloud (4 ARM cores, CPU only, 10 users, multilingual model,
2026-10-15): median 65 ms and p95 120 ms for short text scans, 0
failures out of 472 requests. The test emails are short; a typical
email of about 250 tokens takes about 190 ms
([evaluation](evaluation.md#results)).

## Backups

`scripts/backup.sh` archives what the repository cannot rebuild (env
file, proxy configuration, data folder) to an [rclone](https://rclone.org)
remote. Use a crypt remote: the archive holds the env file.
