# Operations

PhishLens Cloud is set up as described in the first section. The rest
covers running your own server: deployment, configuration, logs and
metrics. The self-hosting examples use Docker behind a reverse proxy;
adapt the names and paths to your machine.

## PhishLens Cloud

- Cloudflare Pages serves the website (`site/`) at `phishlens.dev`.
- The Pages Function `functions/[[path]].js` is the API front. It
  forwards `/analyse`, `/analyse_attachment`, `/explain`, `/feedback`,
  `/health` and `/reputation/stats` to the backend. Every other path is
  a static file, and `/metrics` is never forwarded.
- `.github/workflows/backend-image.yml` builds `backend/Dockerfile.cloud`
  (linux/amd64) and publishes the public image
  `ghcr.io/anzouk/phishlens-backend`. It runs on a version tag (`v*`) or
  by hand ("Run workflow" in the Actions tab).
- The backend is the Cloud Run service `phishlens-backend` in
  `europe-west1` (Belgium). It runs
  `ghcr.io/anzouk/phishlens-backend:latest` pulled straight from ghcr.io,
  since the image is public and needs no registry in between.
- It gets 2 vCPU, 4 GiB of memory, startup CPU boost and the second
  generation execution environment. It scales from 0 to 1 instance,
  with 8 requests at a time per instance and a 120 s request timeout.
- Settings are environment variables of the service (below). Secrets
  live in Secret Manager: `gsb-api-key` (`GSB_API_KEY`), `hf-token`
  (`HF_TOKEN`), `feedback-notify-url` (`FEEDBACK_NOTIFY_URL`) and
  `proxy-secret` (`PROXY_SECRET`).
- The same `proxy-secret` value is the Pages secret `PROXY_SECRET`. The
  function sends it in `X-PhishLens-Proxy` and the backend answers 403
  to any request without it, so the Cloud Run address itself
  (`*.run.app`) answers nothing useful.
- The service runs under a dedicated service account. It can read only
  those four secrets, and it has `roles/storage.objectUser` on the
  reports bucket alone to list, read, create and delete its objects.
  The backend lists the reports to keep their total under
  `FEEDBACK_MAX_MB`.
- Reports go to `FEEDBACK_DIR=/feedback`, a private Cloud Storage bucket
  (`us-central1`, Standard class) mounted as a volume with Cloud Storage
  FUSE.
- A Cloud Scheduler job calls `https://phishlens.dev/health` every 10
  minutes to keep it warm. It goes through the function because the
  run.app address answers 403.
- Cloud Run has a monthly spending cap and a budget alert at 1 USD.

The service sets these environment variables besides the secrets:

```bash
METRICS_ENABLED=0                    # /metrics is never served, not even on the Cloud Run address
AGENTS_ALLOW_PICKLE=0
REPUTATION_CACHE_DB=/tmp/reputation.db
FEEDBACK_DIR=/feedback
FORWARDED_ALLOW_IPS=*                # Cloud Run's front end is the proxy
```

The function replaces any `X-Forwarded-For` sent by the client with the
address Cloudflare saw, so the per-address rate limits see the real
client. It never forwards `Cookie`, `Authorization` or a client-sent
`X-PhishLens-Proxy`, answers 405 to methods other than GET, HEAD, POST
and OPTIONS, and adds the security headers of `site/_headers` (which
Pages does not apply to a function's responses) to every answer. The
backend address is written in the function, and the Pages variable
`BACKEND_ORIGIN` overrides it. The extension and the website only ever call
`https://phishlens.dev`.

To change the proxy secret, add a new version of `proxy-secret`, put the
same value in Pages (`npx wrangler pages secret put PROXY_SECRET`), then
deploy a new Cloud Run revision. Until both sides match, phishlens.dev
answers 403.

At most one instance runs, so the rate limits, the Safe Browsing quota
counter and the result cache, all kept in memory, stay exact. They start
again empty when the instance restarts. The reputation cache lives in
`/tmp`, the instance's memory, and goes with it. Cloud Run can scale the
service to zero, but the Cloud Scheduler call to `/health` every 10 minutes
keeps the instance warm, so users rarely wait for it to start and load
the text model. Cloud Run bills only the time spent on requests, so these
calls cost almost nothing.

### Update the backend

```bash
# 1. publish the image: push a version tag, or run "Backend image" by hand
git tag v2.2.0 && git push origin v2.2.0
# 2. deploy it as a new revision
gcloud run deploy phishlens-backend --region europe-west1 \
  --image ghcr.io/anzouk/phishlens-backend:latest
# 3. check
curl -s https://phishlens.dev/health
```

A new revision pulls the image again, so deploying after each publish is
enough. To go back, send the traffic to the previous revision:

```bash
gcloud run revisions list --service phishlens-backend --region europe-west1
gcloud run services update-traffic phishlens-backend --region europe-west1 \
  --to-revisions <previous revision>=100
```

To change a key, add a new version of its secret
(`gcloud secrets versions add gsb-api-key --data-file=-`), then deploy a
new revision so the instance reads it. Logs go to Cloud Logging, and
`gcloud run services logs read phishlens-backend --region europe-west1`
shows them.

### Update the website

`python3 scripts/build_site.py` (needs pandoc) writes `site/` from
`site-src/`. Cloudflare Pages serves `site/` as it is, with the security
headers of `site/_headers`.

## Self-hosted server

### Deploy or update

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
1000). `~/.phishlens.env` holds the keys and settings, so never commit it.
Enable Docker at boot (`systemctl enable docker`) or the server stays
down after a reboot.

To serve the website yourself, build `site/` as above and copy it to
your web server.

## Switch the text model

```bash
# in ~/.phishlens.env (PhishLens Cloud: the service's environment variables)
HF_MODEL_REPO=<owner>/<model>
HF_MODEL_REVISION=<commit sha>
HF_AGENTS_REVISION=<commit sha>
HF_TOKEN=hf_...                     # private repositories only
```

Pin both revisions. When they are unset, the server takes whatever the
repository holds when it starts (and logs a warning), so anyone who can
push to it changes your model. To get the sha of the latest commit:

```bash
python3 -c "from huggingface_hub import HfApi; print(HfApi().model_info('<owner>/<model>').sha)"
```

Each repository and revision gets its own folder, so going back is
restoring the previous values. `curl -s <server>/health` shows the
repository, revision and settings in use. See
[architecture.md](architecture.md#text-model) for how the server reads a
model.

A self-hosted server uses the English model by default
(`AnzouKiona/phishlens-distilbert`). It flags far more legitimate mail
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
| `RATE_LIMIT_DEFAULT` | `60/minute` | Per IP, for the routes without a limit of their own (`/`, `/reputation/stats`); `/health` is never limited |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Read by uvicorn: the reverse proxy's address, whose `X-Forwarded-For` gives the client's. If the access log (`docker logs phishlens`) shows one private address for every request (the proxy's), set it to that address's Docker network (`172.18.0.0/16`: the container's address can change at restart), or the rate limits apply to all users together |
| `PROXY_SECRET` | empty | Shared with the reverse proxy (the phishlens.dev Pages Function); when set, a request without the header `X-PhishLens-Proxy` carrying it gets 403, `/health` included, so the host's own address cannot be called directly with a forged `X-Forwarded-For`. Leave it empty on a self-hosted server |
| `RESULT_CACHE_TTL` / `RESULT_CACHE_MAX` | `86400` / `2000` | Results kept in memory by request hash; `0` turns it off |
| `LIME_NUM_SAMPLES` | `100` | Model runs per explanation |
| `OCR_LANG` / `OCR_MAX_PAGES` / `OCR_TIMEOUT_S` | `auto` / `3` / `10` | [OCR](languages.md#ocr) |
| `FEEDBACK_DIR` | empty | Where user reports are kept; empty refuses them |
| `FEEDBACK_NOTIFY_URL` | empty | `https://` address told about each new report (an [ntfy](https://ntfy.sh) topic works); never the report's text |
| `METRICS_ENABLED` / `LOG_LEVEL` | `1` / `INFO` | Prometheus metrics on `/metrics`; log level |

The rest is in `backend/settings.py`.

## Observe

`GET /health` reports the version, which agents run a model or rules,
and the text model with its revision. It only answers `"status":"ok"`
once the model is loaded, so an uptime monitor that checks for that
keyword catches a server that is up but not ready.

`GET /reputation/stats` gives the cache hit rate, the Safe Browsing
quota left and the PhishTank feed size, refreshed every 30 s.

`GET /metrics` serves Prometheus metrics: requests, latency and
`phishlens_verdicts_total{endpoint, verdict, trust_path}`.

Keep `/metrics` private: forward only the API paths from the proxy
(`/analyse*`, `/explain*`, `/health`, `/reputation*`, `/feedback`), as
the Pages Function does for PhishLens Cloud, or turn it off with
`METRICS_ENABLED=0`, as PhishLens Cloud does so that its Cloud Run
address does not answer `/metrics` either. The number to watch is the
share of phishing verdicts over time. A jump means an attack wave or a
regression, and a drop to zero means something upstream broke (a Gmail
change, an extension bug).

Logs go to stdout (`docker logs phishlens`, Cloud Logging on PhishLens
Cloud). Email content is never logged.

## Reports from users

With `FEEDBACK_DIR=/data/feedback`, each report is its own file,
`YYYY-MM/<reference>.json`, created once and never rewritten. They are
private, so back them up encrypted and never commit them. To delete one
on request, run
`python3 scripts/delete_report.py --dir <folder> <reference>`.

On PhishLens Cloud the folder is the Cloud Storage bucket mounted at
`/feedback`. Delete a report by removing its object, which no report
received meanwhile can touch:

```bash
gcloud storage rm "gs://<bucket>/*/<reference>.json"
```

Reports received by older servers are lines of the monthly files
`feedback-YYYY-MM.jsonl`, which are still read and never written. To
delete one of those (legacy procedure): copy the month's file with
`gcloud storage cp`, delete the report in the local copy with the same
script, and copy the file back.

## Load test

`scripts/locustfile.py` replays the extension's traffic (text scans
mostly, `.eml` and attachment scans). Run it against a throwaway
container with the rate limits lifted, threat intel off and the result
cache off (`RESULT_CACHE_TTL=0`). Otherwise it measures the limiter, the
intel APIs or the cache. Never aim it at someone else's server.

```bash
docker run --rm --network host -v "$PWD":/mnt/locust locustio/locust \
  -f /mnt/locust/scripts/locustfile.py --host http://127.0.0.1:8001 \
  --headless -u 10 -r 2 -t 2m --csv /mnt/locust/loadtest --only-summary
```

On the earlier PhishLens Cloud host (4 ARM cores, CPU only, 10 users,
multilingual model, 2026-10-15), short text scans took a median of 65 ms
and a p95 of 120 ms, with 0 failures out of 472 requests. The test
emails are short. A typical email of about 250 tokens takes about 190 ms
([evaluation](evaluation.md#results)).

## Backups

On a self-hosted server, back up what the repository cannot rebuild.
That is the env file and the data folder, encrypted because the env
file holds the keys.

PhishLens Cloud has no such files. The code and the image are on GitHub,
the settings on the Cloud Run service, the keys in Secret Manager, and
the reports in their Cloud Storage bucket.
