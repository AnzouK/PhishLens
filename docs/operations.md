# Operations guide

How to deploy, observe and load-test a PhishLens backend. The examples
match the reference deployment (Oracle Cloud ARM VM, Docker, Caddy in
front); adapt names and paths for your own host.

## Deploy or update

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
docker logs -f phishlens          # wait for "Model loaded on device=cpu"
```

The two extra volumes keep the DistilBERT checkpoint and the Random
Forest joblibs across container re-creations, so only the first boot
downloads them from Hugging Face. Create them once with
`mkdir -p ~/phishlens_model ~/phishlens_agents` (the container runs as
uid 1000, the same uid as the `opc` user). To pick up a new model
version published on Hugging Face, empty the folder
(`rm -rf ~/phishlens_model/*`) and re-create the container.

`~/.phishlens.env` holds the secrets and tuning knobs (`GSB_API_KEY`,
`REPUTATION_CACHE_DB=/data/reputation.db`, rate limits). It is never
committed. The landing page is static and deployed separately:
`rsync -avz --delete site/ <vm>:~/phishlens-site/`.

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

## Health and status endpoints

| Endpoint | Use |
| --- | --- |
| `GET /health` | Liveness. Also used by the extension as a warm-up ping. |
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
docker run -d --rm --name phishlens-load -p 127.0.0.1:8001:7860 \
  -v ~/phishlens_model:/home/user/app/model:ro \
  -e RATE_LIMIT_ANALYSE=100000/minute \
  -e RATE_LIMIT_ATTACHMENT=100000/minute \
  -e REPUTATION_ENABLE_GSB=0 -e REPUTATION_ENABLE_DBL=0 \
  -e REPUTATION_ENABLE_URLHAUS=0 -e REPUTATION_ENABLE_PHISHTANK=0 \
  phishlens
sleep 30                                   # model load (agents download)

# 2. Run the test from the repo root, with Locust in a container
cd ~/PhishLens
docker run --rm --network host -v "$PWD":/mnt/locust locustio/locust \
  -f /mnt/locust/scripts/locustfile.py --host http://127.0.0.1:8001 \
  --headless -u 10 -r 2 -t 2m --csv /mnt/locust/loadtest

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

Reading the 2026-09-29 run: 2 minutes, CPU inference in FP32, threat
intel switched off, live backend running on the same VM. Ten users with
a 1 to 4 second think time offer about 4 requests per second, and the
server kept up with zero failures and a p99 under 0.5 s, so this
measures latency under realistic load, not the saturation point. The
attachment median is low because the test page has no visible text, so
the text agent is skipped. In production, a cache miss on the URL
reputation cascade adds the network round-trip of the intel APIs on top
of these numbers; `/explain` (LIME) is excluded and is much slower.

To find the saturation point, raise the offered load, for example
`-u 50 -r 5` and a shorter `wait_time`, and watch for p95 growth and
failures.
