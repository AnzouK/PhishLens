"""
Smart Phishing Detector: minimal FastAPI backend for the Chrome extension.

Exposes  POST /analyse  with the exact JSON contract the popup expects:

  request body:
    {"raw_email_b64": "<base64 of a .eml file>"}

  success response:
    {
      "verdict": "phishing" | "safe",
      "agents": {
        "text":     {"phishing_probability": 0..1, "verdict": "Phishing"|"Safe"},
        "url":      {"phishing_probability": 0..1, "verdict": "Phishing"|"Safe"},
        "metadata": {"phishing_probability": 0..1, "verdict": "Phishing"|"Safe"}
      }
    }
  error response:  {"detail": "..."}  (FastAPI standard HTTPException)

Run (from PhishingDetectorLocal/PhishingDetectorLocal/, with the venv active):
    pip install fastapi uvicorn      # already in this venv
    uvicorn extension_backend:app --host 127.0.0.1 --port 8000

Then load the extension in Chrome:
    chrome://extensions  ->  Developer mode  ->  Load unpacked
    ->  select  ".../extension/dist"
"""
from __future__ import annotations

import asyncio
import base64
import os
import re
from contextlib import asynccontextmanager
from email import message_from_bytes, policy
from email.utils import parseaddr
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from lime.lime_text import LimeTextExplainer
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

import logging
# Root config for the "phishlens.*" loggers. uvicorn configures its own
# loggers but leaves ours without a handler, which silently drops INFO.
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

# Sender authentication + Spamhaus DBL: real cryptographic signals to
# replace the static allowlist. Optional: if the module isn't present the
# backend still boots and the heuristic path takes over.
try:
    from auth_headers import build_metadata_auth_signal, parse_authentication_results
    _AUTH_HEADERS_AVAILABLE = True
except Exception as _e:
    _AUTH_HEADERS_AVAILABLE = False
    logger.warning(f"auth_headers module not loaded ({_e}); "
          "SPF/DKIM/DMARC + Spamhaus DBL disabled.")

# URL reputation cascade: GSB → PhishTank → URLhaus → Spamhaus DBL.
# Same graceful-fallback pattern as auth_headers: missing module → heuristics.
try:
    import reputation as _reputation
    _REPUTATION_AVAILABLE = True
except Exception as _e:
    _REPUTATION_AVAILABLE = False
    logger.warning(f"reputation module not loaded ({_e}); "
          "GSB / PhishTank / URLhaus disabled.")

# Email attachment analysis: PDF / HTML in v1.8 (Phase 1). DOCX/XLSX
# and image OCR + steg heuristics are planned for later phases.
try:
    import attachment_analysis as _attachments
    _ATTACHMENTS_AVAILABLE = True
except Exception as _e:
    _ATTACHMENTS_AVAILABLE = False
    logger.warning(f"attachment_analysis module not loaded ({_e}); "
          "the /analyse_attachment endpoint will 501.")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# MODEL_DIR is the unzipped DistilBERT checkpoint. Defaults to ./model
# next to this file; can be overridden via the MODEL_DIR env var (handy
# when running inside Docker where the model is mounted as a volume).
MODEL_DIR = Path(os.environ.get("MODEL_DIR", Path(__file__).parent / "model"))

# If the local MODEL_DIR is empty, the lifespan will try to fetch the
# checkpoint from this Hugging Face Hub repo. This is the path used by the
# HF Spaces deployment, where bundling the model in the image is wasteful.
HF_MODEL_REPO = os.environ.get("HF_MODEL_REPO", "AnzouKiona/phishlens-distilbert")

# Port the server should listen on. Local Docker uses 8000; HF Spaces inject
# their own PORT env var (typically 7860).
PORT = int(os.environ.get("PORT", "8000"))

MAX_LEN = 256                                   # match the training value
CLASS_NAMES = ["Safe", "Phishing"]

# fusion weights: kept identical to the academic document
W_TEXT, W_URL, W_META = 0.34, 0.33, 0.33
FUSION_THRESHOLD = 0.5
# Any single agent above this confidence forces the overall verdict to
# phishing, even if the weighted sum is below FUSION_THRESHOLD. Prevents
# the URL/metadata heuristics from diluting a confident DistilBERT call.
HIGH_CONF_OVERRIDE = 0.85

# ---------------------------------------------------------------------------
# Trusted sender allowlist.
# ---------------------------------------------------------------------------
# Corporate / institutional domains whose only legitimate senders are the
# organisation itself. When the sender's email domain matches one of these,
# the metadata agent reports a very low score, the text-agent weight in the
# fusion is reduced, and the high-confidence override is disabled, because
# DistilBERT's transactional-template wording often false-positives on real
# bank / hospital / telco / government messages.
#
# Personal email providers (gmail.com, yahoo.com, outlook.com, ...) are
# deliberately NOT in this set; they are used by phishers as much as by
# legitimate senders, so they carry no trust signal.
#
# REGION NOTE: the default list is Nigerian-centric because PhishLens is
# a Nile University project. If you fork this for a different region,
# extend the list with your local banks / telcos / gov domains: an
# empty allowlist is safe (the crypto path still runs), just less
# forgiving on legit transactional templates from those senders.
# Priority order at scan time:
#     trusted_sender  >  crypto_verified  >  gmail_inbox_soft  >  default
TRUSTED_DOMAINS = {
    # Nigerian banks
    "ubagroup.com", "gtbank.com", "gtco.com", "zenithbank.com",
    "accessbankplc.com", "firstbanknigeria.com", "sterlingbankng.com",
    "ecobank.com", "fcmb.com", "fbnholdings.com", "wemabank.com",
    "polarisbanklimited.com", "unionbankng.com", "stanbicibtcbank.com",
    # Nigerian telcos
    "mtnonline.com", "mtn.ng", "airtel.com", "airtel.com.ng",
    "9mobile.com.ng", "glo.com",
    # Nigerian payment processors / fintech
    "flutterwave.com", "paystack.com", "interswitchgroup.com",
    "kuda.com", "opay.com",
    # Nigerian gov / institutional
    "nimc.gov.ng", "firs.gov.ng", "frsc.gov.ng", "nile.edu.ng",
    "nileuniversity.edu.ng", "abu.edu.ng", "unilag.edu.ng",
    # Nigerian hospitals / health
    "nizamiye.ng", "lasuth.ng", "uithniseason.org",
    # International tech (where their support / billing actually comes from)
    "google.com", "googlemail.com",
    "microsoft.com", "outlook.office365.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "amazonpay.com",
    "paypal.com", "stripe.com",
    "github.com", "gitlab.com",
    "linkedin.com", "facebook.com", "facebookmail.com",
    "twitter.com", "x.com",
    "anthropic.com",
}


def _sender_domain(value: str) -> str | None:
    """Extract the domain from a string that may be a bare address or a
    'Name <addr@domain>' header. Returns None on failure."""
    if not value:
        return None
    m = re.search(r"@([A-Za-z0-9.\-_]+)", value)
    if not m:
        return None
    d = m.group(1).lower().rstrip(".")
    return d or None


def is_trusted_domain(domain: str | None) -> bool:
    if not domain:
        return False
    d = domain.lower()
    if d in TRUSTED_DOMAINS:
        return True
    # also match any subdomain of a trusted domain
    for td in TRUSTED_DOMAINS:
        if d.endswith("." + td):
            return True
    return False


# ---------------------------------------------------------------------------
# Model loading (lifespan)
# ---------------------------------------------------------------------------
STATE: dict[str, Any] = {}


def _pick_device() -> str:
    """Prefer Apple Silicon GPU (MPS), then CUDA, fall back to CPU."""
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


def _ensure_model_available() -> Path:
    """Resolve where to load the model from.

    Strategy:
      1. If MODEL_DIR exists and looks complete, use it.
      2. Else, try to download HF_MODEL_REPO from the Hub into MODEL_DIR.
      3. If both fail, raise a clear error.
    """
    must_have = {"config.json", "tokenizer_config.json"}
    if MODEL_DIR.exists() and must_have.issubset({p.name for p in MODEL_DIR.iterdir()}):
        return MODEL_DIR

    logger.info(f"Local model not found at {MODEL_DIR}: falling back to "
          f"Hugging Face Hub repo {HF_MODEL_REPO!r}.")
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise RuntimeError(
            "Local model directory is empty and the huggingface_hub library "
            "is not installed. Either populate MODEL_DIR with the DistilBERT "
            "checkpoint, or `pip install huggingface_hub` and retry."
        ) from e
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=HF_MODEL_REPO,
        local_dir=str(MODEL_DIR),
        local_dir_use_symlinks=False,
    )
    logger.info(f"Downloaded {HF_MODEL_REPO} -> {MODEL_DIR}")
    return MODEL_DIR


@asynccontextmanager
async def lifespan(_app: FastAPI):
    model_dir = _ensure_model_available()
    logger.info(f"Loading DistilBERT from {model_dir} ...")
    device = _pick_device()
    tok = AutoTokenizer.from_pretrained(str(model_dir))
    # FP32 loading: CPUs don't have great FP16 support and inference is ~2×
    # slower in FP16 on typical CPU targets. With a ~256MB footprint this
    # fits comfortably in any host that can run a Docker container, so we
    # prefer the speed. Set MODEL_DTYPE=float16 in the env to opt into FP16
    # on RAM-constrained hosts (~128MB with a small precision loss).
    _dtype = torch.float16 if os.environ.get("MODEL_DTYPE") == "float16" else torch.float32
    model = AutoModelForSequenceClassification.from_pretrained(
        str(model_dir), torch_dtype=_dtype
    )
    model.to(device).eval()
    STATE["tokenizer"] = tok
    STATE["model"] = model
    STATE["device"] = device
    STATE["lime"] = LimeTextExplainer(class_names=CLASS_NAMES, bow=False)
    logger.info(f"Model loaded on device={device}. Ready on port {PORT}.")

    # Start the reputation cascade (PhishTank feed download, cache warm-up).
    # Runs after model load so a slow PhishTank fetch doesn't block startup
    # health checks: the model is already serving by then.
    if _REPUTATION_AVAILABLE:
        try:
            await _reputation.startup()
        except Exception as _e:
            logger.warning(f"reputation.startup() failed: {_e}")

    yield

    if _REPUTATION_AVAILABLE:
        try:
            await _reputation.shutdown()
        except Exception:
            pass
    STATE.clear()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Smart Phishing Detector: extension backend",
              lifespan=lifespan)

# Chrome extensions have origin chrome-extension://<id>. The PhishLens Cloud
# is a shared open backend, so we allow any origin: self-hosted deploys
# should tighten this via CORS_ALLOW_ORIGINS if they don't need it open.
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Rate limiting (v1.9+): protects the public backend from abuse. The
# heavy endpoints (/analyse, /explain, /analyse_attachment) are limited
# to a few dozen requests per minute per client IP. /health and
# /reputation/stats are cheap and left unlimited so uptime probes and
# the landing page don't get throttled.
#
# Uses slowapi (in-memory bucket by default; set SLOWAPI_STORAGE_URI to
# a Redis URL when horizontally scaling). Gracefully degrades to a
# no-op if slowapi isn't installed (dev / older venvs).
# ---------------------------------------------------------------------------
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    from slowapi.util import get_remote_address

    _limiter = Limiter(
        key_func=get_remote_address,
        default_limits=[os.environ.get("RATE_LIMIT_DEFAULT", "60/minute")],
        storage_uri=os.environ.get("SLOWAPI_STORAGE_URI", "memory://"),
    )
    app.state.limiter = _limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    RATE_LIMIT_ANALYSE    = os.environ.get("RATE_LIMIT_ANALYSE",    "30/minute")
    RATE_LIMIT_ATTACHMENT = os.environ.get("RATE_LIMIT_ATTACHMENT", "20/minute")
    RATE_LIMIT_EXPLAIN    = os.environ.get("RATE_LIMIT_EXPLAIN",    "15/minute")
    _RATE_LIMIT_OK = True
except Exception as _e:
    logger.warning(f"slowapi not available ({_e}); rate limiting disabled.")
    _limiter = None
    _RATE_LIMIT_OK = False
    def _noop_decorator(*_a, **_k):
        def _wrap(fn): return fn
        return _wrap
    RATE_LIMIT_ANALYSE = RATE_LIMIT_ATTACHMENT = RATE_LIMIT_EXPLAIN = None


# ---------------------------------------------------------------------------
# Observability (v1.10+): Prometheus metrics on GET /metrics.
# ---------------------------------------------------------------------------
# prometheus-fastapi-instrumentator adds the standard HTTP metrics
# (request count, latency histogram, in-flight requests) per handler.
# On top of that we count final verdicts per endpoint and trust path,
# which is the number that actually matters for a detector: a sudden
# swing in the phishing ratio means either an attack wave or a model
# regression.
#
# Set METRICS_ENABLED=0 to turn it off. On a public deployment, block
# /metrics at the reverse proxy (see docs/operations.md); the numbers
# are not secret but there is no reason to publish them.
# Degrades to a no-op if the package is not installed.
# ---------------------------------------------------------------------------
_VERDICTS = None
if os.environ.get("METRICS_ENABLED", "1") != "0":
    try:
        from prometheus_client import Counter
        from prometheus_fastapi_instrumentator import Instrumentator

        Instrumentator(
            excluded_handlers=["/metrics", "/health"],
        ).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
        _VERDICTS = Counter(
            "phishlens_verdicts_total",
            "Final verdicts returned by the scoring endpoints.",
            ["endpoint", "verdict", "trust_path"],
        )
    except Exception as _e:
        logger.warning(f"Prometheus metrics disabled ({_e}).")


def _count_verdict(endpoint: str, is_phishing: bool, trust_path: str) -> None:
    if _VERDICTS is None:
        return
    try:
        _VERDICTS.labels(endpoint, "phishing" if is_phishing else "safe", trust_path).inc()
    except Exception:
        pass


class AnalyseRequest(BaseModel):
    """Either raw_email_b64 (a base64-encoded .eml file) or raw_text
    (plain-text email body) must be provided.

    The optional sender_email lets the caller (e.g. the Gmail content
    script) supply the sender address explicitly, even when raw_text is
    used and the full headers are not available.

    client_context carries best-effort signals the extension can extract
    from the surrounding UI when the raw headers aren't available. For
    Gmail this includes the visible "mailed-by" / "signed-by" values and
    whether the message is in Inbox (Gmail already ran SPF/DKIM/DMARC on
    every delivered message; surfacing that avoids a false-positive gap
    between raw_email_b64 scans (full headers) and raw_text scans
    (body only)). Structure is intentionally loose (dict) so we can add new
    hints without a breaking API bump.
    """
    raw_email_b64: str | None = None
    raw_text: str | None = None
    sender_email: str | None = None
    client_context: dict[str, Any] | None = None


class AttachmentRequest(BaseModel):
    """
    Payload for POST /analyse_attachment (v1.8+).

    content_b64 : base64-encoded attachment bytes, 10 MB hard cap
    filename    : original filename (only used for MIME sniffing and UX)
    mime_type   : client hint, not trusted (we sniff for real)
    parent_email: optional context: {sender_email, subject} of the mail
                   the attachment came from. Not required for /analyse_attachment
                   to work, but nice to attach in the response for the UI.
    """
    content_b64:  str
    filename:     str | None = None
    mime_type:    str | None = None
    parent_email: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Email parsing
# ---------------------------------------------------------------------------
def html_to_text(html_src: str) -> str:
    """Visible text of an HTML email body, like the text Gmail shows.

    <style>, <script> and <head> contents are dropped: a plain tag strip
    kept the CSS ("25px", "roboto", "heading"...) and the text model read
    it as words. BeautifulSoup when installed (it is in requirements.txt),
    a linear find-based fallback otherwise.
    """
    html_src = html_src[:1_000_000]
    try:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html_src, "html.parser")
        for tag in soup(["style", "script", "head", "noscript", "title"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
    except Exception:
        low = html_src.lower()
        out, i = [], 0
        while True:
            j = min([k for k in (low.find("<style", i), low.find("<script", i)) if k >= 0], default=-1)
            if j < 0:
                out.append(html_src[i:])
                break
            out.append(html_src[i:j])
            end_tag = "</style>" if low.startswith("<style", j) else "</script>"
            k = low.find(end_tag, j)
            if k < 0:
                break
            i = k + len(end_tag)
        stripped, depth = [], 0
        for ch in "".join(out):
            if ch == "<":
                depth = 1
                stripped.append(" ")
            elif ch == ">" and depth:
                depth = 0
            elif not depth:
                stripped.append(ch)
        text = "".join(stripped)
        import html as _html
        text = _html.unescape(text)
    # Collapse whitespace line by line (no regex: linear on any input).
    lines = (" ".join(line.split()) for line in text.splitlines())
    return "\n".join(line for line in lines if line)


# href="https://..." in an HTML part. Bounded class, no nested
# quantifiers: linear on any input.
_HREF_RE = re.compile(r"""href=["'](https?://[^"'\s<>]{1,2048})""", re.IGNORECASE)


def parse_eml(raw_bytes: bytes) -> tuple[str, list[str], dict[str, str]]:
    """Return (body_text, urls_list, headers_dict)."""
    msg = message_from_bytes(raw_bytes, policy=policy.default)
    # body text
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    body = part.get_content()
                    break
                except Exception:
                    pass
        if not body:
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        body = html_to_text(part.get_content())
                        break
                    except Exception:
                        pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = raw_bytes.decode("utf-8", errors="ignore")
    # urls: from the text, then the real link targets of the HTML part
    # (an HTML email shows "Click here", the address is in the href).
    urls = re.findall(r"https?://[^\s\"'<>)]+", body)
    for part in (msg.walk() if msg.is_multipart() else [msg]):
        if part.get_content_type() != "text/html":
            continue
        try:
            html_src = part.get_content()
        except Exception:
            continue
        for m in _HREF_RE.finditer(html_src[:500_000]):
            u = m.group(1)
            if u not in urls:
                urls.append(u)
            if len(urls) >= 200:
                break
    # headers (subset)
    headers = {k.lower(): str(v) for k, v in msg.items()}
    return body.strip(), urls, headers


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------
def predict_proba_batch(texts: list[str]) -> np.ndarray:
    """Return Nx2 array of [P(Safe), P(Phishing)]: needed by LIME."""
    tok = STATE["tokenizer"]
    model = STATE["model"]
    device = STATE["device"]
    inputs = tok(list(texts), truncation=True, max_length=MAX_LEN,
                 padding=True, return_tensors="pt")
    inputs.pop("token_type_ids", None)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        logits = model(**inputs).logits
    return F.softmax(logits, dim=-1).cpu().numpy()


def text_agent(body: str) -> float:
    """DistilBERT phishing probability for the email body."""
    return float(predict_proba_batch([body or ""])[0, 1])


SUSPICIOUS_TLDS = {"zip", "review", "click", "country", "kim", "cricket",
                   "science", "work", "party", "gq", "tk", "ml", "ga", "cf"}


# ---------------------------------------------------------------------------
# Trained URL & metadata agents.
# ---------------------------------------------------------------------------
# The heuristic agents further down are always available as a safety net.
# On top of that, the backend can load the trained Random Forest agents
# from a Hugging Face model repo (default: AnzouKiona/phishlens-agents),
# or from local files pointed at by the URL_AGENT_PATH / METADATA_AGENT_PATH
# env vars.
#
# The upstream training pipeline lives at
# https://github.com/AnzouK/PhishingDetector: the URLAgent and
# MetadataAgent classes ship in this folder (copied verbatim from the
# training repo) so we can load their pickled state directly.
HF_AGENTS_REPO = os.environ.get("HF_AGENTS_REPO", "AnzouKiona/phishlens-agents")
_URL_AGENT       = None
_METADATA_AGENT  = None
_FEATURE_EXTRACT = None

# v1.12: agents are published in the skops format and loaded with a
# type allowlist (agent_io.py), so a tampered file cannot run code. The
# old joblib (pickle) files are only used as a fallback while the skops
# files are not published yet; set AGENTS_ALLOW_PICKLE=0 to refuse them.
AGENTS_ALLOW_PICKLE = os.environ.get("AGENTS_ALLOW_PICKLE", "1") != "0"


def _hf_fetch(filename: str) -> Path | None:
    try:
        from huggingface_hub import hf_hub_download
        return Path(hf_hub_download(
            repo_id=HF_AGENTS_REPO, filename=filename,
            repo_type="model", local_dir="./agents",
        ))
    except Exception as e:
        logger.info(f"{filename} not fetched from {HF_AGENTS_REPO}: {e}")
        return None


def _resolve_agent_file(stem: str, env_var: str) -> Path | None:
    """Local override first, then <stem>.skops, then <stem>.joblib."""
    local = os.environ.get(env_var)
    if local and Path(local).exists():
        return Path(local)
    path = _hf_fetch(f"{stem}.skops")
    if path:
        return path
    if AGENTS_ALLOW_PICKLE:
        path = _hf_fetch(f"{stem}.joblib")
        if path:
            logger.warning(
                f"Loading {path.name} with pickle: publish {stem}.skops "
                "(convert_agents_to_skops.py) and set AGENTS_ALLOW_PICKLE=0."
            )
        return path
    return None


def _load_agent(agent, path: Path):
    if path.suffix == ".skops":
        import agent_io  # noqa: E402
        return agent_io.apply_state(agent, agent_io.load_skops_state(path))
    if not AGENTS_ALLOW_PICKLE:
        raise RuntimeError(f"{path.name} is a pickle file and AGENTS_ALLOW_PICKLE=0")
    agent.load_model(str(path))
    return agent


def _init_agent(stem: str, env_var: str, factory):
    """Load one trained agent; any failure leaves the heuristic in place."""
    try:
        path = _resolve_agent_file(stem, env_var)
        if not path:
            return None
        agent = _load_agent(factory(), path)
        logger.info(f"Loaded trained {stem} from {path}")
        return agent
    except Exception as e:
        logger.warning(f"Could not load {stem}, using the heuristic instead: {e}")
        return None


try:
    # Feature extractor (always available: trained agents need it).
    from feature_extraction import FeatureExtractor  # noqa: E402
    _FEATURE_EXTRACT = FeatureExtractor()

    def _url_factory():
        from url_agent import URLAgent  # noqa: E402
        return URLAgent()

    def _meta_factory():
        from metadata_agent import MetadataAgent  # noqa: E402
        return MetadataAgent()

    _URL_AGENT = _init_agent("url_agent", "URL_AGENT_PATH", _url_factory)
    _METADATA_AGENT = _init_agent("metadata_agent", "METADATA_AGENT_PATH", _meta_factory)
    if not _URL_AGENT and not _METADATA_AGENT:
        logger.info("No trained agents loaded: using heuristic fallbacks.")
except Exception as e:
    logger.warning(f"Feature extractor init failed, falling back to heuristics: {e}")


def url_agent(urls: list[str], body_text: str = "") -> float:
    """URL score: trained RF on the full body text when available,
    heuristic on the extracted URL list otherwise."""
    # No links, no URL risk. Checked before the trained path on purpose:
    # the Random Forest was trained on emails that carry URLs, and on an
    # all-zero feature vector it outputs a high phishing probability,
    # which fired the single-agent override on plain link-free text.
    if not urls:
        return 0.05
    if _URL_AGENT is not None and _FEATURE_EXTRACT is not None and body_text:
        try:
            # The trained features are extracted from text, so URLs that
            # are not in the visible text (Gmail link targets, QR codes)
            # are appended to it; otherwise the RF would never see them.
            missing = [u for u in urls if u not in body_text]
            text = body_text + ("\n" + "\n".join(missing) if missing else "")
            feats = _FEATURE_EXTRACT.extract_url_features(text)
            pred  = _URL_AGENT.get_prediction_with_confidence(feats)
            return float(pred["phishing_probability"])
        except Exception as e:
            logger.warning(f"url_agent trained path failed ({e}); falling back to heuristic")
    if not urls:
        return 0.05  # almost no risk with no URLs
    bad = 0.0
    for u in urls:
        score = 0.0
        if u.startswith("http://"):                              score += 0.25
        if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", u):       score += 0.40
        if "@" in u.split("://", 1)[-1]:                         score += 0.35
        if len(u) > 75:                                          score += 0.15
        tld = u.rstrip("/").rsplit(".", 1)[-1].split("/")[0].lower()
        if tld in SUSPICIOUS_TLDS:                               score += 0.30
        if re.search(r"(login|verify|account|update|secure)", u, re.I): score += 0.10
        bad = max(bad, min(score, 1.0))
    return bad


def metadata_agent(headers: dict[str, str], raw_email: bytes | None = None) -> float:
    """Metadata score: trained RF on the raw email when available,
    heuristic on the parsed header dict otherwise."""
    if _METADATA_AGENT is not None and _FEATURE_EXTRACT is not None and raw_email:
        try:
            feats = _FEATURE_EXTRACT.extract_metadata_features(raw_email)
            pred  = _METADATA_AGENT.get_prediction_with_confidence(feats)
            return float(pred["phishing_probability"])
        except Exception as e:
            logger.warning(f"metadata_agent trained path failed ({e}); falling back to heuristic")
    score = 0.0
    sender = headers.get("from", "").lower()
    reply_to = headers.get("reply-to", "").lower()
    # Reply-To differs from From
    def domain(addr: str) -> str:
        m = re.search(r"@([^>\s]+)", addr)
        return m.group(1).lower() if m else ""
    if reply_to and domain(reply_to) and domain(reply_to) != domain(sender):
        score += 0.45
    # No DKIM / SPF / Authentication-Results
    auth = headers.get("authentication-results", "")
    if "dkim=fail" in auth or "spf=fail" in auth:
        score += 0.40
    if "authentication-results" not in headers:
        score += 0.15
    # Display name impersonation: 'PayPal' from a non-paypal address.
    # Use stdlib email.utils.parseaddr instead of a regex so we can't
    # be hit by ReDoS on a crafted From: header. Header is sliced to
    # 400 chars first as a belt-and-braces cap.
    display_name, _addr = parseaddr(headers.get("from", "")[:400])
    display = display_name.lower()[:200]
    if display:
        for brand in ("paypal", "apple", "google", "microsoft", "amazon", "facebook"):
            if brand in display and brand not in domain(sender):
                score += 0.35
                break
    return min(score, 1.0)


# ---------------------------------------------------------------------------
# /analyse endpoint
# ---------------------------------------------------------------------------
def verdict_label(p: float, threshold: float = 0.5) -> str:
    return "Phishing" if p >= threshold else "Safe"


@app.get("/")
def root():
    return {"status": "ok", "model": "DistilBERT",
            "endpoints": ["/analyse", "/explain", "/health"]}


@app.get("/health")
def health():
    """Lightweight liveness probe. Used by the extension to warm the container
    so users don't hit a cold-start on their first scan."""
    return {"status": "ok", "model": "DistilBERT"}


@app.get("/reputation/stats")
def reputation_stats():
    """
    Debug endpoint: cache hit rate, GSB quota consumption, PhishTank feed
    size. Handy for monitoring how close we get to the 10k/day GSB limit
    and whether the cache is doing its job. Not exposed to end users.
    """
    if not _REPUTATION_AVAILABLE:
        return {"enabled": False, "reason": "reputation module not loaded"}
    return {"enabled": True, **_reputation.stats()}


@app.post("/explain")
@(_limiter.limit(RATE_LIMIT_EXPLAIN) if _RATE_LIMIT_OK else (lambda f: f))
def explain(request: Request, req: AnalyseRequest):
    """Top-K LIME tokens explaining the text-agent decision."""
    body, _, _, _ = _get_body_urls_headers(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")

    lime = STATE["lime"]
    try:
        # Cap body length: LIME runs num_samples forward passes, so a shorter
        # body shaves off real wall-time. 100 samples give explanations that
        # are qualitatively identical to 200 while halving latency
        # (~8s vs ~15s per explanation on a CPU-only host).
        body_short = body[:800]
        exp = lime.explain_instance(
            body_short, predict_proba_batch,
            num_samples=int(os.environ.get("LIME_NUM_SAMPLES", "100")),
            num_features=12,
            labels=(1,),     # explain in the Phishing direction
        )
        # Build the feature list. We keep tokens whose absolute weight is
        # meaningful, but we ALWAYS guarantee at least 5 tokens so the user
        # never sees an empty 'Why?' panel, even when DistilBERT is so
        # confident that LIME spreads contributions thinly across many words.
        all_feats = []
        for word, w in exp.as_list(label=1):
            all_feats.append({
                "token": word,
                "weight": float(w),
                "supports": "phishing" if w > 0 else "safe",
                "abs_weight": abs(float(w)),
            })
        all_feats.sort(key=lambda f: f["abs_weight"], reverse=True)
        strong = [f for f in all_feats if f["abs_weight"] >= 0.003]
        feats = strong if len(strong) >= 5 else all_feats[:8]
        for f in feats:
            f.pop("abs_weight", None)
    except Exception as e:
        raise HTTPException(500, f"LIME failed: {e}")

    return {"features": feats}


def _synthesize_auth_results(ctx: dict, sender_email: str | None) -> str:
    """
    Build a synthetic Authentication-Results header from Gmail DOM signals.

    Gmail scans expose "mailed-by" (SPF-authenticated identity) and
    "signed-by" (DKIM-signing domain) in the DOM. When the extension's
    Gmail content script scrapes those and passes them to us in
    client_context, we forge a header that looks like what a real MTA
    would produce. parse_authentication_results() then handles it the
    same way it handles a real one, and the alignment check makes sure
    a spoofed "signed-by" that doesn't align with From: is still caught.

    Returns "" when there's not enough signal to synthesize anything.
    """
    if not isinstance(ctx, dict):
        return ""
    if ctx.get("origin") != "gmail":
        return ""

    signed_by = (ctx.get("gmail_signed_by") or "").strip().lower()
    mailed_by = (ctx.get("gmail_mailed_by") or "").strip().lower()
    via       = (ctx.get("gmail_via")       or "").strip().lower()
    in_inbox  = bool(ctx.get("gmail_in_inbox"))

    if not (signed_by or mailed_by or via):
        return ""

    # From: domain: used by parse_authentication_results to check alignment.
    from_addr = (sender_email or "").strip()
    m = re.search(r"@([^>\s,]+)", from_addr)
    from_domain = m.group(1).lower() if m else ""

    parts = ["gmail-client-context;"]
    if signed_by:
        parts.append(f"dkim=pass header.i=@{signed_by}")
    if mailed_by or via:
        spf_domain = mailed_by or via
        parts.append(f"spf=pass smtp.mailfrom={spf_domain}")
    # DMARC pass only when the signed-by aligns with From: at the org level.
    if signed_by and from_domain:
        # cheap org-domain compare: mirrors auth_headers._org_domain
        def _od(d):
            ps = d.split(".")
            return ".".join(ps[-2:]) if len(ps) >= 2 else d
        if _od(signed_by) == _od(from_domain):
            parts.append(f"dmarc=pass header.from={from_domain}")

    return " ".join(parts)


MAX_LINK_URLS = 50

# Below this many words the text agent has nothing meaningful to read
# (image-only emails, a bare link). Its score is then left out of the
# fusion and the verdict rests on the links and the sender.
MIN_TEXT_WORDS = 3

# ---------------------------------------------------------------------
# Forwarded emails (v1.14). The From: of a forwarded email is the person
# who forwarded it, not the author of the content, so the sender-trust
# discounts (allowlist, DKIM, Gmail inbox) must not apply to the content.
# ---------------------------------------------------------------------
_FORWARD_MARKERS = re.compile(
    r"^[ \t]*(?:-{2,}[ \t]*(?:forwarded message|original message|message transf[ée]r[ée]|"
    r"message d'origine|mensaje reenviado|mensaje original)[ \t]*-{2,}"
    r"|begin forwarded message\s*:"
    r"|d[ée]but du message (?:r[ée]exp[ée]di[ée]|transf[ée]r[ée])\s*:)",
    re.IGNORECASE | re.MULTILINE,
)
_FORWARD_SUBJECT = re.compile(r"^\s*(?:fwd?|tr|wg|rv|enc)\s*:", re.IGNORECASE)
_FORWARD_FROM_KEYS = ("from", "de", "von")


def _forwarded_sender(tail: str) -> str | None:
    """First "From:" / "De :" line of the forwarded block, parsed without a
    regex (CodeQL flagged the regex versions as polynomial on crafted
    input). Only the first 40 lines and 300 characters per line are read."""
    for line in tail.splitlines()[:40]:
        key, sep, value = line[:300].partition(":")
        if sep and key.strip().lower() in _FORWARD_FROM_KEYS:
            _name, addr = parseaddr(value.strip())
            if "@" in addr and " " not in addr and "." in addr.rsplit("@", 1)[-1]:
                return addr.lower()
            return None
    return None


def detect_forwarded(body: str, subject: str | None = None) -> dict[str, Any]:
    """Return {"detected": bool, "original_sender": str | None}.

    A forward marker in the body is required when there is one; the
    subject prefix (Fwd:, TR:, ...) alone also counts, since mail clients
    that inline the forwarded text do not always add a marker line.
    """
    body = body or ""
    m = _FORWARD_MARKERS.search(body)
    detected = bool(m) or bool(subject and _FORWARD_SUBJECT.match(subject))
    original = None
    if detected:
        tail = body[m.end():] if m else body
        original = _forwarded_sender(tail[:5000])
    return {"detected": detected, "original_sender": original}


# ---------------------------------------------------------------------
# Links to file-sharing and form services (v1.14). The domain is
# legitimate (Google, Microsoft, Dropbox), so the URL agent and threat
# intel rarely flag it, but the shared file or form is often the lure.
# Informational: surfaced to the user, not added to the score.
# ---------------------------------------------------------------------
_SHARE_SERVICES = [
    (re.compile(r"(?:^|\.)docs\.google\.com$"), r"^/forms/", "Google Forms"),
    (re.compile(r"(?:^|\.)forms\.gle$"), None, "Google Forms"),
    (re.compile(r"(?:^|\.)drive\.google\.com$"), None, "Google Drive"),
    (re.compile(r"(?:^|\.)docs\.google\.com$"), None, "Google Docs"),
    (re.compile(r"(?:^|\.)(?:firebasestorage|storage)\.googleapis\.com$"), None, "Google Cloud Storage"),
    (re.compile(r"(?:^|\.)(?:1drv\.ms|onedrive\.live\.com)$"), None, "OneDrive"),
    (re.compile(r"(?:^|\.)sharepoint\.com$"), None, "SharePoint"),
    (re.compile(r"(?:^|\.)forms\.(?:office|microsoft)\.com$"), None, "Microsoft Forms"),
    (re.compile(r"(?:^|\.)(?:dropbox\.com|dropboxusercontent\.com|db\.tt)$"), None, "Dropbox"),
    (re.compile(r"(?:^|\.)(?:wetransfer\.com|we\.tl)$"), None, "WeTransfer"),
    (re.compile(r"(?:^|\.)box\.com$"), None, "Box"),
    (re.compile(r"(?:^|\.)mega\.nz$"), None, "MEGA"),
    (re.compile(r"(?:^|\.)mediafire\.com$"), None, "MediaFire"),
    (re.compile(r"(?:^|\.)docsend\.com$"), None, "DocSend"),
    (re.compile(r"(?:^|\.)icloud\.com$"), r"^/iclouddrive/", "iCloud Drive"),
]


def detect_shared_links(urls: list[str]) -> dict[str, Any]:
    """Return {"count": int, "services": [names], "urls": [first 10]}."""
    from urllib.parse import urlsplit
    services: list[str] = []
    hits: list[str] = []
    for u in urls:
        try:
            parts = urlsplit(u)
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        for host_re, path_re, name in _SHARE_SERVICES:
            if host_re.search(host) and (path_re is None or re.match(path_re, parts.path or "/")):
                hits.append(u)
                if name not in services:
                    services.append(name)
                break
    return {"count": len(hits), "services": services, "urls": hits[:10]}


def _merge_link_urls(urls: list[str], extra: Any) -> list[str]:
    """Add client-supplied link targets to the URLs found in the text.

    Untrusted input: only http(s) strings under 2048 characters are kept,
    at most MAX_LINK_URLS of them, and duplicates are dropped (order kept).
    """
    out = list(dict.fromkeys(urls))
    if not isinstance(extra, list):
        return out
    seen = set(out)
    for u in extra:
        if len(out) >= MAX_LINK_URLS:
            break
        if not isinstance(u, str) or len(u) > 2048:
            continue
        u = u.strip()
        if not re.match(r"https?://", u, re.I) or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def _get_body_urls_headers(req: AnalyseRequest):
    """Resolve the request into (body, urls, headers, raw_bytes).

    Either raw_email_b64 (full EML) or raw_text (plain body) must be present.
    sender_email, when provided, is injected into headers['from'] so the
    rest of the pipeline can use it uniformly. raw_bytes is the raw EML
    bytes when available (needed by the trained metadata agent), None when
    only raw_text was supplied.
    """
    if req.raw_text:
        body = req.raw_text.strip()
        urls = re.findall(r"https?://[^\s\"'<>)]+", body)
        # The visible text of an HTML email hides where its links go
        # ("Click here"). The Gmail extension sends the real href targets
        # in client_context.link_urls so the URL agent and the threat-intel
        # cascade see them too.
        urls = _merge_link_urls(urls, (req.client_context or {}).get("link_urls"))
        headers: dict[str, str] = {}
        if req.sender_email:
            headers["from"] = req.sender_email
        # Synthesize an Authentication-Results header from the extension's
        # client_context when we have one. Rationale: Gmail already ran
        # SPF/DKIM/DMARC on every delivered message and exposes the results
        # in the DOM ("mailed-by:" / "signed-by:"). If the signed-by domain
        # aligns with the From: domain we treat it as DKIM=pass, which lets
        # the /analyse crypto_verified path apply the same discount as
        # raw_email_b64 scans of the same message.
        ctx = req.client_context or {}
        synth = _synthesize_auth_results(ctx, req.sender_email)
        if synth:
            headers["authentication-results"] = synth
        return body, urls, headers, None
    if not req.raw_email_b64:
        raise HTTPException(400, "Provide either raw_email_b64 or raw_text.")
    try:
        raw_bytes = base64.b64decode(req.raw_email_b64)
    except Exception as e:
        raise HTTPException(400, f"Could not decode base64: {e}")
    try:
        body, urls, headers = parse_eml(raw_bytes)
    except Exception as e:
        raise HTTPException(400, f"Could not parse EML: {e}")
    # let sender_email override the parsed From if explicitly given
    if req.sender_email:
        headers["from"] = req.sender_email
    # v1.15: the Gmail extension sends the full original message ("Show
    # original") together with the link targets it saw in the page.
    urls = _merge_link_urls(urls, (req.client_context or {}).get("link_urls"))
    return body, urls, headers, raw_bytes


@app.post("/analyse")
@(_limiter.limit(RATE_LIMIT_ANALYSE) if _RATE_LIMIT_OK else (lambda f: f))
async def analyse(request: Request, req: AnalyseRequest):
    body, urls, headers, raw_bytes = _get_body_urls_headers(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")

    # trusted-sender check (must be done before fusion)
    sender_domain = _sender_domain(headers.get("from", ""))
    trusted_sender = is_trusted_domain(sender_domain)

    # NEW: SPF/DKIM/DMARC + Spamhaus DBL. This runs in parallel with the
    # model inference below: the DNS lookup is ~50ms and the header parse
    # is <1ms, so we kick it off first and gather the result later.
    auth_signal_task = None
    if _AUTH_HEADERS_AVAILABLE:
        # Toggle DBL via env: set REPUTATION_ENABLE_DBL=0 to skip the DNS
        # lookup entirely (useful in isolated dev environments).
        enable_dbl = os.environ.get("REPUTATION_ENABLE_DBL", "1") != "0"
        auth_signal_task = asyncio.create_task(
            build_metadata_auth_signal(headers, enable_dbl=enable_dbl)
        )

    # NEW: URL reputation cascade. Same pattern: kick it off in parallel so
    # its latency (mostly one GSB HTTP round-trip on cache miss) overlaps
    # with the model inference on the CPU.
    reputation_task = None
    if _REPUTATION_AVAILABLE and urls:
        reputation_task = asyncio.create_task(_reputation.check_urls(urls))

    # run agents: pass the extra context so the trained models can take
    # over when they're loaded; the heuristic fallback still works with
    # just the parsed urls/headers.
    try:
        p_text = text_agent(body)
        p_url  = url_agent(urls, body_text=body)
        p_meta = metadata_agent(headers, raw_email=raw_bytes)
    except Exception as e:
        if auth_signal_task:
            auth_signal_task.cancel()
        if reputation_task:
            reputation_task.cancel()
        raise HTTPException(500, f"Inference failed: {e}")

    # Collect the auth signal (or a safe default if disabled/errored)
    auth_signal: dict[str, Any] = {"score_delta": 0.0, "reasons": [], "auth": {}, "spamhaus_dbl": {}}
    if auth_signal_task:
        try:
            auth_signal = await auth_signal_task
        except Exception as e:
            logger.warning(f"auth_signal task failed: {e}")

    # Collect the URL reputation verdicts (or an empty list if disabled)
    reputation_verdicts: list[dict[str, Any]] = []
    if reputation_task:
        try:
            reputation_verdicts = await reputation_task
        except Exception as e:
            logger.warning(f"reputation task failed: {e}")

    # Apply reputation to the URL agent score. Any tier flagging a URL is
    # very strong evidence: much better than a RF trained on lexical
    # features alone. We take the max score across all URLs.
    rep_max_score = 0.0
    rep_hit_sources: set[str] = set()
    rep_threat_types: set[str] = set()
    for v in reputation_verdicts:
        if v.get("malicious"):
            rep_max_score = max(rep_max_score, float(v.get("score", 0.0)))
            for s in v.get("sources", []):
                rep_hit_sources.add(s)
            for t in v.get("threat_types", []):
                rep_threat_types.add(t)

    # Fusion between RF/heuristic (p_url) and reputation:
    #   • Google Safe Browsing hit (score 1.0)         → override to 0.95
    #   • Any fallback source hit                      → boost via weighted max
    #   • No hit                                       → keep RF score untouched
    p_url_raw = p_url
    if rep_max_score >= 0.99:               # GSB match
        p_url = max(p_url, 0.95)
    elif rep_max_score > 0:                 # PhishTank / URLhaus / Spamhaus
        p_url = max(p_url, 0.7 * rep_max_score + 0.3 * p_url)

    # Apply the auth signal to the metadata score. Clamp to [0, 1] so a big
    # negative delta on a well-signed email can't drive p_meta below zero.
    p_meta_raw = p_meta
    p_meta = max(0.0, min(1.0, p_meta + float(auth_signal.get("score_delta", 0.0))))

    # Alignment override: if the message is DKIM-aligned to a well-known
    # institutional domain, we trust the crypto signal over any allowlist.
    crypto_verified = bool(auth_signal.get("auth", {}).get("cryptographically_verified"))

    # Softer signal: Gmail delivered this message to Inbox. Gmail already
    # ran SPF/DKIM/DMARC on every message it delivers: a spoofed message
    # from an unauthenticated sender lands in Spam. So Inbox delivery is
    # itself a weak verification signal. We use it only when:
    #   (a) the message came from the Gmail content script (client_context)
    #   (b) crypto_verified is FALSE (we always prefer the real crypto path)
    #   (c) the strong signal path can't be built (mailed-by/signed-by
    #       scraping failed: Gmail lazy-loads them behind an overlay)
    #   (d) the strong signal we DO have doesn't fail DMARC
    #
    # When these all hold, we apply a much softer discount than crypto_verified
    # (text weight * 0.75, keep single-agent override, threshold 0.6).
    ctx = req.client_context or {}

    # v1.14: forwarded emails and near-empty bodies.
    subject = headers.get("subject") or ctx.get("subject")
    forwarded = detect_forwarded(body, subject if isinstance(subject, str) else None)
    shared_links = detect_shared_links(urls)
    text_used = len(body.split()) >= MIN_TEXT_WORDS
    if forwarded["detected"]:
        # The sender vouches for the forward, not for the forwarded content.
        trusted_sender = False
        crypto_verified = False

    gmail_inbox_soft = (
        not crypto_verified
        and not forwarded["detected"]
        and ctx.get("origin") == "gmail"
        and bool(ctx.get("gmail_in_inbox"))
        and auth_signal.get("auth", {}).get("dmarc") != "fail"
        and auth_signal.get("auth", {}).get("dkim")  != "fail"
    )

    # When the sender domain is trusted, the metadata agent reports a low
    # score and the text agent's contribution to the fused score is halved
    # (DistilBERT often false-positives on transactional bank/hospital tone).
    # A Google Safe Browsing match on any link means the sending account is
    # compromised, whoever it belongs to: it forces the phishing verdict on
    # every trust path, including the allowlist (fixed in v1.11.0; before,
    # an allowlisted sender could carry a GSB-listed link and stay "safe").
    gsb_hit = "google_safe_browsing" in rep_hit_sources

    def _fuse(text_factor: float) -> float:
        # Without usable text, the URL and metadata agents share the
        # whole weight (renormalised) instead of the text agent's score
        # on two words deciding a third of the verdict.
        if text_used:
            return (W_TEXT * text_factor) * p_text + W_URL * p_url + W_META * p_meta
        return (W_URL * p_url + W_META * p_meta) / (W_URL + W_META)

    if trusted_sender:
        p_meta = min(p_meta, 0.05)
        fused = _fuse(0.5)
        high_conf = gsb_hit            # only real threat intel overrides the allowlist
        threshold = 0.65               # raise the bar for flagging a trusted sender
        trust_path = "trusted_sender"
    elif crypto_verified:
        # DKIM-aligned to the visible From: header, which is cryptographic proof of the
        # sender identity. Apply the same discount as the static allowlist:
        # halve the text weight (DistilBERT often false-positives on
        # "verify your account" transactional templates) and disable the
        # single-agent override (a confident text-agent call alone shouldn't
        # flip an authenticated message to phishing).
        #
        # Exception: URL reputation hits (Google Safe Browsing, etc.)
        # override this: a real threat-intel match on a link means the
        # sender's account was compromised, so we let the phishing verdict
        # through even for a signed message.
        fused = _fuse(0.5)
        high_conf = gsb_hit   # only real threat-intel forces the override
        threshold = 0.65
        trust_path = "crypto_verified"
    elif gmail_inbox_soft:
        # Gmail delivered this message to Inbox, so its own SPF/DKIM/DMARC
        # verification passed even though our scraping couldn't recover
        # the exact identifiers. Discount text agent contribution and
        # disable the single-agent override so a confident DistilBERT call
        # on a transactional template ("verify your email") doesn't flip
        # the verdict on its own.
        #
        # Gmail's spam filter catches >99% of phishing before Inbox delivery,
        # so we can be aggressive with this discount. URL / metadata agents
        # still contribute at full weight: if a URL is actually malicious
        # (RF or reputation cascade), the fused score can still cross the
        # threshold. GSB match still forces phishing regardless.
        fused = _fuse(0.6)
        high_conf = gsb_hit
        threshold = 0.62
        trust_path = "gmail_inbox_soft"
    else:
        fused = _fuse(1.0)
        high_conf = max(p_text if text_used else 0.0, p_url, p_meta) >= HIGH_CONF_OVERRIDE
        threshold = FUSION_THRESHOLD
        trust_path = "default"

    is_phishing = (fused >= threshold) or high_conf
    _count_verdict("/analyse", is_phishing, trust_path)

    return {
        "verdict": "phishing" if is_phishing else "safe",
        "fused_score": float(fused),
        "high_confidence_override": bool(high_conf),
        # Which of the four scoring paths was applied (additive field, v1.10):
        #   trusted_sender > crypto_verified > gmail_inbox_soft > default
        "trust_path": trust_path,
        "trusted_sender": bool(trusted_sender),
        "sender_domain": sender_domain,
        # v1.14 (additive): forwarded detection, shared-file links, and
        # whether the text agent counted (False when the body is too short).
        "forwarded": forwarded,
        "shared_links": shared_links,
        "text_agent_used": text_used,
        "sender_auth": {
            "cryptographically_verified": crypto_verified,
            "gmail_inbox_soft_verified":  bool(gmail_inbox_soft),
            "spf":   auth_signal.get("auth", {}).get("spf", "none"),
            "dkim":  auth_signal.get("auth", {}).get("dkim", "none"),
            "dmarc": auth_signal.get("auth", {}).get("dmarc", "none"),
            "aligned": auth_signal.get("auth", {}).get("aligned", False),
            "spamhaus_dbl_listed": bool(auth_signal.get("spamhaus_dbl", {}).get("listed")),
            "reasons": auth_signal.get("reasons", []),
            "score_delta": auth_signal.get("score_delta", 0.0),
        },
        "url_reputation": {
            "checked": len(reputation_verdicts),
            "malicious_count": sum(1 for v in reputation_verdicts if v.get("malicious")),
            "sources_hit": sorted(rep_hit_sources),
            "threat_types": sorted(rep_threat_types),
            "verdicts": reputation_verdicts,
        },
        "agents": {
            "text":     {"phishing_probability": p_text,
                         "verdict": verdict_label(p_text)},
            "url":      {"phishing_probability": p_url,
                         "phishing_probability_raw": p_url_raw,
                         "verdict": verdict_label(p_url)},
            "metadata": {"phishing_probability": p_meta,
                         "phishing_probability_raw": p_meta_raw,
                         "verdict": verdict_label(p_meta)},
        },
    }


# ---------------------------------------------------------------------------
# /analyse_attachment: v1.8+
# ---------------------------------------------------------------------------
# Runs the same text-agent + URL-agent + reputation-cascade pipeline as
# /analyse, but on content extracted from an uploaded attachment (PDF or
# HTML in Phase 1). The response shape mirrors /analyse so the extension
# and landing widgets can share their rendering code, with an extra
# `attachment` object carrying the extracted metadata (kind, size, page
# count, notable features like /JavaScript in PDFs, etc).
# ---------------------------------------------------------------------------
@app.post("/analyse_attachment")
@(_limiter.limit(RATE_LIMIT_ATTACHMENT) if _RATE_LIMIT_OK else (lambda f: f))
async def analyse_attachment(request: Request, req: AttachmentRequest):
    if not _ATTACHMENTS_AVAILABLE:
        raise HTTPException(
            501,
            "Attachment analysis is not available on this backend "
            "(attachment_analysis module failed to import).",
        )

    try:
        extracted = _attachments.analyse_attachment(
            req.content_b64,
            filename=req.filename or "",
            mime_type=req.mime_type,
        )
    except ValueError as e:
        # Client-side error: unsupported type, oversized, bad base64.
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        # Server-side extraction failed (corrupt PDF, etc). Not a 500:
        # the request was valid, the file just doesn't parse.
        raise HTTPException(422, str(e))
    except Exception as e:
        raise HTTPException(500, f"Attachment analysis crashed: {e}")

    text = extracted.get("extracted_text", "") or ""
    urls = extracted.get("extracted_urls", []) or []

    # If we couldn't extract any text (image-only PDF for instance),
    # we skip the text agent and only rely on the URL agent + reputation.
    # This still catches most malicious PDFs; they usually carry a link
    # to a credential-harvesting page.
    p_text = 0.0
    if text.strip():
        try:
            p_text = float(text_agent(text))
        except Exception as e:
            logger.warning(f"text_agent failed on attachment: {e}")

    # URL agent: trained RF when available, heuristic fallback otherwise.
    try:
        p_url = float(url_agent(urls, body_text=text))
    except Exception as e:
        logger.warning(f"url_agent failed on attachment: {e}")
        p_url = 0.0

    # Reputation cascade in parallel: same tiers as /analyse.
    reputation_verdicts: list[dict[str, Any]] = []
    if _REPUTATION_AVAILABLE and urls:
        try:
            reputation_verdicts = await _reputation.check_urls(urls)
        except Exception as e:
            logger.warning(f"reputation check failed on attachment: {e}")

    rep_max_score = 0.0
    rep_hit_sources: set[str] = set()
    rep_threat_types: set[str] = set()
    for v in reputation_verdicts:
        if v.get("malicious"):
            rep_max_score = max(rep_max_score, float(v.get("score", 0.0)))
            rep_hit_sources.update(v.get("sources", []))
            rep_threat_types.update(v.get("threat_types", []))

    # Fusion between RF and reputation: same rule as /analyse.
    p_url_raw = p_url
    if rep_max_score >= 0.99:
        p_url = max(p_url, 0.95)
    elif rep_max_score > 0:
        p_url = max(p_url, 0.7 * rep_max_score + 0.3 * p_url)

    # PDF / HTML notable features carry weight: an unsolicited HTML
    # attachment carrying a password field is basically a phishing
    # template, and a PDF that auto-executes JavaScript on open is a
    # malware dropper. These features often ARE the whole signal on
    # attachments (extracted text is short or empty), so we let the
    # bonus climb to ~0.7 rather than capping at 0.4.
    notable = extracted.get("notable_features", []) or []
    feature_bonus = 0.0
    _RISK = {
        # PDF-side markers
        "contains_javascript":     0.20,
        "auto_execute_on_open":    0.30,
        "launch_external_action":  0.35,
        "embeds_another_file":     0.20,
        "submits_form_to_url":     0.25,
        "contains_link_annotation":0.00,   # too common in legit PDFs
        "remote_link_action":      0.10,
        "flash_or_richmedia":      0.15,
        # HTML-side markers
        "contains_form":           0.15,
        "contains_password_field": 0.40,   # login-page attachments are ~always phish
        "contains_iframe":         0.10,
        "meta_refresh_redirect":   0.20,
        # Images and scanned PDFs (v1.12)
        "image_only_pdf":          0.10,   # no text layer: common evasion, also real scans
        "contains_qr_code":        0.20,   # "quishing": link hidden from text scanners
        "text_from_ocr":           0.00,   # informational
        # Office documents (v1.12)
        "contains_macros":         0.45,
        "remote_template":         0.45,   # template injection
        "dde_field":               0.40,
        "contains_activex":        0.25,
        "embedded_ole_object":     0.20,
        "external_data_connection":0.20,
        "encrypted_document":      0.30,   # password in the email body blinds scanners
        "legacy_office_format":    0.10,
        "suspicious_xml_doctype":  0.20,
        # Archives, calendar invites, risky file types (v1.14)
        "encrypted_archive":       0.35,   # scanners can't open it: classic evasion
        "uninspectable_archive":   0.20,   # RAR / 7z: not opened here
        "nested_archive":          0.10,
        "zip_bomb_suspected":      0.30,
        "disk_image_in_archive":   0.40,
        "disk_image_attachment":   0.40,
        "oversized_inner_file":    0.00,
        "calendar_invite":         0.00,
        "calendar_with_links":     0.10,
    }
    for f in notable:
        feature_bonus += _RISK.get(f, 0.0)
    # Combo bump: a form + password field together is a full login page
    if "contains_form" in notable and "contains_password_field" in notable:
        feature_bonus += 0.10
    feature_bonus = min(feature_bonus, 0.7)

    # Attachments have no From:/DKIM to check, so the metadata agent is
    # effectively N/A; we still expose it as 0 for consistent shape.
    p_meta = 0.0

    # Inherit trust context from the parent email. If the extension told
    # us the message is Gmail-delivered (soft SPF/DKIM/DMARC pass) or
    # cryptographically DKIM-aligned, we know a phishing attachment
    # requires a compromised legitimate account: much rarer than a
    # random attacker. We apply softer weights and a higher threshold
    # in that case to avoid false-positives on legit documents (INTERPOL
    # checklists, HR onboarding kits, bank T&Cs) whose text vocabulary
    # overlaps with real phishing.
    #
    # EXCEPTION: a Google Safe Browsing hit on any URL in the attachment
    # still forces phishing regardless: a signed message pointing to a
    # blocklisted URL means the sender's account is compromised.
    # SECURITY NOTE: parent_email is a client-supplied hint we can't
    # independently verify from a raw /analyse_attachment call: a caller
    # can trivially claim `gmail_delivered=true` in curl. The impact of
    # a false claim is limited: it only softens THAT caller's own scoring,
    # never anyone else's. A Google Safe Browsing hit still overrides the
    # softer path (see gsb_hit below). Never widen this trust surface
    # to actions with side-effects for other users.
    parent = req.parent_email or {}
    parent_trusted = bool(
        parent.get("crypto_verified")
        or parent.get("gmail_inbox_soft_verified")
        or parent.get("trusted_sender")
        or parent.get("gmail_delivered")   # explicit flag set by gmail.js
    )
    gsb_hit = "google_safe_browsing" in rep_hit_sources
    # Office dropper techniques (v1.12). Gmail delivering the parent email
    # says nothing about what a macro will do once enabled, and compromised
    # accounts are exactly how these documents travel, so they force the
    # phishing verdict on every path, like a Safe Browsing hit.
    dropper = sorted(set(notable) & {
        "contains_macros", "remote_template", "dde_field",
        # v1.14: executables, scripts and shortcuts, directly or in an archive
        "dangerous_file_type", "executable_in_archive", "script_in_archive",
        "shortcut_in_archive", "double_extension",
    })

    if parent_trusted and not gsb_hit and not dropper:
        # text agent halved, url weight kept, feature bonus intact.
        # Threshold raised so purely-textual false-positives (99% content
        # score on a legit doc) don't cross alone.
        fused = 0.5 * 0.5 * p_text + 0.5 * p_url + feature_bonus
        threshold = 0.72
        high_conf = False              # disable single-agent override
    else:
        fused = 0.5 * p_text + 0.5 * p_url + feature_bonus
        threshold = 0.55
        high_conf = gsb_hit or bool(dropper) or (max(p_text, p_url) >= HIGH_CONF_OVERRIDE)

    fused = min(1.0, fused)
    is_phishing = fused >= threshold or high_conf
    _count_verdict("/analyse_attachment", is_phishing,
                   "parent_trusted" if parent_trusted else "default")

    return {
        "verdict": "phishing" if is_phishing else "safe",
        "fused_score": float(fused),
        "high_confidence_override": bool(high_conf),
        "attachment": {
            "filename":            extracted.get("filename"),
            "kind":                extracted.get("kind"),
            "size_bytes":          extracted.get("size_bytes"),
            "page_count":          extracted.get("page_count"),
            "pages_read":          extracted.get("pages_read"),
            "extracted_text_chars": extracted.get("extracted_text_chars"),
            "extracted_urls_count": len(urls),
            "notable_features":    notable,
            "feature_bonus":       round(feature_bonus, 3),
            # v1.12: images, scanned PDFs, Office
            "qr_urls":             extracted.get("qr_urls", []),
            "ocr_used":            bool(extracted.get("ocr_used")),
            "capabilities":        extracted.get("capabilities"),
            "dropper_techniques":  dropper,
            # v1.14: archives and calendar invites (None for other kinds)
            "archive_format":      extracted.get("archive_format"),
            "entries":             extracted.get("entries"),
            "entry_count":         extracted.get("entry_count"),
            "encrypted":           extracted.get("encrypted"),
            "inner_files":         extracted.get("inner_files"),
            "organizer":           extracted.get("organizer"),
        },
        "parent_email": req.parent_email or None,
        "parent_trusted": bool(parent_trusted),
        "url_reputation": {
            "checked": len(reputation_verdicts),
            "malicious_count": sum(1 for v in reputation_verdicts if v.get("malicious")),
            "sources_hit": sorted(rep_hit_sources),
            "threat_types": sorted(rep_threat_types),
            "verdicts": reputation_verdicts,
        },
        "agents": {
            "text":     {"phishing_probability": p_text,
                         "verdict": verdict_label(p_text)},
            "url":      {"phishing_probability": p_url,
                         "phishing_probability_raw": p_url_raw,
                         "verdict": verdict_label(p_url)},
            "metadata": {"phishing_probability": p_meta,
                         "verdict": "Safe",
                         "note": "not applicable to attachments"},
        },
    }
