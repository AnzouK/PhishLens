"""
Smart Phishing Detector — minimal FastAPI backend for the Chrome extension.

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
from pathlib import Path
from typing import Any

import numpy as np
import torch
import torch.nn.functional as F
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from lime.lime_text import LimeTextExplainer
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# Sender authentication + Spamhaus DBL — real cryptographic signals to
# replace the static allowlist. Optional: if the module isn't present the
# backend still boots and the heuristic path takes over.
try:
    from auth_headers import build_metadata_auth_signal, parse_authentication_results
    _AUTH_HEADERS_AVAILABLE = True
except Exception as _e:
    _AUTH_HEADERS_AVAILABLE = False
    print(f"⚠ auth_headers module not loaded ({_e}); "
          "SPF/DKIM/DMARC + Spamhaus DBL disabled.")

# URL reputation cascade — GSB → PhishTank → URLhaus → Spamhaus DBL.
# Same graceful-fallback pattern as auth_headers: missing module → heuristics.
try:
    import reputation as _reputation
    _REPUTATION_AVAILABLE = True
except Exception as _e:
    _REPUTATION_AVAILABLE = False
    print(f"⚠ reputation module not loaded ({_e}); "
          "GSB / PhishTank / URLhaus disabled.")

# Email attachment analysis — PDF / HTML in v1.8 (Phase 1). DOCX/XLSX
# and image OCR + steg heuristics are planned for later phases.
try:
    import attachment_analysis as _attachments
    _ATTACHMENTS_AVAILABLE = True
except Exception as _e:
    _ATTACHMENTS_AVAILABLE = False
    print(f"⚠ attachment_analysis module not loaded ({_e}); "
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

# fusion weights — kept identical to the academic document
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
# fusion is reduced, and the high-confidence override is disabled — because
# DistilBERT's transactional-template wording often false-positives on real
# bank / hospital / telco / government messages.
#
# Personal email providers (gmail.com, yahoo.com, outlook.com, ...) are
# deliberately NOT in this set — they are used by phishers as much as by
# legitimate senders, so they carry no trust signal.
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

    print(f"Local model not found at {MODEL_DIR} — falling back to "
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
    print(f"Downloaded {HF_MODEL_REPO} -> {MODEL_DIR}")
    return MODEL_DIR


@asynccontextmanager
async def lifespan(_app: FastAPI):
    model_dir = _ensure_model_available()
    print(f"Loading DistilBERT from {model_dir} ...")
    device = _pick_device()
    tok = AutoTokenizer.from_pretrained(str(model_dir))
    # FP32 loading — CPUs don't have great FP16 support and inference is ~2×
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
    print(f"Model loaded on device={device}. Ready on port {PORT}.")

    # Start the reputation cascade (PhishTank feed download, cache warm-up).
    # Runs after model load so a slow PhishTank fetch doesn't block startup
    # health checks — the model is already serving by then.
    if _REPUTATION_AVAILABLE:
        try:
            await _reputation.startup()
        except Exception as _e:
            print(f"⚠ reputation.startup() failed: {_e}")

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
app = FastAPI(title="Smart Phishing Detector — extension backend",
              lifespan=lifespan)

# Chrome extensions have origin chrome-extension://<id>. For local dev we
# allow any origin (the backend is localhost-only anyway).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


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
    between raw_email_b64 scans — full headers — and raw_text scans —
    body only). Structure is intentionally loose (dict) so we can add new
    hints without a breaking API bump.
    """
    raw_email_b64: str | None = None
    raw_text: str | None = None
    sender_email: str | None = None
    client_context: dict[str, Any] | None = None


class AttachmentRequest(BaseModel):
    """
    Payload for POST /analyse_attachment (v1.8+).

    content_b64  — base64-encoded attachment bytes, 10 MB hard cap
    filename     — original filename (only used for MIME sniffing and UX)
    mime_type    — client hint, not trusted (we sniff for real)
    parent_email — optional context: {sender_email, subject} of the mail
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
                        body = re.sub(r"<[^>]+>", " ", part.get_content())
                        break
                    except Exception:
                        pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = raw_bytes.decode("utf-8", errors="ignore")
    # urls
    urls = re.findall(r"https?://[^\s\"'<>)]+", body)
    # headers (subset)
    headers = {k.lower(): str(v) for k, v in msg.items()}
    return body.strip(), urls, headers


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------
def predict_proba_batch(texts: list[str]) -> np.ndarray:
    """Return Nx2 array of [P(Safe), P(Phishing)] — needed by LIME."""
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
# https://github.com/AnzouK/PhishingDetector — the URLAgent and
# MetadataAgent classes ship in this folder (copied verbatim from the
# training repo) so we can load their pickled state directly.
HF_AGENTS_REPO = os.environ.get("HF_AGENTS_REPO", "AnzouKiona/phishlens-agents")
_URL_AGENT       = None
_METADATA_AGENT  = None
_FEATURE_EXTRACT = None

def _try_download_agents() -> tuple[Path | None, Path | None]:
    """Fetch the two agent joblibs from Hugging Face, if reachable."""
    try:
        from huggingface_hub import hf_hub_download
        url_path = hf_hub_download(
            repo_id=HF_AGENTS_REPO, filename="url_agent.joblib",
            repo_type="model", local_dir="./agents"
        )
        meta_path = hf_hub_download(
            repo_id=HF_AGENTS_REPO, filename="metadata_agent.joblib",
            repo_type="model", local_dir="./agents"
        )
        return Path(url_path), Path(meta_path)
    except Exception as e:
        print(f"⚠ Could not fetch agents from {HF_AGENTS_REPO}: {e}")
        return None, None


try:
    # Feature extractor (always available — trained agents need it).
    from feature_extraction import FeatureExtractor  # noqa: E402
    _FEATURE_EXTRACT = FeatureExtractor()

    # Local override paths win over the HF download.
    local_url  = os.environ.get("URL_AGENT_PATH")
    local_meta = os.environ.get("METADATA_AGENT_PATH")
    url_path   = Path(local_url) if local_url and Path(local_url).exists() else None
    meta_path  = Path(local_meta) if local_meta and Path(local_meta).exists() else None

    if url_path is None or meta_path is None:
        u2, m2 = _try_download_agents()
        url_path  = url_path  or u2
        meta_path = meta_path or m2

    if url_path and url_path.exists():
        from url_agent import URLAgent  # noqa: E402
        _URL_AGENT = URLAgent()
        _URL_AGENT.load_model(str(url_path))
        print(f"✓ Loaded trained URL agent from {url_path}")

    if meta_path and meta_path.exists():
        from metadata_agent import MetadataAgent  # noqa: E402
        _METADATA_AGENT = MetadataAgent()
        _METADATA_AGENT.load_model(str(meta_path))
        print(f"✓ Loaded trained metadata agent from {meta_path}")

    if not _URL_AGENT and not _METADATA_AGENT:
        print("ℹ No trained agents loaded — using heuristic fallbacks.")
except Exception as e:
    print(f"⚠ Trained-agents init failed, falling back to heuristics: {e}")


def url_agent(urls: list[str], body_text: str = "") -> float:
    """URL score — trained RF on the full body text when available,
    heuristic on the extracted URL list otherwise."""
    if _URL_AGENT is not None and _FEATURE_EXTRACT is not None and body_text:
        try:
            feats = _FEATURE_EXTRACT.extract_url_features(body_text)
            pred  = _URL_AGENT.get_prediction_with_confidence(feats)
            return float(pred["phishing_probability"])
        except Exception as e:
            print(f"  url_agent trained path failed ({e}); falling back to heuristic")
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
    """Metadata score — trained RF on the raw email when available,
    heuristic on the parsed header dict otherwise."""
    if _METADATA_AGENT is not None and _FEATURE_EXTRACT is not None and raw_email:
        try:
            feats = _FEATURE_EXTRACT.extract_metadata_features(raw_email)
            pred  = _METADATA_AGENT.get_prediction_with_confidence(feats)
            return float(pred["phishing_probability"])
        except Exception as e:
            print(f"  metadata_agent trained path failed ({e}); falling back to heuristic")
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
    # Display name impersonation: 'PayPal' from a non-paypal address
    m = re.match(r'"?([^"<]+)"?\s*<', headers.get("from", ""))
    if m:
        display = m.group(1).lower()
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
    Debug endpoint — cache hit rate, GSB quota consumption, PhishTank feed
    size. Handy for monitoring how close we get to the 10k/day GSB limit
    and whether the cache is doing its job. Not exposed to end users.
    """
    if not _REPUTATION_AVAILABLE:
        return {"enabled": False, "reason": "reputation module not loaded"}
    return {"enabled": True, **_reputation.stats()}


@app.post("/explain")
def explain(req: AnalyseRequest):
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
        # never sees an empty 'Why?' panel — even when DistilBERT is so
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
    same way it handles a real one — and the alignment check makes sure
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

    # From: domain — used by parse_authentication_results to check alignment.
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
        # cheap org-domain compare — mirrors auth_headers._org_domain
        def _od(d):
            ps = d.split(".")
            return ".".join(ps[-2:]) if len(ps) >= 2 else d
        if _od(signed_by) == _od(from_domain):
            parts.append(f"dmarc=pass header.from={from_domain}")

    return " ".join(parts)


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
    return body, urls, headers, raw_bytes


@app.post("/analyse")
async def analyse(req: AnalyseRequest):
    body, urls, headers, raw_bytes = _get_body_urls_headers(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")

    # trusted-sender check (must be done before fusion)
    sender_domain = _sender_domain(headers.get("from", ""))
    trusted_sender = is_trusted_domain(sender_domain)

    # NEW: SPF/DKIM/DMARC + Spamhaus DBL. This runs in parallel with the
    # model inference below — the DNS lookup is ~50ms and the header parse
    # is <1ms, so we kick it off first and gather the result later.
    auth_signal_task = None
    if _AUTH_HEADERS_AVAILABLE:
        # Toggle DBL via env — set REPUTATION_ENABLE_DBL=0 to skip the DNS
        # lookup entirely (useful in isolated dev environments).
        enable_dbl = os.environ.get("REPUTATION_ENABLE_DBL", "1") != "0"
        auth_signal_task = asyncio.create_task(
            build_metadata_auth_signal(headers, enable_dbl=enable_dbl)
        )

    # NEW: URL reputation cascade. Same pattern — kick it off in parallel so
    # its latency (mostly one GSB HTTP round-trip on cache miss) overlaps
    # with the model inference on the CPU.
    reputation_task = None
    if _REPUTATION_AVAILABLE and urls:
        reputation_task = asyncio.create_task(_reputation.check_urls(urls))

    # run agents — pass the extra context so the trained models can take
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
            print(f"⚠ auth_signal task failed: {e}")

    # Collect the URL reputation verdicts (or an empty list if disabled)
    reputation_verdicts: list[dict[str, Any]] = []
    if reputation_task:
        try:
            reputation_verdicts = await reputation_task
        except Exception as e:
            print(f"⚠ reputation task failed: {e}")

    # Apply reputation to the URL agent score. Any tier flagging a URL is
    # very strong evidence — much better than a RF trained on lexical
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

    # Alignment override — if the message is DKIM-aligned to a well-known
    # institutional domain, we trust the crypto signal over any allowlist.
    crypto_verified = bool(auth_signal.get("auth", {}).get("cryptographically_verified"))

    # Softer signal: Gmail delivered this message to Inbox. Gmail already
    # ran SPF/DKIM/DMARC on every message it delivers — a spoofed message
    # from an unauthenticated sender lands in Spam. So Inbox delivery is
    # itself a weak verification signal. We use it only when:
    #   (a) the message came from the Gmail content script (client_context)
    #   (b) crypto_verified is FALSE (we always prefer the real crypto path)
    #   (c) the strong signal path can't be built (mailed-by/signed-by
    #       scraping failed — Gmail lazy-loads them behind an overlay)
    #   (d) the strong signal we DO have doesn't fail DMARC
    #
    # When these all hold, we apply a much softer discount than crypto_verified
    # (text weight * 0.75, keep single-agent override, threshold 0.6).
    ctx = req.client_context or {}
    gmail_inbox_soft = (
        not crypto_verified
        and ctx.get("origin") == "gmail"
        and bool(ctx.get("gmail_in_inbox"))
        and auth_signal.get("auth", {}).get("dmarc") != "fail"
        and auth_signal.get("auth", {}).get("dkim")  != "fail"
    )

    # When the sender domain is trusted, the metadata agent reports a low
    # score and the text agent's contribution to the fused score is halved
    # (DistilBERT often false-positives on transactional bank/hospital tone).
    if trusted_sender:
        p_meta = min(p_meta, 0.05)
        fused = (W_TEXT * 0.5) * p_text + W_URL * p_url + W_META * p_meta
        high_conf = False              # disable single-agent override for trusted senders
        threshold = 0.65               # raise the bar for flagging a trusted sender
    elif crypto_verified:
        # DKIM-aligned to the visible From: — cryptographic proof of the
        # sender identity. Apply the same discount as the static allowlist:
        # halve the text weight (DistilBERT often false-positives on
        # "verify your account" transactional templates) and disable the
        # single-agent override (a confident text-agent call alone shouldn't
        # flip an authenticated message to phishing).
        #
        # Exception: URL reputation hits (Google Safe Browsing, etc.)
        # override this — a real threat-intel match on a link means the
        # sender's account was compromised, so we let the phishing verdict
        # through even for a signed message.
        gsb_hit = "google_safe_browsing" in rep_hit_sources
        fused = (W_TEXT * 0.5) * p_text + W_URL * p_url + W_META * p_meta
        high_conf = gsb_hit   # only real threat-intel forces the override
        threshold = 0.65
    elif gmail_inbox_soft:
        # Gmail delivered this message to Inbox — its own SPF/DKIM/DMARC
        # verification passed even though our scraping couldn't recover
        # the exact identifiers. Discount text agent contribution and
        # disable the single-agent override so a confident DistilBERT call
        # on a transactional template ("verify your email") doesn't flip
        # the verdict on its own.
        #
        # Gmail's spam filter catches >99% of phishing before Inbox delivery,
        # so we can be aggressive with this discount. URL / metadata agents
        # still contribute at full weight — if a URL is actually malicious
        # (RF or reputation cascade), the fused score can still cross the
        # threshold. GSB match still forces phishing regardless.
        gsb_hit = "google_safe_browsing" in rep_hit_sources
        fused = (W_TEXT * 0.6) * p_text + W_URL * p_url + W_META * p_meta
        high_conf = gsb_hit
        threshold = 0.62
    else:
        fused = W_TEXT * p_text + W_URL * p_url + W_META * p_meta
        high_conf = max(p_text, p_url, p_meta) >= HIGH_CONF_OVERRIDE
        threshold = FUSION_THRESHOLD

    is_phishing = (fused >= threshold) or high_conf

    return {
        "verdict": "phishing" if is_phishing else "safe",
        "fused_score": float(fused),
        "high_confidence_override": bool(high_conf),
        "trusted_sender": bool(trusted_sender),
        "sender_domain": sender_domain,
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
# /analyse_attachment — v1.8+
# ---------------------------------------------------------------------------
# Runs the same text-agent + URL-agent + reputation-cascade pipeline as
# /analyse, but on content extracted from an uploaded attachment (PDF or
# HTML in Phase 1). The response shape mirrors /analyse so the extension
# and landing widgets can share their rendering code — with an extra
# `attachment` object carrying the extracted metadata (kind, size, page
# count, notable features like /JavaScript in PDFs, etc).
# ---------------------------------------------------------------------------
@app.post("/analyse_attachment")
async def analyse_attachment(req: AttachmentRequest):
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
        # Client-side error — unsupported type, oversized, bad base64.
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        # Server-side extraction failed (corrupt PDF, etc). Not a 500 —
        # the request was valid, the file just doesn't parse.
        raise HTTPException(422, str(e))
    except Exception as e:
        raise HTTPException(500, f"Attachment analysis crashed: {e}")

    text = extracted.get("extracted_text", "") or ""
    urls = extracted.get("extracted_urls", []) or []

    # If we couldn't extract any text (image-only PDF for instance),
    # we skip the text agent and only rely on the URL agent + reputation.
    # This still catches most malicious PDFs — they usually carry a link
    # to a credential-harvesting page.
    p_text = 0.0
    if text.strip():
        try:
            p_text = float(text_agent(text))
        except Exception as e:
            print(f"⚠ text_agent failed on attachment: {e}")

    # URL agent — trained RF when available, heuristic fallback otherwise.
    try:
        p_url = float(url_agent(urls, body_text=text))
    except Exception as e:
        print(f"⚠ url_agent failed on attachment: {e}")
        p_url = 0.0

    # Reputation cascade in parallel — same tiers as /analyse.
    reputation_verdicts: list[dict[str, Any]] = []
    if _REPUTATION_AVAILABLE and urls:
        try:
            reputation_verdicts = await _reputation.check_urls(urls)
        except Exception as e:
            print(f"⚠ reputation check failed on attachment: {e}")

    rep_max_score = 0.0
    rep_hit_sources: set[str] = set()
    rep_threat_types: set[str] = set()
    for v in reputation_verdicts:
        if v.get("malicious"):
            rep_max_score = max(rep_max_score, float(v.get("score", 0.0)))
            rep_hit_sources.update(v.get("sources", []))
            rep_threat_types.update(v.get("threat_types", []))

    # Fusion between RF and reputation — same rule as /analyse.
    p_url_raw = p_url
    if rep_max_score >= 0.99:
        p_url = max(p_url, 0.95)
    elif rep_max_score > 0:
        p_url = max(p_url, 0.7 * rep_max_score + 0.3 * p_url)

    # PDF / HTML notable features carry weight too — /JavaScript in a
    # PDF you didn't ask for is a red flag on its own. We surface these
    # in the response but only nudge the score, we don't dominate it.
    notable = extracted.get("notable_features", []) or []
    feature_bonus = 0.0
    _RISK = {
        "contains_javascript":     0.15,
        "auto_execute_on_open":    0.20,
        "launch_external_action":  0.25,
        "embeds_another_file":     0.15,
        "submits_form_to_url":     0.15,
        "contains_password_field": 0.20,
        "meta_refresh_redirect":   0.10,
        "flash_or_richmedia":      0.10,
    }
    for f in notable:
        feature_bonus += _RISK.get(f, 0.0)
    feature_bonus = min(feature_bonus, 0.4)

    # Attachments have no From:/DKIM to check, so the metadata agent is
    # effectively N/A — we still expose it as 0 for consistent shape.
    p_meta = 0.0

    # Attachment-specific fusion: text and URL carry all the weight,
    # plus the feature bonus on top. Threshold is a bit higher than
    # /analyse's default (0.55) because attachments have less signal.
    fused = 0.5 * p_text + 0.5 * p_url + feature_bonus
    fused = min(1.0, fused)
    gsb_hit = "google_safe_browsing" in rep_hit_sources
    high_conf = gsb_hit or (max(p_text, p_url) >= HIGH_CONF_OVERRIDE)
    threshold = 0.55
    is_phishing = fused >= threshold or high_conf

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
        },
        "parent_email": req.parent_email or None,
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
