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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
# MODEL_DIR is the unzipped DistilBERT checkpoint. Defaults to ./model
# next to this file; can be overridden via the MODEL_DIR env var (handy
# when running inside Docker where the model is mounted as a volume).
MODEL_DIR = Path(os.environ.get("MODEL_DIR", Path(__file__).parent / "model"))
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


@asynccontextmanager
async def lifespan(_app: FastAPI):
    print(f"Loading DistilBERT from {MODEL_DIR} ...")
    if not MODEL_DIR.exists():
        raise RuntimeError(
            f"Model folder not found: {MODEL_DIR}\n"
            f"Unzip phishing_model.zip next to extension_backend.py first."
        )
    device = _pick_device()
    tok = AutoTokenizer.from_pretrained(str(MODEL_DIR))
    model = AutoModelForSequenceClassification.from_pretrained(str(MODEL_DIR))
    model.to(device).eval()
    STATE["tokenizer"] = tok
    STATE["model"] = model
    STATE["device"] = device
    STATE["lime"] = LimeTextExplainer(class_names=CLASS_NAMES, bow=False)
    print(f"Model loaded on device={device}. Ready on http://127.0.0.1:8000")
    yield
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
    """
    raw_email_b64: str | None = None
    raw_text: str | None = None
    sender_email: str | None = None


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


def url_agent(urls: list[str]) -> float:
    """Heuristic URL score (replace with the trained RF when available)."""
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


def metadata_agent(headers: dict[str, str]) -> float:
    """Heuristic metadata score (replace with the trained RF when available)."""
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
            "endpoints": ["/analyse", "/explain"]}


@app.post("/explain")
def explain(req: AnalyseRequest):
    """Top-K LIME tokens explaining the text-agent decision."""
    body, _, _ = _get_body_urls_headers(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")

    lime = STATE["lime"]
    try:
        # Cap body length: LIME runs num_samples forward passes, so a shorter
        # body shaves off real wall-time.
        body_short = body[:800]
        exp = lime.explain_instance(
            body_short, predict_proba_batch,
            num_samples=200, num_features=12,
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


def _get_body_urls_headers(req: AnalyseRequest):
    """Resolve the request into (body, urls, headers).

    Either raw_email_b64 (full EML) or raw_text (plain body) must be present.
    sender_email, when provided, is injected into headers['from'] so the
    rest of the pipeline can use it uniformly.
    """
    if req.raw_text:
        body = req.raw_text.strip()
        urls = re.findall(r"https?://[^\s\"'<>)]+", body)
        headers: dict[str, str] = {}
        if req.sender_email:
            headers["from"] = req.sender_email
        return body, urls, headers
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
    return body, urls, headers


@app.post("/analyse")
def analyse(req: AnalyseRequest):
    body, urls, headers = _get_body_urls_headers(req)
    if not body:
        raise HTTPException(400, "Could not extract any text from this email.")

    # trusted-sender check (must be done before fusion)
    sender_domain = _sender_domain(headers.get("from", ""))
    trusted_sender = is_trusted_domain(sender_domain)

    # run agents
    try:
        p_text = text_agent(body)
        p_url  = url_agent(urls)
        p_meta = metadata_agent(headers)
    except Exception as e:
        raise HTTPException(500, f"Inference failed: {e}")

    # When the sender domain is trusted, the metadata agent reports a low
    # score and the text agent's contribution to the fused score is halved
    # (DistilBERT often false-positives on transactional bank/hospital tone).
    if trusted_sender:
        p_meta = min(p_meta, 0.05)
        fused = (W_TEXT * 0.5) * p_text + W_URL * p_url + W_META * p_meta
        high_conf = False              # disable single-agent override for trusted senders
        threshold = 0.65               # raise the bar for flagging a trusted sender
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
        "agents": {
            "text":     {"phishing_probability": p_text,
                         "verdict": verdict_label(p_text)},
            "url":      {"phishing_probability": p_url,
                         "verdict": verdict_label(p_url)},
            "metadata": {"phishing_probability": p_meta,
                         "verdict": verdict_label(p_meta)},
        },
    }
