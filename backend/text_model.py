"""
The text agent: a fine-tuned transformer that scores the wording of an
email, and its LIME explanation.

load() runs once at startup (FastAPI lifespan); text_agent() and
explain() are synchronous and CPU-bound, so the API calls them from a
worker thread.

A model directory can carry phishlens_text_agent.json, describing how the
model expects its input and how to read its output:

    {"normalize": true,            # text_normalize.normalize_text first
     "max_length": 256,            # tokens
     "temperature": 0.447,         # calibrated scores: softmax(logits / T)
     "override_threshold": 0.7,    # text score that can force the verdict
     "name": "...",                # shown in /health and the extension
     "version": "..."}

Without it (the v1 DistilBERT), the text is used as is, T = 1 and the
override threshold is settings.HIGH_CONF_OVERRIDE. A calibration.json
from the training code ({"temperature": T}) is read too.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
from text_normalize import normalize_text

from settings import (
    CLASS_NAMES,
    HF_MODEL_REPO,
    HIGH_CONF_OVERRIDE,
    LIME_MAX_CHARS,
    LIME_NUM_SAMPLES,
    MAX_LEN,
    MODEL_DIR,
    MODEL_DTYPE,
)

LEGACY_REPO = "AnzouKiona/phishlens-distilbert"
META_FILE = "phishlens_text_agent.json"

logger = logging.getLogger("phishlens.text_model")

STATE: dict[str, Any] = {}


def _pick_device() -> str:
    """Apple Silicon GPU (MPS), then CUDA, then CPU."""
    import torch

    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


def _complete(path: Path) -> bool:
    must_have = {"config.json", "tokenizer_config.json"}
    return path.is_dir() and must_have.issubset({p.name for p in path.iterdir()})


def ensure_model_available(model_dir: Path = MODEL_DIR, repo: str = HF_MODEL_REPO) -> Path:
    """Directory of the text model to load.

    Each Hugging Face repository gets its own subfolder of model_dir
    (model_dir/<owner>--<name>), so switching HF_MODEL_REPO never loads the
    previous model by mistake. A checkpoint placed directly in model_dir
    (the layout of earlier versions, and of a local Docker setup) is used
    for the original v1 repository only.
    """
    target = model_dir / repo.replace("/", "--")
    if _complete(target):
        return target
    if repo == LEGACY_REPO and _complete(model_dir):
        return model_dir
    logger.info("No local copy of %s: downloading it into %s.", repo, target)
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise RuntimeError(
            f"{target} is empty and huggingface_hub is not installed: put the "
            "checkpoint there or install huggingface_hub."
        ) from e
    target.mkdir(parents=True, exist_ok=True)
    # A private repository needs HF_TOKEN in the environment (read-only token).
    snapshot_download(repo_id=repo, local_dir=str(target))
    return target


def read_meta(model_dir: Path) -> dict[str, Any]:
    """How to feed and read this model (see the module docstring)."""
    meta: dict[str, Any] = {
        "normalize": False,
        "max_length": MAX_LEN,
        "temperature": 1.0,
        "override_threshold": HIGH_CONF_OVERRIDE,
    }
    for name in ("calibration.json", META_FILE):
        path = model_dir / name
        if path.is_file():
            meta.update(json.loads(path.read_text()))
    meta["temperature"] = float(meta["temperature"]) or 1.0
    return meta


def display_name(meta: dict[str, Any], repo: str = HF_MODEL_REPO) -> str:
    """Human-readable model name for /health: the meta file's "name" (and
    "version"), else the repository id."""
    name = meta.get("name") or ("DistilBERT (English)" if repo == LEGACY_REPO else repo)
    version = meta.get("version")
    return f"{name} {version}" if version else name


def load() -> None:
    """Load the tokenizer, the model and the LIME explainer into STATE."""
    import torch
    from lime.lime_text import LimeTextExplainer
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    model_dir = ensure_model_available()
    device = _pick_device()
    dtype = torch.float16 if MODEL_DTYPE == "float16" else torch.float32
    tok = AutoTokenizer.from_pretrained(str(model_dir))
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir), torch_dtype=dtype)
    model.to(device).eval()
    meta = read_meta(model_dir)
    STATE.update(
        tokenizer=tok,
        model=model,
        device=device,
        meta=meta,
        source=HF_MODEL_REPO,
        name=display_name(meta),
        lime=LimeTextExplainer(class_names=CLASS_NAMES, bow=False),
    )
    logger.info("Text model loaded from %s on %s (%s).", model_dir, device, meta)


def unload() -> None:
    STATE.clear()


def _meta() -> dict[str, Any]:
    return STATE.get("meta") or {
        "normalize": False,
        "max_length": MAX_LEN,
        "temperature": 1.0,
        "override_threshold": HIGH_CONF_OVERRIDE,
    }


def override_threshold() -> float:
    """Text score from which the text agent alone can force the phishing
    verdict on the default path (calibrated models need a lower one)."""
    return float(_meta()["override_threshold"])


def predict_proba_batch(texts: list[str]) -> np.ndarray:
    """N x 2 array of [P(safe), P(phishing)] (the shape LIME expects)."""
    import torch
    import torch.nn.functional as F

    tok, model, device = STATE["tokenizer"], STATE["model"], STATE["device"]
    meta = _meta()
    texts = [normalize_text(t) for t in texts] if meta["normalize"] else list(texts)
    inputs = tok(
        texts,
        truncation=True,
        max_length=int(meta["max_length"]),
        padding=True,
        return_tensors="pt",
    )
    inputs.pop("token_type_ids", None)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        logits = model(**inputs).logits
    return F.softmax(logits / meta["temperature"], dim=-1).cpu().numpy()


def text_agent(body: str) -> float:
    """Phishing probability of the email text."""
    return float(predict_proba_batch([body or ""])[0, 1])


def explain(body: str) -> list[dict[str, Any]]:
    """Words that pushed the text agent the most, strongest first.

    At least five words are returned when LIME finds them, so the "Why?"
    panel is never empty even when a confident model spreads its weight
    thinly across many words.
    """
    exp = STATE["lime"].explain_instance(
        body[:LIME_MAX_CHARS],
        predict_proba_batch,
        num_samples=LIME_NUM_SAMPLES,
        num_features=12,
        labels=(1,),  # explain in the phishing direction
    )
    feats = [
        {"token": word, "weight": float(w), "supports": "phishing" if w > 0 else "safe"}
        for word, w in exp.as_list(label=1)
    ]
    feats.sort(key=lambda f: abs(f["weight"]), reverse=True)
    strong = [f for f in feats if abs(f["weight"]) >= 0.003]
    return strong if len(strong) >= 5 else feats[:8]
