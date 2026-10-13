"""
The text agent: a fine-tuned transformer that scores the wording of an
email, and its LIME explanation.

load() runs once at startup (FastAPI lifespan); text_agent() and
explain() are synchronous and CPU-bound, so the API calls them from a
worker thread.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np

from settings import (
    CLASS_NAMES,
    HF_MODEL_REPO,
    LIME_MAX_CHARS,
    LIME_NUM_SAMPLES,
    MAX_LEN,
    MODEL_DIR,
    MODEL_DTYPE,
)

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


def ensure_model_available(model_dir: Path = MODEL_DIR) -> Path:
    """Use model_dir when it holds a checkpoint, otherwise download
    HF_MODEL_REPO into it."""
    must_have = {"config.json", "tokenizer_config.json"}
    if model_dir.exists() and must_have.issubset({p.name for p in model_dir.iterdir()}):
        return model_dir
    logger.info("No model in %s: downloading %s.", model_dir, HF_MODEL_REPO)
    try:
        from huggingface_hub import snapshot_download
    except ImportError as e:
        raise RuntimeError(
            f"{model_dir} is empty and huggingface_hub is not installed: put the "
            "checkpoint there or install huggingface_hub."
        ) from e
    model_dir.mkdir(parents=True, exist_ok=True)
    snapshot_download(repo_id=HF_MODEL_REPO, local_dir=str(model_dir))
    return model_dir


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
    STATE.update(
        tokenizer=tok,
        model=model,
        device=device,
        lime=LimeTextExplainer(class_names=CLASS_NAMES, bow=False),
    )
    logger.info("Text model loaded from %s on %s.", model_dir, device)


def unload() -> None:
    STATE.clear()


def predict_proba_batch(texts: list[str]) -> np.ndarray:
    """N x 2 array of [P(safe), P(phishing)] (the shape LIME expects)."""
    import torch
    import torch.nn.functional as F

    tok, model, device = STATE["tokenizer"], STATE["model"], STATE["device"]
    inputs = tok(
        list(texts), truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt"
    )
    inputs.pop("token_type_ids", None)
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        logits = model(**inputs).logits
    return F.softmax(logits, dim=-1).cpu().numpy()


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
