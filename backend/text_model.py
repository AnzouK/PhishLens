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
import unicodedata
from pathlib import Path
from typing import Any

import numpy as np

from language import FUNCTION_WORDS
from settings import (
    CLASS_NAMES,
    HF_MODEL_REPO,
    HF_MODEL_REVISION,
    HIGH_CONF_OVERRIDE,
    LIME_MAX_CHARS,
    LIME_NUM_SAMPLES,
    MAX_LEN,
    MODEL_DIR,
    MODEL_DTYPE,
)
from text_normalize import normalize_text

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


def ensure_model_available(
    model_dir: Path = MODEL_DIR, repo: str = HF_MODEL_REPO, revision: str | None = HF_MODEL_REVISION
) -> Path:
    """Directory of the text model to load.

    Each Hugging Face repository gets its own subfolder of model_dir
    (model_dir/<owner>--<name>), so switching HF_MODEL_REPO never loads the
    previous model by mistake; a pinned revision gets its own subfolder too
    (<owner>--<name>@<sha>). A checkpoint placed directly in model_dir
    (the layout of earlier versions, and of a local Docker setup) is used
    for the original v1 repository only.
    """
    target = model_dir / (repo.replace("/", "--") + (f"@{revision[:12]}" if revision else ""))
    if not revision:
        logger.warning("HF_MODEL_REVISION is not set: the latest commit of %s is used.", repo)
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
    snapshot_download(repo_id=repo, revision=revision, local_dir=str(target))
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


_SPECIAL = (
    "bos_token",
    "eos_token",
    "unk_token",
    "sep_token",
    "pad_token",
    "cls_token",
    "mask_token",
)


def fast_tokenizer_kwargs(cfg: dict[str, Any]) -> dict[str, Any]:
    """Special tokens of a tokenizer_config.json, in the form
    PreTrainedTokenizerFast accepts (see _load_tokenizer)."""
    kwargs: dict[str, Any] = {k: cfg[k] for k in _SPECIAL if isinstance(cfg.get(k), str)}
    extra = cfg.get("extra_special_tokens") or cfg.get("additional_special_tokens")
    if isinstance(extra, list) and extra:
        kwargs["additional_special_tokens"] = [str(t) for t in extra]
    return kwargs


def _load_tokenizer(model_dir: Path):
    """AutoTokenizer, or the plain fast tokenizer built from tokenizer.json
    when the checkpoint was saved by a newer Transformers whose tokenizer
    class this version does not know (Transformers 5 writes
    "TokenizersBackend"). The tokenizer.json format is the same."""
    from transformers import AutoTokenizer

    try:
        return AutoTokenizer.from_pretrained(str(model_dir))
    except (ValueError, TypeError, AttributeError) as e:
        if not (model_dir / "tokenizer.json").is_file():
            raise
        from transformers import PreTrainedTokenizerFast

        logger.info("AutoTokenizer failed (%s): using tokenizer.json directly.", e)
        cfg = json.loads((model_dir / "tokenizer_config.json").read_text())
        tok = PreTrainedTokenizerFast(
            tokenizer_file=str(model_dir / "tokenizer.json"), **fast_tokenizer_kwargs(cfg)
        )
        tok.padding_side = cfg.get("padding_side", "right")
        tok.model_max_length = int(cfg.get("model_max_length", 512))
        return tok


def load() -> None:
    """Load the tokenizer, the model and the LIME explainer into STATE."""
    import torch
    from lime.lime_text import LimeTextExplainer
    from transformers import AutoModelForSequenceClassification

    model_dir = ensure_model_available()
    device = _pick_device()
    dtype = torch.float16 if MODEL_DTYPE == "float16" else torch.float32
    tok = _load_tokenizer(model_dir)
    model = AutoModelForSequenceClassification.from_pretrained(str(model_dir), torch_dtype=dtype)
    model.to(device).eval()
    meta = read_meta(model_dir)
    STATE.update(
        tokenizer=tok,
        model=model,
        device=device,
        meta=meta,
        source=HF_MODEL_REPO,
        revision=HF_MODEL_REVISION,
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


def without_invisible(text: str) -> str:
    """The text without the characters that do not show (zero-width
    spaces, soft hyphens, direction marks): "V\u200be\u200br\u200bify" is
    "Verify" on screen, but cut the word in pieces for the tokenizer.
    The joiners that shape Arabic and Indic scripts (U+200C, U+200D) are
    kept between letters of those scripts and dropped elsewhere."""
    if text.isascii():
        return text
    out = []
    for i, c in enumerate(text):
        if (
            unicodedata.category(c) != "Cf"
            or c in "\u200c\u200d"
            and i
            and not text[i - 1].isascii()
        ):
            out.append(c)
    return "".join(out)


def predict_proba_batch(texts: list[str]) -> np.ndarray:
    """N x 2 array of [P(safe), P(phishing)] (the shape LIME expects)."""
    import torch
    import torch.nn.functional as F

    tok, model, device = STATE["tokenizer"], STATE["model"], STATE["device"]
    meta = _meta()
    texts = [without_invisible(t) for t in texts]
    texts = [normalize_text(t) for t in texts] if meta["normalize"] else texts
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
        num_features=20,
        labels=(1,),  # explain in the phishing direction
    )
    # Words such as "the", "votre", "est" are left out of the display:
    # they say nothing to a reader even when the model leans on them.
    feats = [
        {"token": word, "weight": float(w), "supports": "phishing" if w > 0 else "safe"}
        for word, w in exp.as_list(label=1)
        if str(word).lower() not in FUNCTION_WORDS
    ][:12]
    feats.sort(key=lambda f: abs(f["weight"]), reverse=True)
    strong = [f for f in feats if abs(f["weight"]) >= 0.003]
    return strong if len(strong) >= 5 else feats[:8]
