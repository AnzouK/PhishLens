"""
PhishLens: loading the Random Forest agents without pickle (v1.12).
=====================================================================
The URL and metadata agents used to be published as joblib files.
joblib is pickle underneath, and unpickling runs whatever code the file
asks for: a tampered file on Hugging Face would mean code execution on
every backend that downloads it (threat model, risk R4).

The skops format stores the same scikit-learn objects as data. Loading
it never imports an arbitrary module: skops lists every type it would
have to reconstruct, and we accept the file only if all of them come
from scikit-learn, NumPy, SciPy or the Python builtins. Anything else
(os.system, subprocess, a custom class) is refused.

``load_agent_state`` returns the dict the agents' ``load_model`` used to
read from joblib: model, scaler, feature_names, is_trained, and the
optional training_history / best_params.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("phishlens." + __name__.split(".")[-1])

# Type-name prefixes a legitimate agent file may contain.
ALLOWED_TYPE_PREFIXES = ("sklearn.", "numpy.", "scipy.", "builtins.")

REQUIRED_KEYS = ("model", "scaler", "feature_names")


class UntrustedModelError(RuntimeError):
    """Raised when a model file references types outside the allowlist."""


def _skops():
    try:
        import skops.io as sio  # type: ignore
    except Exception as e:  # pragma: no cover - depends on the image
        raise RuntimeError(f"skops is not installed ({e})")
    return sio


def unexpected_types(untrusted: list[str]) -> list[str]:
    return [t for t in untrusted if not t.startswith(ALLOWED_TYPE_PREFIXES)]


def load_skops_state(path: str | Path) -> dict[str, Any]:
    sio = _skops()
    path = str(path)
    untrusted = sio.get_untrusted_types(file=path)
    bad = unexpected_types(untrusted)
    if bad:
        raise UntrustedModelError(
            f"{path} references types outside the allowlist, refusing to load: {bad}"
        )
    state = sio.load(path, trusted=untrusted)
    if not isinstance(state, dict) or any(k not in state for k in REQUIRED_KEYS):
        raise UntrustedModelError(f"{path} is not a PhishLens agent file (missing keys).")
    return state


def dump_skops_state(state: dict[str, Any], path: str | Path) -> None:
    """Write an agent state dict as .skops. Only the fields the runtime
    needs are kept, and the metadata is reduced to plain JSON types so
    no extra type ever ends up in the file."""
    sio = _skops()
    clean = {
        "model": state["model"],
        "scaler": state["scaler"],
        "feature_names": [str(f) for f in state["feature_names"]],
        "is_trained": bool(state.get("is_trained", True)),
        "training_history": json.loads(json.dumps(state.get("training_history") or {}, default=str)),
        "best_params": json.loads(json.dumps(state.get("best_params"), default=str)),
    }
    sio.dump(clean, str(path))


def apply_state(agent: Any, state: dict[str, Any]) -> Any:
    """Fill a URLAgent / MetadataAgent instance, exactly like its own
    load_model does after joblib.load."""
    agent.model = state["model"]
    agent.scaler = state["scaler"]
    agent.feature_names = list(state["feature_names"])
    agent.is_trained = bool(state.get("is_trained", True))
    agent.training_history = state.get("training_history") or {}
    agent.best_params = state.get("best_params")
    return agent
