"""
Shared pytest setup.

extension_backend.py imports torch, transformers and lime at module
level. CI deliberately does not install those (torch alone is hundreds
of MB), and the endpoint tests never run the real model: they patch
`text_agent` with a fixed score.

``import_extension_backend()`` therefore registers tiny placeholder
modules for whichever of those packages is missing, imports the
backend, and removes the placeholders again. Keeping them only for that
one import matters: other libraries (scikit-learn, SciPy, Hugging Face
Hub...) probe for torch with ``importlib.util.find_spec`` or
``sys.modules``, and a fake torch left behind breaks their import.

Hugging Face Hub is forced offline so importing the backend never
downloads the Random Forest agents during the tests.
"""
from __future__ import annotations

import contextlib
import importlib
import importlib.machinery
import os
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


def _missing(name: str) -> bool:
    try:
        importlib.import_module(name)
        return False
    except Exception:
        return True


class _Placeholder:
    """Stands in for heavy classes that are only touched in lifespan()."""

    def __init__(self, *_a, **_k):
        raise RuntimeError("placeholder: the real dependency is not installed")

    @classmethod
    def from_pretrained(cls, *_a, **_k):
        raise RuntimeError("placeholder: the real dependency is not installed")


def _stub(name: str, **attrs) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    mod.__spec__ = importlib.machinery.ModuleSpec(name, loader=None)
    return mod


def _placeholders() -> dict[str, types.ModuleType]:
    mods: dict[str, types.ModuleType] = {}
    if _missing("torch"):
        torch = _stub(
            "torch",
            __version__="0.0.0+stub",
            float16="float16",
            float32="float32",
            no_grad=contextlib.nullcontext,
            cuda=types.SimpleNamespace(is_available=lambda: False),
            backends=types.SimpleNamespace(),
        )
        nn = _stub("torch.nn")
        functional = _stub("torch.nn.functional", softmax=None)
        torch.nn = nn
        nn.functional = functional
        mods.update({"torch": torch, "torch.nn": nn, "torch.nn.functional": functional})
    if _missing("transformers"):
        mods["transformers"] = _stub(
            "transformers",
            AutoModelForSequenceClassification=_Placeholder,
            AutoTokenizer=_Placeholder,
        )
    if _missing("lime.lime_text"):
        lime = _stub("lime")
        lime_text = _stub("lime.lime_text", LimeTextExplainer=_Placeholder)
        lime.lime_text = lime_text
        mods.update({"lime": lime, "lime.lime_text": lime_text})
    return mods


def import_extension_backend():
    """Import extension_backend with placeholders for missing heavy deps,
    then take the placeholders out of sys.modules again."""
    if "extension_backend" in sys.modules:
        return sys.modules["extension_backend"]
    mods = _placeholders()
    sys.modules.update(mods)
    try:
        return importlib.import_module("extension_backend")
    finally:
        for name, mod in mods.items():
            if sys.modules.get(name) is mod:
                del sys.modules[name]
