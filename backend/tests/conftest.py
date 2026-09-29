"""
Shared pytest setup.

extension_backend.py imports torch, transformers and lime at module
level. CI deliberately does not install those (torch alone is hundreds
of MB), and the endpoint tests never run the real model: they patch
`text_agent` with a fixed score. So when a heavy dependency is missing
we register a tiny placeholder module under its name, just enough for
the import statements to succeed. If the real package is installed
(e.g. on a dev laptop) it is used untouched.
"""
from __future__ import annotations

import contextlib
import importlib
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _missing(name: str) -> bool:
    try:
        importlib.import_module(name)
        return False
    except Exception:
        return True


def _stub(name: str, **attrs) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    sys.modules[name] = mod
    return mod


class _Placeholder:
    """Stands in for heavy classes that are only touched in lifespan()."""

    def __init__(self, *_a, **_k):
        raise RuntimeError("placeholder: the real dependency is not installed")

    @classmethod
    def from_pretrained(cls, *_a, **_k):
        raise RuntimeError("placeholder: the real dependency is not installed")


if _missing("torch"):
    torch = _stub(
        "torch",
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

if _missing("transformers"):
    _stub(
        "transformers",
        AutoModelForSequenceClassification=_Placeholder,
        AutoTokenizer=_Placeholder,
    )

if _missing("lime.lime_text"):
    lime = _stub("lime")
    lime_text = _stub("lime.lime_text", LimeTextExplainer=_Placeholder)
    lime.lime_text = lime_text
