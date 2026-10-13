"""Text agent wrapper (text_model.py) with small stand-ins for torch,
transformers and LIME: the real model never loads in CI."""

from __future__ import annotations

import contextlib
import sys
import types

import numpy as np
import pytest

import text_model


class FakeTensor:
    def __init__(self, arr):
        self.arr = np.asarray(arr, dtype=float)

    def to(self, _device):
        return self

    def cpu(self):
        return self

    def numpy(self):
        return self.arr


def _softmax(t, dim=-1):
    e = np.exp(t.arr - t.arr.max(axis=dim, keepdims=True))
    return FakeTensor(e / e.sum(axis=dim, keepdims=True))


@pytest.fixture
def fake_torch(monkeypatch):
    torch = types.ModuleType("torch")
    torch.no_grad = contextlib.nullcontext
    torch.float16, torch.float32 = "float16", "float32"
    torch.cuda = types.SimpleNamespace(is_available=lambda: False)
    torch.backends = types.SimpleNamespace()
    nn = types.ModuleType("torch.nn")
    functional = types.ModuleType("torch.nn.functional")
    functional.softmax = _softmax
    torch.nn, nn.functional = nn, functional
    for name, mod in {"torch": torch, "torch.nn": nn, "torch.nn.functional": functional}.items():
        monkeypatch.setitem(sys.modules, name, mod)
    return torch


class FakeTokenizer:
    def __call__(self, texts, **_kw):
        # one "token" per text: its length, enough to vary the logits
        return {
            "input_ids": FakeTensor([[len(t)] for t in texts]),
            "token_type_ids": FakeTensor([[0]] * len(texts)),
        }


class FakeModel:
    def __call__(self, input_ids, **_kw):
        n = input_ids.arr[:, 0]
        # texts containing "verify" are longer in the tests: higher phishing logit
        return types.SimpleNamespace(
            logits=FakeTensor(np.stack([np.zeros_like(n), (n - 10) / 5], axis=1))
        )


@pytest.fixture
def loaded(fake_torch, monkeypatch):
    monkeypatch.setattr(
        text_model, "STATE", {"tokenizer": FakeTokenizer(), "model": FakeModel(), "device": "cpu"}
    )
    return text_model.STATE


def test_predict_returns_two_probabilities_per_text(loaded):
    p = text_model.predict_proba_batch(["short", "a much longer text here"])
    assert p.shape == (2, 2) and np.allclose(p.sum(axis=1), 1.0)
    assert p[1, 1] > p[0, 1]


def test_text_agent_is_a_float_and_handles_empty_text(loaded):
    assert 0.0 <= text_model.text_agent("") <= 1.0
    assert isinstance(text_model.text_agent("hello"), float)


def test_explain_orders_by_weight_and_keeps_at_least_five(loaded):
    class Exp:
        def as_list(self, label):
            return [
                ("hi", 0.001),
                ("verify", 0.4),
                ("account", -0.2),
                ("now", 0.002),
                ("a", 0.0005),
                ("b", 0.0001),
            ]

    class Lime:
        def explain_instance(self, text, fn, **kw):
            assert len(text) <= text_model.LIME_MAX_CHARS and kw["labels"] == (1,)
            return Exp()

    loaded["lime"] = Lime()
    feats = text_model.explain("x" * 5000)
    assert [f["token"] for f in feats[:2]] == ["verify", "account"]
    assert feats[1]["supports"] == "safe" and len(feats) >= 5


def test_load_uses_a_local_checkpoint(tmp_path, fake_torch, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "tokenizer_config.json").write_text("{}")
    calls = {}

    class Auto:
        @classmethod
        def from_pretrained(cls, path, **kw):
            calls[cls.__name__] = (path, kw)
            return types.SimpleNamespace(to=lambda d: types.SimpleNamespace(eval=lambda: None))

    transformers = types.ModuleType("transformers")
    transformers.AutoTokenizer = type("AutoTokenizer", (Auto,), {})
    transformers.AutoModelForSequenceClassification = type(
        "AutoModelForSequenceClassification", (Auto,), {}
    )
    lime_text = types.ModuleType("lime.lime_text")
    lime_text.LimeTextExplainer = lambda **kw: "explainer"
    monkeypatch.setitem(sys.modules, "transformers", transformers)
    monkeypatch.setitem(sys.modules, "lime", types.ModuleType("lime"))
    monkeypatch.setitem(sys.modules, "lime.lime_text", lime_text)
    monkeypatch.setattr(text_model, "MODEL_DIR", tmp_path)
    monkeypatch.setattr(text_model, "STATE", {})
    monkeypatch.setattr(text_model.ensure_model_available, "__defaults__", (tmp_path,))

    text_model.load()
    assert text_model.STATE["device"] == "cpu" and text_model.STATE["lime"] == "explainer"
    assert calls["AutoModelForSequenceClassification"][1]["torch_dtype"] == "float32"
    text_model.unload()
    assert text_model.STATE == {}


def test_missing_checkpoint_without_hub_library_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "huggingface_hub", None)
    with pytest.raises(RuntimeError, match="huggingface_hub"):
        text_model.ensure_model_available(tmp_path / "empty")
