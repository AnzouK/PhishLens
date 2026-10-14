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

    def __truediv__(self, t):
        return FakeTensor(self.arr / t)


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
    monkeypatch.setattr(
        text_model.ensure_model_available, "__defaults__", (tmp_path, text_model.LEGACY_REPO)
    )

    text_model.load()
    assert text_model.STATE["device"] == "cpu" and text_model.STATE["lime"] == "explainer"
    assert calls["AutoModelForSequenceClassification"][1]["torch_dtype"] == "float32"
    text_model.unload()
    assert text_model.STATE == {}


def test_missing_checkpoint_without_hub_library_is_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "huggingface_hub", None)
    with pytest.raises(RuntimeError, match="huggingface_hub"):
        text_model.ensure_model_available(tmp_path / "empty")


def test_v2_meta_normalises_input_and_applies_temperature(loaded, tmp_path):
    seen = []

    class Recorder(FakeTokenizer):
        def __call__(self, texts, **kw):
            seen.append((list(texts), kw["max_length"]))
            return super().__call__(texts, **kw)

    loaded["tokenizer"] = Recorder()
    loaded["meta"] = {
        "normalize": True,
        "max_length": 128,
        "temperature": 0.5,
        "override_threshold": 0.7,
    }
    p = text_model.predict_proba_batch(["Verify at https://evil.example/x now"])
    assert seen[0] == (["Verify at <URL> now"], 128)
    loaded["meta"]["temperature"] = 1.0
    p1 = text_model.predict_proba_batch(["Verify at https://evil.example/x now"])
    # T < 1 sharpens: the same logits give a more extreme probability
    assert abs(p[0, 1] - 0.5) > abs(p1[0, 1] - 0.5)
    assert text_model.override_threshold() == 0.7


def test_meta_files_are_read(tmp_path):
    import json

    meta = text_model.read_meta(tmp_path)
    assert meta["normalize"] is False and meta["temperature"] == 1.0
    (tmp_path / "calibration.json").write_text(json.dumps({"temperature": 0.447}))
    (tmp_path / "phishlens_text_agent.json").write_text(
        json.dumps({"normalize": True, "override_threshold": 0.7})
    )
    meta = text_model.read_meta(tmp_path)
    assert meta == {
        "normalize": True,
        "max_length": 256,
        "temperature": 0.447,
        "override_threshold": 0.7,
    }


def test_display_name():
    assert text_model.display_name({}, text_model.LEGACY_REPO) == "DistilBERT (English)"
    assert text_model.display_name({}, "owner/model") == "owner/model"
    meta = {"name": "PhishLens multilingual", "version": "r4p"}
    assert text_model.display_name(meta, "owner/model") == "PhishLens multilingual r4p"


def test_each_repository_has_its_own_folder(tmp_path, monkeypatch):
    for d in (tmp_path, tmp_path / "AnzouKiona--phishlens-v2"):
        d.mkdir(exist_ok=True)
        (d / "config.json").write_text("{}")
        (d / "tokenizer_config.json").write_text("{}")
    # legacy layout: a checkpoint directly in the folder is the v1 model
    assert text_model.ensure_model_available(tmp_path, text_model.LEGACY_REPO) == tmp_path
    assert (
        text_model.ensure_model_available(tmp_path, "AnzouKiona/phishlens-v2")
        == tmp_path / "AnzouKiona--phishlens-v2"
    )
    # a new repository never falls back to the old checkpoint
    calls = []
    hub = types.ModuleType("huggingface_hub")
    hub.snapshot_download = lambda repo_id, local_dir: calls.append((repo_id, local_dir))
    monkeypatch.setitem(sys.modules, "huggingface_hub", hub)
    out = text_model.ensure_model_available(tmp_path, "AnzouKiona/other")
    assert out == tmp_path / "AnzouKiona--other" and calls == [("AnzouKiona/other", str(out))]
