"""
Tests for agent_io: the skops round trip of a Random Forest agent and
the type allowlist that refuses anything outside scikit-learn / NumPy.
Skipped when scikit-learn or skops is not installed (CI installs both).
"""
from __future__ import annotations

import pytest

sklearn = pytest.importorskip("sklearn")
sio = pytest.importorskip("skops.io")
np = pytest.importorskip("numpy")

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

import agent_io  # noqa: E402


def trained_state():
    rng = np.random.default_rng(0)
    X = rng.integers(0, 4, size=(200, 5)).astype(float)
    y = (X[:, 0] + X[:, 1] > 3).astype(int)
    scaler = StandardScaler().fit(X)
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(scaler.transform(X), y)
    return {
        "model": model,
        "scaler": scaler,
        "feature_names": [f"f{i}" for i in range(5)],
        "is_trained": True,
        "training_history": {"num_samples": np.int64(200), "training_date": "2026-09-30"},
        "best_params": None,
    }, X


def test_round_trip_keeps_predictions(tmp_path):
    state, X = trained_state()
    path = tmp_path / "url_agent.skops"
    agent_io.dump_skops_state(state, path)
    loaded = agent_io.load_skops_state(path)
    assert loaded["feature_names"] == state["feature_names"]
    before = state["model"].predict_proba(state["scaler"].transform(X))
    after = loaded["model"].predict_proba(loaded["scaler"].transform(X))
    assert np.allclose(before, after)


def test_apply_state_fills_agent(tmp_path):
    state, _ = trained_state()

    class Agent:
        pass

    agent = agent_io.apply_state(Agent(), state)
    assert agent.is_trained is True
    assert agent.feature_names == state["feature_names"]


def test_allowlist_filter():
    assert agent_io.unexpected_types(["sklearn.tree._tree.Tree", "numpy.dtype"]) == []
    assert agent_io.unexpected_types(["builtins.eval", "os.system"]) == ["os.system"]


def test_foreign_type_is_refused(tmp_path, monkeypatch):
    state, _ = trained_state()
    path = tmp_path / "evil.skops"
    agent_io.dump_skops_state(state, path)
    # Simulate a tampered file: skops reports a type from outside the
    # allowlist. The loader must refuse before reconstructing anything.
    monkeypatch.setattr(sio, "get_untrusted_types", lambda file: ["subprocess.Popen"])
    with pytest.raises(agent_io.UntrustedModelError):
        agent_io.load_skops_state(path)


def test_missing_keys_refused(tmp_path):
    path = tmp_path / "other.skops"
    sio.dump({"hello": "world"}, str(path))
    with pytest.raises(agent_io.UntrustedModelError):
        agent_io.load_skops_state(path)
