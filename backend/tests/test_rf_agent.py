"""Inference wrapper of the Random Forest agents (rf_agent.py)."""

from __future__ import annotations

import numpy as np
import pytest

pytest.importorskip("sklearn")

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

import agent_io  # noqa: E402
from metadata_agent import MetadataAgent  # noqa: E402
from url_agent import URLAgent  # noqa: E402


def _state():
    X = np.array([[0, 0], [0, 1], [5, 9], [6, 8]] * 5, dtype=float)
    y = np.array([0, 0, 1, 1] * 5)
    scaler = StandardScaler().fit(X)
    model = RandomForestClassifier(n_estimators=10, random_state=0).fit(scaler.transform(X), y)
    return {"model": model, "scaler": scaler, "feature_names": ["a", "b"], "is_trained": True}


@pytest.mark.parametrize("cls", [URLAgent, MetadataAgent])
def test_prediction_pads_missing_and_ignores_extra_features(cls):
    agent = agent_io.apply_state(cls(), _state())
    out = agent.get_prediction_with_confidence({"a": 6, "extra": 1})  # "b" missing -> 0
    assert set(out) == {"verdict", "confidence", "phishing_probability", "legitimate_probability"}
    assert out["phishing_probability"] + out["legitimate_probability"] == pytest.approx(1.0)
    high = agent.get_prediction_with_confidence({"a": 6, "b": 9})
    assert high["verdict"] == "Phishing" and high["phishing_probability"] > 0.5


def test_untrained_agent_refuses_to_predict():
    with pytest.raises(ValueError):
        URLAgent().get_prediction_with_confidence({"a": 1})


def test_joblib_fallback_loads_the_same_state(tmp_path):
    joblib = pytest.importorskip("joblib")
    path = tmp_path / "agent.joblib"
    joblib.dump(_state(), path)
    agent = URLAgent()
    agent.load_model(str(path))
    assert agent.feature_names == ["a", "b"] and agent.is_trained
