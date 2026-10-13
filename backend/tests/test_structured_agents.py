"""Loading the trained URL / metadata agents (structured_agents.py)."""

from __future__ import annotations

import numpy as np
import pytest

pytest.importorskip("sklearn")
pytest.importorskip("skops")

from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402

import agent_io  # noqa: E402
import structured_agents as sa  # noqa: E402


def _write_agent(path):
    X = np.array([[0, 0], [1, 1], [8, 9], [9, 8]] * 5, dtype=float)
    y = np.array([0, 0, 1, 1] * 5)
    scaler = StandardScaler().fit(X)
    model = RandomForestClassifier(n_estimators=5, random_state=0).fit(scaler.transform(X), y)
    agent_io.dump_skops_state({"model": model, "scaler": scaler, "feature_names": ["a", "b"]}, path)


@pytest.fixture
def no_hub(monkeypatch):
    monkeypatch.setattr(sa, "_hf_fetch", lambda filename: None)
    for name in ("_URL_AGENT", "_METADATA_AGENT", "_FEATURE_EXTRACT"):
        monkeypatch.setattr(sa, name, None)


def test_local_skops_files_are_loaded(tmp_path, monkeypatch, no_hub):
    _write_agent(tmp_path / "url.skops")
    _write_agent(tmp_path / "meta.skops")
    monkeypatch.setenv("URL_AGENT_PATH", str(tmp_path / "url.skops"))
    monkeypatch.setenv("METADATA_AGENT_PATH", str(tmp_path / "meta.skops"))
    sa.load()
    assert sa.url_model_ready() and sa.metadata_model_ready()


def test_nothing_published_leaves_the_rules(monkeypatch, no_hub):
    monkeypatch.delenv("URL_AGENT_PATH", raising=False)
    monkeypatch.delenv("METADATA_AGENT_PATH", raising=False)
    sa.load()
    assert not sa.url_model_ready() and not sa.metadata_model_ready()
    assert sa.url_agent(["http://10.0.0.1/login"]) >= 0.7


def test_pickle_refused_when_disabled(tmp_path, monkeypatch, no_hub):
    joblib = pytest.importorskip("joblib")
    path = tmp_path / "url_agent.joblib"
    joblib.dump({"model": None, "scaler": None, "feature_names": []}, path)
    monkeypatch.setattr(sa, "AGENTS_ALLOW_PICKLE", False)
    monkeypatch.setenv("URL_AGENT_PATH", str(path))
    from url_agent import URLAgent

    assert sa._init_agent("url_agent", "URL_AGENT_PATH", URLAgent) is None


def test_trained_url_agent_scores_visible_links(tmp_path, monkeypatch, no_hub):
    _write_agent(tmp_path / "url.skops")
    monkeypatch.setenv("URL_AGENT_PATH", str(tmp_path / "url.skops"))
    monkeypatch.delenv("METADATA_AGENT_PATH", raising=False)
    sa.load()

    class Features:
        def extract_url_features(self, text):
            return {"a": 9, "b": 9}

    monkeypatch.setattr(sa, "_FEATURE_EXTRACT", Features())
    body = "Pay here https://example.org/pay"
    assert sa.url_agent(["https://example.org/pay"], body_text=body) > 0.5
