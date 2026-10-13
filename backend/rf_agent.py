"""
Inference side of the Random Forest agents (URL and metadata).

The agents are trained in the PhishingDetector repository
(github.com/dodi-ctrl/PhishingDetector); this backend only loads the
published state (skops, see agent_io.py) and scores one email at a
time. The state is the dict the training code saves: model, scaler,
feature_names, is_trained, training_history, best_params.
"""
from __future__ import annotations

import logging
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger("phishlens.rf_agent")


class RandomForestAgent:
    """A trained scaler + Random Forest over a fixed list of features."""

    def __init__(self) -> None:
        self.model: Any = None
        self.scaler: Any = None
        self.feature_names: list[str] = []
        self.is_trained = False
        self.training_history: dict[str, Any] = {}
        self.best_params: Any = None

    def _matrix(self, X) -> np.ndarray:
        values = X.values if isinstance(X, pd.DataFrame) else np.asarray(X)
        return self.scaler.transform(values)

    def _require_model(self) -> None:
        if not self.is_trained:
            raise ValueError("The agent has no trained model loaded.")

    def predict(self, X) -> np.ndarray:
        """Labels: 0 legitimate, 1 phishing."""
        self._require_model()
        return self.model.predict(self._matrix(X))

    def predict_proba(self, X) -> np.ndarray:
        """[P(legitimate), P(phishing)] per row."""
        self._require_model()
        return self.model.predict_proba(self._matrix(X))

    def get_prediction_with_confidence(self, features: dict[str, Any]) -> dict[str, Any]:
        """Score one feature dict (FeatureExtractor output). Features the
        model expects but the dict lacks count as 0; extra ones are ignored."""
        self._require_model()
        row = pd.DataFrame([features])
        for name in self.feature_names:
            if name not in row.columns:
                row[name] = 0
        row = row[self.feature_names]
        prediction = self.predict(row)[0]
        proba = self.predict_proba(row)[0]
        return {
            "verdict": "Phishing" if prediction == 1 else "Legitimate",
            "confidence": float(proba[1] if prediction == 1 else proba[0]),
            "phishing_probability": float(proba[1]),
            "legitimate_probability": float(proba[0]),
        }

    def load_model(self, filepath: str) -> None:
        """Load a joblib (pickle) state file. Only used while
        AGENTS_ALLOW_PICKLE is on; production loads skops files."""
        import joblib
        import agent_io
        agent_io.apply_state(self, joblib.load(filepath))
        logger.info("Loaded %s (%d features)", filepath, len(self.feature_names))
