"""
SentinelAI — Anomaly Detector
Uses Isolation Forest trained on auth/access log features.
"""

from __future__ import annotations
import os
import re
import math
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from pandas import DataFrame

try:
    import joblib
    import numpy as np
    import pandas as pd
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class AnomalyDetector:
    """
    Detects behavioral anomalies in log data using an Isolation Forest model.
    """

    def __init__(self):
        self.model = None
        self._try_load_model()

    def _try_load_model(self):
        """Load the trained Isolation Forest model."""
        if SKLEARN_AVAILABLE:
            model_path = os.path.join(os.path.dirname(__file__), "..", "models", "log_anomaly_model.joblib")
            if os.path.exists(model_path):
                try:
                    self.model = joblib.load(model_path)
                except Exception:
                    pass

    def detect(self, log_data: str) -> dict:
        """Analyze log text for anomalies."""
        features = self._extract_features(log_data)
        
        score = 0.0
        is_anomaly = False
        
        if self.model and SKLEARN_AVAILABLE:
            try:
                # Prepare features for prediction
                # Ensure the columns match what the model was trained on
                df = pd.DataFrame([features])
                # IsolationForest returns -1 for anomalies, 1 for normal
                pred = self.model.predict(df)[0]
                is_anomaly = (pred == -1)
                
                # Convert decision function to a 0-1 risk score
                decision = self.model.decision_function(df)[0]
                # Lower decision function means more anomalous
                score = 1.0 / (1.0 + np.exp(5 * (decision + 0.1))) 
            except Exception:
                # Heuristic fallback if ML fails
                score = self._heuristic_score(features)
        else:
            score = self._heuristic_score(features)

        return {
            "score": round(score, 4),
            "is_anomaly": is_anomaly or (score > 0.7),
            "features_extracted": features,
            "anomalous_fields": [k for k, v in features.items() if self._is_field_suspicious(k, v)],
            "model_used": "IsolationForest" if self.model else "Heuristic"
        }

    def _extract_features(self, log_line: str) -> dict:
        """Extract numerical features from a log line."""
        # Simple extraction logic for demo
        has_sudo = "sudo" in log_line.lower()
        has_fail = any(x in log_line.lower() for x in ["fail", "error", "denied", "invalid"])
        path_depth = log_line.count("/")
        
        return {
            "has_sudo": float(has_sudo),
            "has_failure": float(has_fail),
            "path_depth": float(path_depth),
            "length": float(len(log_line))
        }

    def _heuristic_score(self, f: dict) -> float:
        score = 0.0
        if f["has_sudo"]: score += 0.4
        if f["has_failure"]: score += 0.5
        if f["path_depth"] > 5: score += 0.2
        return min(1.0, score)

    def _is_field_suspicious(self, key: str, value: float) -> bool:
        if key == "has_failure" and value > 0: return True
        if key == "has_sudo" and value > 0: return True
        return False
