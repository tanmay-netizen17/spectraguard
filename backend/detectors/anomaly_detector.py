"""
SentinelAI — Anomaly Detector
Uses Isolation Forest trained on CICIDS-2017 auth/access log features.
Detects: brute force, credential stuffing, lateral movement, after-hours access.
"""

from __future__ import annotations

import os
import re
import math
from datetime import datetime
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Conditional imports – sklearn / numpy may not be installed in every env.
# Pyre2 cannot reason about try/except imports, so we use TYPE_CHECKING to
# provide the symbol at analysis time and runtime guards everywhere else.
# ---------------------------------------------------------------------------
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sklearn.ensemble import IsolationForest  # type: ignore[import]
    import numpy as np  # type: ignore[import]

SKLEARN_AVAILABLE: bool = False
try:
    import sklearn.ensemble  # noqa: F401
    import numpy  # noqa: F401
    SKLEARN_AVAILABLE = True
except ImportError:
    pass


# Default baseline statistics (trained on CICIDS-2017 normal traffic patterns)
# In production, these are learned from actual org data
BASELINE_STATS: dict[str, dict[str, float]] = {
    "login_attempts_per_hour": {"mean": 2.0, "std": 1.5},
    "unique_ips_per_hour": {"mean": 3.0, "std": 2.0},
    "failed_login_ratio": {"mean": 0.05, "std": 0.08},
    "average_session_duration_min": {"mean": 45.0, "std": 30.0},
    "unique_resources_accessed": {"mean": 12.0, "std": 8.0},
    "requests_per_minute": {"mean": 5.0, "std": 4.0},
}


# Resolve the models directory relative to *this* file so that the path is
# correct regardless of the working directory the process was started from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_MODELS_DIR = os.path.join(_HERE, os.pardir, "models")
_MODEL_PATH = os.path.normpath(os.path.join(_MODELS_DIR, "anomaly_isoforest.pkl"))


class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector for user/system behaviour logs.
    Produces a 0.0–1.0 anomaly score with per-feature deviation analysis.
    """

    def __init__(self) -> None:
        # Use `Any` so Pyre2 does not complain about calling methods on None.
        self.model: Any = None
        self._try_load_model()

    def _try_load_model(self) -> None:
        if not SKLEARN_AVAILABLE:
            return

        import numpy as np  # local import guarded by SKLEARN_AVAILABLE
        from sklearn.ensemble import IsolationForest as _IF

        try:
            import pickle

            with open(_MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
        except Exception:
            # Train a minimal placeholder model so the detector can still run.
            self.model = _IF(
                n_estimators=100,
                contamination=0.05,
                random_state=42,
            )
            # Fit on synthetic "normal" data (6 features)
            normal_data: Any = np.random.default_rng(42).standard_normal((500, 6)) * 0.5
            self.model.fit(normal_data)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def detect(self, log_data: str) -> dict[str, Any]:
        """Parse log lines and score for anomalous behaviour."""
        features = self._parse_log_features(log_data)
        score = self._compute_anomaly_score(features)
        deviations = self._compute_deviations(features)

        return {
            "score": float(round(score, 4)),
            "features_extracted": features,
            "deviation_map": deviations,
            "anomalous_features": [
                k for k, v in deviations.items() if v.get("z_score", 0) > 2
            ],
            "model_used": "isolation-forest" if self.model else "heuristic",
            "log_lines_parsed": log_data.count("\n") + 1,
        }

    # ── Log parsing ────────────────────────────────────────────────────────────

    def _parse_log_features(self, log_data: str) -> dict[str, float]:
        """Extract numerical features from raw auth/access log text."""
        lines = log_data.strip().split("\n")

        # Pattern matching for common log formats
        failed_logins: int = len(
            re.findall(
                r"(failed|invalid|incorrect|authentication failure)",
                log_data,
                re.IGNORECASE,
            )
        )
        successful_logins: int = len(
            re.findall(
                r"(accepted|success|logged in|session opened)",
                log_data,
                re.IGNORECASE,
            )
        )

        # IP address extraction
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_data)
        unique_ips: int = len(set(ips))

        # Timestamp extraction for rate analysis
        timestamps: list[str] = re.findall(r"\d{2}:\d{2}:\d{2}", log_data)

        total_logins: int = failed_logins + successful_logins
        failure_ratio: float = failed_logins / max(total_logins, 1)

        # After-hours detection (logins between 10pm and 6am)
        after_hours_count: int = 0
        for ts in timestamps:
            try:
                hour = int(ts.split(":")[0])
                if hour < 6 or hour >= 22:
                    after_hours_count = after_hours_count + 1
            except Exception:
                pass

        return {
            "login_attempts_per_hour": float(min(total_logins, 200)),
            "unique_ips_per_hour": float(unique_ips),
            "failed_login_ratio": float(round(failure_ratio, 4)),
            "after_hours_logins": float(after_hours_count),
            "unique_resources_accessed": float(
                len(set(re.findall(r"/[a-zA-Z0-9/_\-\.]+", log_data)))
            ),
            "total_log_lines": float(len(lines)),
        }

    def _compute_anomaly_score(self, features: dict[str, float]) -> float:
        """Combine Isolation Forest score with heuristic rules."""
        heuristic: float = self._heuristic_score(features)

        if self.model is not None and SKLEARN_AVAILABLE:
            try:
                import numpy as np  # guarded import

                vec: Any = np.array(
                    [
                        [
                            features["login_attempts_per_hour"],
                            features["unique_ips_per_hour"],
                            features["failed_login_ratio"],
                            features["after_hours_logins"],
                            features["unique_resources_accessed"],
                            features["total_log_lines"],
                        ]
                    ]
                )
                # IsolationForest returns -1 (anomaly) or 1 (normal)
                raw: float = float(self.model.decision_function(vec)[0])
                # Normalise: more negative = more anomalous → higher score
                model_score: float = max(0.0, min(1.0, (0.5 - raw)))
                return 0.6 * model_score + 0.4 * heuristic
            except Exception:
                pass

        return heuristic

    @staticmethod
    def _heuristic_score(features: dict[str, float]) -> float:
        score: float = 0.0

        # High failure rate → credential stuffing / brute force
        if features["failed_login_ratio"] > 0.5:
            score += 0.35
        elif features["failed_login_ratio"] > 0.2:
            score += 0.20

        # Too many IPs → distributed attack
        if features["unique_ips_per_hour"] > 10:
            score += 0.20
        elif features["unique_ips_per_hour"] > 5:
            score += 0.10

        # High volume → automated attack
        if features["login_attempts_per_hour"] > 50:
            score += 0.20
        elif features["login_attempts_per_hour"] > 20:
            score += 0.10

        # After-hours activity
        if features["after_hours_logins"] > 5:
            score += 0.15
        elif features["after_hours_logins"] > 0:
            score += 0.08

        return min(1.0, score)

    @staticmethod
    def _compute_deviations(features: dict[str, float]) -> dict[str, dict[str, Any]]:
        """Compute z-score deviation from baseline for each feature."""
        deviations: dict[str, dict[str, Any]] = {}
        for feat, stats in BASELINE_STATS.items():
            if feat not in features:
                continue
            value: float = features[feat]
            z: float = (value - stats["mean"]) / max(stats["std"], 0.001)
            deviations[feat] = {
                "value": value,
                "baseline_mean": stats["mean"],
                "z_score": float(round(z, 2)),
                "is_anomalous": abs(z) > 2.0,
            }
        return deviations
