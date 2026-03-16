"""
Generate the pre-trained Isolation Forest model for the Anomaly Detector.

The model is trained on synthetic data that mimics CICIDS-2017 normal traffic
patterns.  Feature order (6 features):
  0 – login_attempts_per_hour
  1 – unique_ips_per_hour
  2 – failed_login_ratio
  3 – after_hours_logins
  4 – unique_resources_accessed
  5 – total_log_lines

Run:
    python generate_model.py
"""

import os
import pickle
import numpy as np
from sklearn.ensemble import IsolationForest

# ── Synthetic "normal" training data ──────────────────────────────────────────
rng = np.random.default_rng(42)
n_samples = 2000

normal_data = np.column_stack([
    rng.poisson(lam=2.0, size=n_samples).astype(float),        # login_attempts/hr
    rng.poisson(lam=3.0, size=n_samples).astype(float),        # unique_ips/hr
    rng.beta(a=1, b=19, size=n_samples),                        # failed_login_ratio (~0.05 mean)
    rng.poisson(lam=0.3, size=n_samples).astype(float),        # after_hours_logins
    rng.poisson(lam=12.0, size=n_samples).astype(float),       # unique_resources_accessed
    rng.poisson(lam=25.0, size=n_samples).astype(float),       # total_log_lines
])

# ── Inject a small amount of anomalous samples (~5%) ─────────────────────────
n_anomalies = 100
anomalous_data = np.column_stack([
    rng.poisson(lam=60.0, size=n_anomalies).astype(float),
    rng.poisson(lam=15.0, size=n_anomalies).astype(float),
    rng.beta(a=5, b=5, size=n_anomalies),
    rng.poisson(lam=8.0, size=n_anomalies).astype(float),
    rng.poisson(lam=40.0, size=n_anomalies).astype(float),
    rng.poisson(lam=100.0, size=n_anomalies).astype(float),
])

training_data = np.vstack([normal_data, anomalous_data])

# ── Train Isolation Forest ────────────────────────────────────────────────────
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    max_samples="auto",
    random_state=42,
    n_jobs=-1,
)
model.fit(training_data)

# ── Save ──────────────────────────────────────────────────────────────────────
out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "anomaly_isoforest.pkl")

with open(out_path, "wb") as f:
    pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)

print(f"✅  Model saved to {out_path}")
print(f"    Training samples : {training_data.shape[0]}")
print(f"    Features         : {training_data.shape[1]}")
print(f"    File size        : {os.path.getsize(out_path) / 1024:.1f} KB")
