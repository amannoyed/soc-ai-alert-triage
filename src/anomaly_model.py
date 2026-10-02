"""
anomaly_model.py
════════════════
Unsupervised anomaly detection for SOC triage.

WHAT IT IS:
  An IsolationForest trained EXCLUSIVELY on benign baseline activity.
  It learns "what normal looks like" (time-of-day patterns, event mix,
  failure-count distributions) and scores how far each new event deviates.

WHAT IT IS NOT:
  - Not a classifier: there are no labels, no "threat vs benign" training.
  - Not tautological: no feature is derived from alert_type or labels.

Training data: data/baseline_benign.csv
  (synthetic benign demo data — see scripts/generate_baseline.py.
   Replace with your own historical benign logs for production use.)

Cold start: on first run the model trains automatically (~seconds) and is
persisted to model/isolation_forest.pkl + model/anomaly_scaler.pkl.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from features import extract_features, to_vector, FEATURE_NAMES

_BASE         = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR    = os.path.join(_BASE, "model")
_ISO_PATH     = os.path.join(_MODEL_DIR, "isolation_forest.pkl")
_BASELINE_CSV = os.path.join(_BASE, "data", "baseline_benign.csv")

# Honest, conservative: expect ~5% of baseline to look odd, not 40%.
CONTAMINATION = 0.05


def _load_baseline_rows() -> list[dict]:
    import csv
    if not os.path.exists(_BASELINE_CSV):
        raise FileNotFoundError(
            f"Benign baseline not found: {_BASELINE_CSV}\n"
            "Generate it with: python scripts/generate_baseline.py"
        )
    with open(_BASELINE_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    if len(rows) < 100:
        raise ValueError(
            f"Baseline has only {len(rows)} rows — need >= 100 for a "
            "meaningful anomaly model."
        )
    return rows


def train() -> tuple:
    """Fit scaler + IsolationForest on the benign baseline. Returns (iso, scaler)."""
    rows = _load_baseline_rows()
    X = np.array([to_vector(extract_features(r)) for r in rows])

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    iso = IsolationForest(
        n_estimators=200,
        contamination=CONTAMINATION,
        random_state=42,
    )
    iso.fit(Xs)

    # Calibrate: map raw decision values to 0-100 using the baseline's own
    # distribution of "strangeness". Knots are honest percentiles — a score
    # of 85 means "stranger than 99% of observed benign activity".
    raws = iso.decision_function(Xs)
    strange = -raws  # higher = more anomalous
    pmin, p50, p95, p99 = (float(np.percentile(strange, q))
                           for q in (0, 50, 95, 99))
    pmax = float(strange.max())
    xs = [pmin, p50, p95, p99, max(pmax, p99 + 1e-6)]
    calib = {"knot_x": xs, "knot_y": [5.0, 25.0, 60.0, 85.0, 100.0]}

    os.makedirs(_MODEL_DIR, exist_ok=True)
    joblib.dump({"iso": iso, "scaler": scaler, "calib": calib}, _ISO_PATH)
    print(f"[anomaly_model] Trained on {len(rows)} benign events "
          f"(contamination={CONTAMINATION}); score calibrated on baseline "
          f"percentiles.")
    return iso, scaler, calib


def _load() -> tuple:
    if os.path.exists(_ISO_PATH):
        try:
            bundle = joblib.load(_ISO_PATH)
            return bundle["iso"], bundle["scaler"], bundle["calib"]
        except Exception as e:
            print(f"[anomaly_model] Saved model unreadable ({e}) — retraining.")
    return train()


# Lazy singleton — no training at import time.
_model_cache = {}


def _get():
    if "m" not in _model_cache:
        _model_cache["m"] = _load()
    return _model_cache["m"]


def _calibrated_score(raw: float, calib: dict) -> float:
    """
    Map an IsolationForest decision value to 0-100 via the baseline's own
    strangeness distribution (piecewise-linear between percentile knots).
    85 ≈ stranger than 99% of benign baseline; 60 ≈ stranger than 95%.
    """
    strange = -raw
    return round(float(np.interp(strange, calib["knot_x"], calib["knot_y"])), 1)


def score_event(log: dict) -> tuple[float, str]:
    """
    Score one parsed log dict.
    Returns (anomaly_score 0-100, label). Score is calibrated: 60 means
    "stranger than ~95% of benign baseline activity".
    """
    iso, scaler, calib = _get()
    vec = np.array([to_vector(extract_features(log))])
    raw = float(iso.decision_function(scaler.transform(vec))[0])
    score = _calibrated_score(raw, calib)
    label = "🔴 Anomaly Detected" if score >= 60 else "🟢 Normal"
    return score, label


def score_batch(logs: list[dict]) -> list[tuple[float, str]]:
    if not logs:
        return []
    iso, scaler, calib = _get()
    X = np.array([to_vector(extract_features(l)) for l in logs])
    raws = iso.decision_function(scaler.transform(X))
    out = []
    for raw in raws:
        s = _calibrated_score(float(raw), calib)
        out.append((s, "🔴 Anomaly Detected" if s >= 60 else "🟢 Normal"))
    return out


def model_info() -> dict:
    iso, _, calib = _get()
    return {
        "model": "IsolationForest",
        "n_estimators": iso.n_estimators,
        "contamination": iso.contamination,
        "features": FEATURE_NAMES,
        "baseline_rows": len(_load_baseline_rows()),
        "supervised": False,
        "labels_used": False,
        "score_calibration": "baseline percentiles (60≈p95, 85≈p99)",
    }


if __name__ == "__main__":
    print("Anomaly model self-test\n" + "=" * 40)
    benign = {"event_id": "4624", "timestamp": "2026-01-06T10:15:00+00:00",
              "failed_logins": 1, "source_ip": "192.168.1.10"}
    evil = {"event_id": "10", "timestamp": "2026-01-06T03:12:00+00:00",
            "failed_logins": 0, "source_ip": "45.33.32.1", "process_risk": 1}
    for name, log in [("benign login", benign), ("lsass access 3am", evil)]:
        s, lab = score_event(log)
        print(f"{name:18s} → {s:5.1f}/100 {lab}")
    print(model_info())
