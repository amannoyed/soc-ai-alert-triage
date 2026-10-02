"""
feedback_model.py
═════════════════
Supervised triage model trained on ANALYST DECISIONS — the only labeled
learning in this project, and the labels are real (analysts marking alerts
true/false positive in the triage queue).

How it works:
  - Labels come from TriageStore.labeled_events():
      closed_true_positive  → 1
      closed_false_positive → 0
  - Features are the SAME observable-only vector as the anomaly model
    (features.py). alert_type is deliberately excluded — the model must
    learn from behavior, not from the category name.
  - Model: RandomForestClassifier. Cold start: needs >= MIN_LABELS labels
    with both classes present, otherwise available() is False and the
    pipeline ignores it.

What it's FOR:
  Prioritization, not detection. When the model is available, scoring may
  apply a small boost/penalty: "analysts confirmed similar past alerts as
  threats" (or "...as false positives"). Similar = close in feature space,
  which is exactly what the forest learns.

Retraining: call retrain() after a batch of new analyst decisions, or let
maybe_retrain() handle it (retrains when >=10 new labels since last fit).
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from features import extract_features, to_vector, FEATURE_NAMES

_BASE       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_DIR  = os.path.join(_BASE, "model")
_MODEL_PATH = os.path.join(_MODEL_DIR, "feedback_rf.pkl")

MIN_LABELS      = 20   # minimum analyst decisions before training
MIN_PER_CLASS   = 5    # need both outcomes represented
RETRAIN_EVERY   = 10   # new labels triggering a refit


def _label_count_at_train(path: str = _MODEL_PATH) -> int:
    meta = _MODEL_PATH + ".meta"
    if os.path.exists(meta):
        try:
            return int(open(meta).read().strip())
        except Exception:
            return 0
    return 0


def train() -> dict:
    """Fit RandomForest on analyst labels. Returns info dict."""
    from triage_store import TriageStore
    store = TriageStore()
    labeled = store.labeled_events()
    if len(labeled) < MIN_LABELS:
        raise ValueError(
            f"Need >= {MIN_LABELS} analyst labels, have {len(labeled)}.")
    X = np.array([to_vector(extract_features(log)) for log, _ in labeled])
    y = np.array([label for _, label in labeled])
    classes = set(int(v) for v in y)
    if len(classes) < 2 or min((y == c).sum() for c in classes) < MIN_PER_CLASS:
        raise ValueError(
            "Need both true-positive and false-positive labels "
            f"(>= {MIN_PER_CLASS} each). Have: {dict(zip(*np.unique(y, return_counts=True)))}")

    clf = RandomForestClassifier(
        n_estimators=150, max_depth=6, class_weight="balanced",
        random_state=42)
    clf.fit(X, y)

    os.makedirs(_MODEL_DIR, exist_ok=True)
    joblib.dump(clf, _MODEL_PATH)
    with open(_MODEL_PATH + ".meta", "w") as f:
        f.write(str(len(labeled)))
    _cache.clear()
    print(f"[feedback_model] Trained RandomForest on {len(labeled)} analyst "
          f"labels (TP={int((y == 1).sum())}, FP={int((y == 0).sum())}).")
    return {"labels": len(labeled), "tp": int((y == 1).sum()),
            "fp": int((y == 0).sum()), "features": FEATURE_NAMES}


_cache: dict = {}


def _get():
    if "m" not in _cache:
        if not os.path.exists(_MODEL_PATH):
            return None
        try:
            _cache["m"] = joblib.load(_MODEL_PATH)
        except Exception:
            return None
    return _cache["m"]


def available() -> bool:
    """True when a trained feedback model exists."""
    return _get() is not None


def threat_probability(log: dict) -> float | None:
    """
    P(analyst would confirm this as a threat) in [0,1],
    or None when the model isn't trained yet.
    """
    clf = _get()
    if clf is None:
        return None
    vec = np.array([to_vector(extract_features(log))])
    return float(clf.predict_proba(vec)[0][1])


def maybe_retrain() -> bool:
    """Retrain if enough new analyst labels arrived. Returns True if retrained."""
    from triage_store import TriageStore
    n = len(TriageStore().labeled_events())
    if n >= MIN_LABELS and n - _label_count_at_train() >= RETRAIN_EVERY:
        try:
            train()
            return True
        except ValueError as e:
            print(f"[feedback_model] Retrain skipped: {e}")
    return False


def model_info() -> dict:
    clf = _get()
    if clf is None:
        return {"available": False,
                "reason": f"needs >={MIN_LABELS} analyst labels"}
    return {"available": True, "model": "RandomForestClassifier",
            "n_estimators": clf.n_estimators,
            "labels_at_train": _label_count_at_train(),
            "features": FEATURE_NAMES}


if __name__ == "__main__":
    print("Feedback model self-test\n" + "=" * 40)
    print(model_info())
